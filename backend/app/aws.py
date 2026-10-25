"""Read-only AWS inventory. Never retrieves secrets or executes remediation."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

CONFIG = Config(connect_timeout=5, read_timeout=15, retries={"mode": "adaptive", "max_attempts": 5})


def collect(profile: str | None = None, role_arn: str | None = None,
            region: str = "us-east-1", expected_account_id: str | None = None) -> dict[str, Any]:
    session = boto3.Session(profile_name=profile, region_name=region)
    if role_arn:
        creds = session.client("sts", config=CONFIG).assume_role(
            RoleArn=role_arn, RoleSessionName="CloudPathX-read-only", DurationSeconds=900)["Credentials"]
        session = boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                                aws_secret_access_key=creds["SecretAccessKey"],
                                aws_session_token=creds["SessionToken"], region_name=region)
    caller = session.client("sts", config=CONFIG).get_caller_identity()
    account = caller["Account"]
    if expected_account_id and account != expected_account_id:
        raise ValueError("AWS account does not match explicitly authorized account ID")
    if caller["Arn"].endswith(":root"):
        raise ValueError("Root credentials are not accepted")
    data: dict[str, Any] = {"synthetic": False, "accounts": [{"id": account, "name": account,
        "region": region, "synthetic": False}], "identities": [], "resources": [], "events": [],
        "errors": [], "policies": [], "groups": [], "instance_profiles": [], "access_analyzer": [],
        "security_hub": [], "config_resources": [], "organization": {},
        "controls_complete": False, "collected_at": datetime.now(timezone.utc).isoformat()}

    def call(client: Any, operation: str, **kwargs: Any) -> dict[str, Any]:
        try:
            return getattr(client, operation)(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            code = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else type(exc).__name__
            data["errors"].append({"service": client.meta.service_model.service_name,
                                   "operation": operation, "code": code, "scope": str(kwargs)[:300]})
            return {}

    def pages(client: Any, operation: str, key: str, **kwargs: Any) -> list[Any]:
        result: list[Any] = []
        try:
            if client.can_paginate(operation):
                for page in client.get_paginator(operation).paginate(**kwargs):
                    result.extend(page.get(key, []))
            else:
                result.extend(call(client, operation, **kwargs).get(key, []))
        except (ClientError, BotoCoreError) as exc:
            code = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else type(exc).__name__
            data["errors"].append({"service": client.meta.service_model.service_name,
                                   "operation": operation, "code": code})
        return result

    iam = session.client("iam", config=CONFIG)
    # A single paginated authorization snapshot contains group membership and policy versions.
    auth: dict[str, list[Any]] = {k: [] for k in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")}
    try:
        for page in iam.get_paginator("get_account_authorization_details").paginate():
            for key in auth:
                auth[key].extend(page.get(key, []))
    except (ClientError, BotoCoreError) as exc:
        data["errors"].append({"service": "iam", "operation": "get_account_authorization_details",
                               "code": type(exc).__name__})
    managed = {p["Arn"]: next((v["Document"] for v in p.get("PolicyVersionList", [])
                              if v.get("IsDefaultVersion")), None) for p in auth["Policies"]}
    data["policies"] = auth["Policies"]
    groups = {g["GroupName"]: g for g in auth["GroupDetailList"]}
    data["groups"] = auth["GroupDetailList"]

    def documents(entity: dict[str, Any], kind: str) -> list[dict[str, Any]]:
        docs = [p["PolicyDocument"] for p in entity.get(f"{kind}PolicyList", [])]
        for attached in entity.get("AttachedManagedPolicies", []):
            document = managed.get(attached["PolicyArn"])
            if document is None:
                meta = call(iam, "get_policy", PolicyArn=attached["PolicyArn"]).get("Policy", {})
                if meta.get("DefaultVersionId"):
                    document = call(iam, "get_policy_version", PolicyArn=attached["PolicyArn"],
                                    VersionId=meta["DefaultVersionId"]).get("PolicyVersion", {}).get("Document")
                if document is None:
                    data["errors"].append({"service": "iam", "operation": "resolve_policy",
                                           "code": "Unavailable", "policy": attached["PolicyArn"]})
            if document:
                docs.append(document)
        return docs

    for kind, key in (("User", "UserDetailList"), ("Role", "RoleDetailList")):
        for item in auth[key]:
            policies = documents(item, kind)
            for group in item.get("GroupList", []):
                policies.extend(documents(groups.get(group, {}), "Group"))
            trust = item.get("AssumeRolePolicyDocument", {})
            identity = {"id": item["Arn"], "name": item[f"{kind}Name"], "type": kind.lower(),
                        "account_id": account, "policies": policies, "trust_policy": trust,
                        "created_at": item.get("CreateDate"), "last_activity": item.get("RoleLastUsed"),
                        "controls_complete": False, "synthetic": False,
                        "assumptions": ["Organizations hierarchy, session policies, service controls and runtime context are not fully collected."]}
            boundary = item.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            if boundary:
                docs = documents({"AttachedManagedPolicies": [{"PolicyArn": boundary}]}, "Role")
                identity["boundary"] = docs[0] if docs else {"Statement": []}
                identity["boundary_unavailable"] = not bool(docs)
            data["identities"].append(identity)
    data["instance_profiles"] = pages(iam, "list_instance_profiles", "InstanceProfiles")
    for profile_record in data["instance_profiles"]:
        for role in profile_record.get("Roles", []):
            for identity in data["identities"]:
                if identity["id"] == role["Arn"]:
                    identity["workload_type"] = "ec2"
    lam = session.client("lambda", config=CONFIG)
    for function in pages(lam, "list_functions", "Functions"):
        data["resources"].append({"id": function["FunctionArn"], "name": function["FunctionName"],
                                  "type": "lambda", "account_id": account, "role": function["Role"], "sensitive": False})
        for identity in data["identities"]:
            if identity["id"] == function["Role"]:
                identity["workload_type"] = "lambda"
    s3 = session.client("s3", config=CONFIG)
    for bucket in pages(s3, "list_buckets", "Buckets"):
        name = bucket["Name"]
        policy = call(s3, "get_bucket_policy", Bucket=name).get("Policy")
        data["resources"].append({"id": f"arn:aws:s3:::{name}", "name": name, "type": "s3",
            "account_id": account, "sensitive": False, "policy": json.loads(policy) if policy else {},
            "public_access_block": call(s3, "get_public_access_block", Bucket=name).get("PublicAccessBlockConfiguration"),
            "policy_status": call(s3, "get_bucket_policy_status", Bucket=name).get("PolicyStatus"),
            "controls_complete": False})
    trail = session.client("cloudtrail", config=CONFIG)
    for event in pages(trail, "lookup_events", "Events", StartTime=datetime.now(timezone.utc) - timedelta(days=1)):
        if event.get("CloudTrailEvent"):
            data["events"].append(json.loads(event["CloudTrailEvent"]))
    analyzer = session.client("accessanalyzer", config=CONFIG)
    for item in pages(analyzer, "list_analyzers", "analyzers"):
        data["access_analyzer"].extend(pages(analyzer, "list_findings", "findings", analyzerArn=item["arn"]))
    org = session.client("organizations", config=CONFIG)
    data["organization"] = call(org, "describe_organization").get("Organization", {})
    data["errors"].append({"service": "organizations", "operation": "effective_controls", "code": "NotEvaluated",
        "detail": "Inherited SCP/RCP, session policies and endpoint policies are not resolved. Live permissions remain uncertain."})
    hub = session.client("securityhub", config=CONFIG)
    data["security_hub"] = pages(hub, "get_findings", "Findings", MaxResults=100)
    cfg = session.client("config", config=CONFIG)
    data["config_resources"] = pages(cfg, "list_discovered_resources", "resourceIdentifiers", resourceType="AWS::S3::Bucket")
    # SDK timestamps are normalized at the ingestion boundary, never serialized with credentials.
    return json.loads(json.dumps(data, default=lambda value: value.isoformat() if isinstance(value, datetime) else str(value)))


def validate_policy(policy: dict[str, Any], profile: str | None = None, region: str = "us-east-1") -> list[dict[str, Any]]:
    """Explicit read-only validation; no custom paid checks or AWS writes."""
    client = boto3.Session(profile_name=profile, region_name=region).client("accessanalyzer", config=CONFIG)
    findings = []
    token: dict[str, str] = {}
    while True:
        response = client.validate_policy(policyDocument=json.dumps(policy), policyType="IDENTITY_POLICY", **token)
        findings.extend(response.get("findings", []))
        if not response.get("nextToken"):
            return findings
        token = {"nextToken": response["nextToken"]}
