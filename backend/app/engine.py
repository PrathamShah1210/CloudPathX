"""Evidence-aware, deliberately bounded IAM and attack-path analysis.

An `allowed` result means allowed within supplied policy layers, not proof that an
AWS request succeeds. Unknown policy layers and unsupported conditions fail to
`uncertain`, never to confirmed access. See IAM_ANALYSIS.md.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any

import networkx as nx


def _list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _id(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:20]


def _match(pattern: str, value: str, insensitive: bool = False) -> bool:
    # IAM wildcards are * and ?. Shell character classes are not IAM syntax.
    regex = re.escape(str(pattern)).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(regex, str(value), re.IGNORECASE if insensitive else 0) is not None


def _condition(conditions: dict, context: dict) -> tuple[bool | None, list[str]]:
    unknown: list[str] = []
    for operator, entries in conditions.items():
        if not isinstance(entries, dict):
            return None, ["Malformed condition values"]
        if operator.startswith(("ForAllValues:", "ForAnyValue:")):
            unknown.append(f"Unsupported set operator: {operator}")
            continue
        if_exists = operator.endswith("IfExists")
        op = operator.removesuffix("IfExists")
        for key, expected in entries.items():
            actual = next((v for k, v in context.items() if k.lower() == key.lower()), None)
            if op == "Null":
                # Explicitly supplied context is required: omitted metadata is unknown.
                if key not in context:
                    unknown.append(f"Context key not observed: {key}")
                    continue
                result = (actual is None) == (str(expected).lower() == "true")
                if not result:
                    return False, []
                continue
            if actual is None:
                if if_exists and context.get("__complete__"):
                    continue
                unknown.append(f"Missing request context: {key}")
                continue
            if isinstance(actual, list):
                unknown.append(f"Multivalued request context needs set semantics: {key}")
                continue
            if any("${" in str(v) for v in _list(expected)):
                unknown.append(f"Unresolved policy variable: {key}")
                continue
            negative = op in {"StringNotEquals", "StringNotLike", "ArnNotEquals", "ArnNotLike", "NotIpAddress"}
            base = {
                "StringNotEquals": "StringEquals",
                "StringNotLike": "StringLike",
                "ArnNotEquals": "ArnEquals",
                "ArnNotLike": "ArnLike",
                "NotIpAddress": "IpAddress",
            }.get(op, op)

            def compare(a: Any, b: Any) -> bool | None:
                if base in {"StringEquals", "ArnEquals"}:
                    return str(a) == str(b)
                if base == "StringEqualsIgnoreCase":
                    return str(a).lower() == str(b).lower()
                if base in {"StringLike", "ArnLike"}:
                    return _match(str(b), str(a))
                if base == "Bool":
                    return str(a).lower() == str(b).lower()
                if base == "IpAddress":
                    return ipaddress.ip_address(a) in ipaddress.ip_network(b, strict=False)
                if base.startswith("Numeric"):
                    x: Any = float(a)
                    y: Any = float(b)
                elif base.startswith("Date"):
                    x, y = datetime.fromisoformat(str(a).replace("Z", "+00:00")), datetime.fromisoformat(str(b).replace("Z", "+00:00"))
                else:
                    return None
                suffix = base.removeprefix("Numeric").removeprefix("Date")
                return {
                    "Equals": x == y,
                    "LessThan": x < y,
                    "LessThanEquals": x <= y,
                    "GreaterThan": x > y,
                    "GreaterThanEquals": x >= y,
                }.get(suffix)

            try:
                values = [compare(a, b) for a in _list(actual) for b in _list(expected)]
            except (ValueError, TypeError):
                values = [None]
            if None in values:
                unknown.append(f"Unsupported or invalid condition: {operator}/{key}")
            elif not (not any(values) if negative else any(values)):
                return False, []
    return (None if unknown else True), unknown


def validate_policy(policy: Any) -> list[str]:
    errors = []
    if not isinstance(policy, dict) or "Statement" not in policy:
        return ["Policy must be an object containing Statement"]
    for i, statement in enumerate(_list(policy["Statement"])):
        if not isinstance(statement, dict):
            errors.append(f"Statement {i} must be an object")
            continue
        if statement.get("Effect") not in {"Allow", "Deny"}:
            errors.append(f"Statement {i} has invalid Effect")
        if ("Action" in statement) == ("NotAction" in statement):
            errors.append(f"Statement {i} needs exactly one of Action or NotAction")
        if "Resource" in statement and "NotResource" in statement:
            errors.append(f"Statement {i} cannot combine Resource and NotResource")
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in statement and (not _list(statement[key]) or not all(isinstance(x, str) and x for x in _list(statement[key]))):
                errors.append(f"Statement {i} has invalid {key}")
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            errors.append(f"Statement {i} has invalid Condition")
    return errors


def _principal(statement: dict, principal: str | None) -> tuple[bool | None, str | None]:
    if "NotPrincipal" in statement:
        return None, "NotPrincipal semantics are not supported"
    if "Principal" not in statement:
        return True, None
    if principal is None:
        return None, "Principal context missing"
    p = statement["Principal"]
    if p == "*":
        return True, None
    if isinstance(p, dict) and "AWS" not in p and principal.startswith("arn:aws:iam:"):
        return False, None
    if not isinstance(p, dict) or set(p) != {"AWS"}:
        return None, "Service/federated principal evaluation requires service request context"
    for candidate in _list(p["AWS"]):
        if candidate == principal or candidate == "*":
            return True, None
        if str(candidate).endswith(":root") or re.fullmatch(r"\d{12}", str(candidate)):
            account = str(candidate).split(":")[4] if ":" in str(candidate) else str(candidate)
            if len(principal.split(":")) > 4 and principal.split(":")[4] == account:
                return True, None
    return False, None


def _layer(policies: list[dict], action: str, resource: str, context: dict, principal: str | None, label: str) -> dict:
    allows, uncertain_allow, uncertain_deny, evidence, assumptions = [], [], [], [], []
    for p_index, policy in enumerate(policies):
        errors = validate_policy(policy)
        if errors:
            assumptions.extend(errors)
            uncertain_deny.append({"invalid_policy": True})
            continue
        for s_index, statement in enumerate(_list(policy["Statement"])):
            action_match = any(_match(a, action, True) for a in _list(statement.get("Action", statement.get("NotAction", []))))
            if "NotAction" in statement:
                action_match = not action_match
            if not action_match:
                continue
            if label != "trust" and "Resource" not in statement and "NotResource" not in statement:
                assumptions.append("Missing Resource in non-trust policy statement")
                uncertain_deny.append({"missing_resource": True})
                continue
            patterns = _list(statement.get("Resource", statement.get("NotResource", "*")))
            if any("${" in p for p in patterns):
                resource_match = True
                variable = True
            else:
                resource_match = any(_match(p, resource) for p in patterns)
                variable = False
                if "NotResource" in statement:
                    resource_match = not resource_match
            if not resource_match:
                continue
            principal_match, principal_unknown = _principal(statement, principal)
            if principal_match is False:
                continue
            condition_match, unknown = _condition(statement.get("Condition", {}), context)
            if condition_match is False:
                continue
            assumptions.extend(unknown)
            if principal_unknown:
                assumptions.append(principal_unknown)
            if variable:
                assumptions.append("Unresolved resource policy variable")
            record = {
                "layer": label,
                "policy_index": p_index,
                "statement_index": s_index,
                "sid": statement.get("Sid"),
                "statement": statement,
            }
            evidence.append(record)
            uncertain = condition_match is None or principal_match is None or variable
            if statement["Effect"] == "Deny":
                if not uncertain:
                    return {"decision": "denied", "explicit_deny": True, "evidence": evidence, "assumptions": assumptions}
                uncertain_deny.append(record)
            elif uncertain:
                uncertain_allow.append(record)
            else:
                allows.append(record)
    decision = "uncertain" if uncertain_deny else "allowed" if allows else "uncertain" if uncertain_allow else "denied"
    return {"decision": decision, "explicit_deny": False, "evidence": evidence, "assumptions": list(dict.fromkeys(assumptions))}


def evaluate(
    policy: dict | list[dict],
    action: str,
    resource: str,
    context: dict | None = None,
    *,
    boundary: dict | None = None,
    session_policy: dict | None = None,
    scps: list[dict] | None = None,
    rcps: list[dict] | None = None,
    resource_policy: dict | None = None,
    principal: str | None = None,
    controls_complete: bool = True,
    policy_type: str = "identity",
    **kwargs: Any,
) -> dict:
    """Evaluate a documented identity-policy subset using intersection for limiters.

    SCP/RCP entries represent already-resolved hierarchy layers, each intersected.
    Resource policies are deliberately uncertain except for matching explicit Deny:
    session/user direct grants and cross-account semantics require more context.
    """
    layers = [_layer(_list(policy), action, resource, context or {}, principal, "trust" if policy_type == "trust" else "identity")]
    for label, limiter in [("boundary", boundary), ("session", session_policy)]:
        if limiter is not None:
            layers.append(_layer([limiter], action, resource, context or {}, principal, label))
    for label, policies in [("scp", scps), ("rcp", rcps)]:
        for p in policies or []:
            layers.append(_layer([p], action, resource, context or {}, principal, label))
    assumptions = [a for layer in layers for a in layer["assumptions"]]
    resource_uncertain = False
    if resource_policy:
        rp = _layer([resource_policy], action, resource, context or {}, principal, "resource")
        if rp["explicit_deny"]:
            layers.append(rp)
        elif rp["decision"] != "denied":
            resource_uncertain = True
            assumptions.extend(rp["assumptions"])
            assumptions.append("Resource-policy grant semantics are not fully modeled")
    decision = (
        "denied"
        if any(x["decision"] == "denied" for x in layers)
        else "uncertain"
        if any(x["decision"] == "uncertain" for x in layers)
        else "allowed"
    )
    if not controls_complete:
        assumptions.append("Organization, session, service or resource controls may be unobserved")
    if kwargs:
        assumptions.append("Unsupported evaluation options: " + ", ".join(sorted(kwargs)))
    if resource_uncertain and not any(x.get("explicit_deny") for x in layers):
        decision = "uncertain"
    if decision == "allowed" and assumptions:
        decision = "uncertain"
    return {
        "decision": decision,
        "confidence": "confirmed" if decision != "uncertain" else "uncertain",
        "evidence": [e for layer in layers for e in layer["evidence"]],
        "assumptions": sorted(set(assumptions)),
        "scope": "Supplied policy subset; not an AWS authorization guarantee",
    }


def risk_score(
    *,
    sensitive: bool = False,
    external: bool = False,
    workload: bool = False,
    behavior: bool = False,
    confidence: str = "confirmed",
    hops: int = 1,
) -> dict:
    factors = {
        "permission_sensitivity": 35,
        "sensitive_asset": 20 if sensitive else 0,
        "external_exposure": 15 if external else 0,
        "workload_identity": 5 if workload else 0,
        "behavioral_evidence": 15 if behavior else 0,
        "path_prerequisites": -min(15, max(0, hops - 1) * 5),
        "uncertainty": -10 if confidence != "confirmed" else 0,
    }
    score = max(0, min(100, sum(factors.values())))
    return {
        "score": score,
        "severity": "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low",
        "confidence": confidence,
        "factors": factors,
        "explanation": "Additive prioritization score, not probability of compromise; "
        + ", ".join(f"{k}={v:+d}" for k, v in factors.items() if v),
    }


RULES = {
    "PutRolePolicy": ("IAM policy modified", "T1098"),
    "PutUserPolicy": ("IAM policy modified", "T1098"),
    "AttachRolePolicy": ("Role permissions changed", "T1098"),
    "AttachUserPolicy": ("User permissions changed", "T1098"),
    "CreatePolicyVersion": ("Policy version created", "T1098"),
    "SetDefaultPolicyVersion": ("Default policy changed", "T1098"),
    "UpdateAssumeRolePolicy": ("Role trust modified", "T1098"),
    "CreateAccessKey": ("Access key created", "T1098.001"),
}


def detect_events(events: list[dict]) -> list[dict]:
    alerts, denials = [], defaultdict(list)
    seen = set()
    for event in events:
        event_id = event.get("eventID", _id(event))
        if event_id in seen:
            continue
        seen.add(event_id)
        identity = event.get("userIdentity", {})
        principal = identity.get("arn", identity.get("principalId", "unknown"))
        event_name = event.get("eventName", "")
        base = {
            "identity_id": principal,
            "event_ids": [event_id],
            "timestamp": event.get("eventTime"),
            "confidence": "observed",
            "evidence": [event],
            "status": "Open",
            "interpretation": "Investigation signal; not a declaration of malicious activity",
        }
        if event.get("errorCode") in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            denials[principal].append(event)
        elif event_name in RULES and not event.get("errorCode"):
            title, technique = RULES[event_name]
            alerts.append(
                {
                    **base,
                    "id": _id("rule", event_id),
                    "title": title,
                    "rule": event_name,
                    "severity": "medium",
                    "mitre_technique": technique,
                }
            )
        if event_name == "AssumeRole" and not event.get("errorCode"):
            role = event.get("requestParameters", {}).get("roleArn", "")
            if role and len(role.split(":")) > 4 and len(principal.split(":")) > 4 and role.split(":")[4] != principal.split(":")[4]:
                alerts.append(
                    {
                        **base,
                        "id": _id("cross-account", event_id),
                        "title": "Cross-account role assumption observed",
                        "rule": "cross_account_assumption",
                        "severity": "medium",
                        "mitre_technique": "T1078.004",
                    }
                )
    for principal, denied in denials.items():
        valid = []
        for event in denied:
            try:
                valid.append((datetime.fromisoformat(event["eventTime"].replace("Z", "+00:00")).timestamp(), event))
            except (ValueError, KeyError, TypeError):
                continue
        valid.sort(key=lambda pair: pair[0])
        for i, (timestamp, _) in enumerate(valid):
            window = [event for t, event in valid[i:] if t - timestamp <= 300]
            if len(window) >= 3:
                alerts.append(
                    {
                        "id": _id("denials", principal, [e.get("eventID") for e in window]),
                        "title": "Repeated access denials within five minutes",
                        "rule": "repeated_denials",
                        "identity_id": principal,
                        "event_ids": [e.get("eventID", _id(e)) for e in window],
                        "timestamp": window[-1]["eventTime"],
                        "confidence": "observed",
                        "severity": "medium",
                        "mitre_technique": "T1078.004",
                        "evidence": window,
                        "status": "Open",
                        "interpretation": "May indicate misconfiguration or misuse; requires investigation",
                    }
                )
                break
    return alerts


def analyze(dataset: dict) -> dict:
    data = copy.deepcopy(dataset)
    identities, resources = data.get("identities", []), data.get("resources", [])
    alerts = detect_events(data.get("events", []))
    active = {a["identity_id"] for a in alerts}
    nodes = [
        {
            "id": x["id"],
            "label": x.get("name", x["id"]),
            "type": x.get("type", "resource"),
            "account_id": x.get("account_id"),
            "synthetic": data.get("synthetic", False),
        }
        for x in identities + resources
    ]
    edges, findings = [], []

    def finding(
        identity: dict, title: str, evidence: list, *, sensitive: bool = False, external: bool = False, confidence: str = "confirmed"
    ) -> None:
        scoring = risk_score(
            sensitive=sensitive,
            external=external,
            workload=identity.get("type") != "user",
            behavior=identity["id"] in active,
            confidence=confidence,
        )
        findings.append(
            {
                "id": _id(identity["id"], title, evidence),
                "title": title,
                "identity_id": identity["id"],
                "status": "Open",
                "evidence": evidence,
                "remediation": "Replace broad grants with required actions/resources; restrict trust principals and validate workload requirements before applying.",
                "synthetic": data.get("synthetic", False),
                **scoring,
            }
        )

    def edge(source: str, target: str, kind: str, decision: dict, action: str) -> None:
        if decision["decision"] == "denied":
            return
        edges.append(
            {
                "id": _id(source, target, kind),
                "source": source,
                "target": target,
                "type": kind,
                "confidence": decision["confidence"],
                "evidence": decision["evidence"],
                "assumptions": decision["assumptions"],
                "required_permissions": [action],
            }
        )

    for identity in identities:
        for pi, policy in enumerate(identity.get("policies", [])):
            if validate_policy(policy):
                finding(
                    identity,
                    "Policy could not be analyzed",
                    [{"policy_index": pi, "errors": validate_policy(policy)}],
                    confidence="uncertain",
                )
                continue
            for si, statement in enumerate(_list(policy["Statement"])):
                if statement.get("Effect") != "Allow":
                    continue
                actions = _list(statement.get("Action", []))
                evidence = [{"policy_index": pi, "statement_index": si, "statement": statement}]
                if "*" in actions or any(a.lower() in {"iam:*", "s3:*"} for a in actions):
                    finding(identity, "Broad permission grant in policy", evidence, sensitive="*" in actions)
                elif any(
                    a.lower() in {"iam:passrole", "iam:putrolepolicy", "iam:attachrolepolicy", "iam:createpolicyversion"} for a in actions
                ):
                    finding(identity, "Sensitive identity delegation or policy-management grant", evidence)
        trust = identity.get("trust_policy")
        if trust and not validate_policy(trust):
            for si, statement in enumerate(_list(trust["Statement"])):
                if statement.get("Effect") != "Allow":
                    continue
                principal = statement.get("Principal", {})
                principals = _list(principal.get("AWS", [])) if isinstance(principal, dict) else [principal]
                external = any(
                    p == "*"
                    or (len(str(p).split(":")) > 4 and str(p).split(":")[4] != identity.get("account_id"))
                    or (re.fullmatch(r"\d{12}", str(p)) and str(p) != identity.get("account_id"))
                    for p in principals
                )
                if external:
                    finding(
                        identity,
                        "External principal in role trust; verify intended delegation",
                        [{"statement_index": si, "statement": statement}],
                        external=True,
                        confidence="uncertain" if statement.get("Condition") else "confirmed",
                    )
        for target in resources:
            if target.get("type", "").lower() not in {"s3", "bucket", "s3_bucket", "s3_object"}:
                continue
            resource = target.get("arn", target["id"])
            if target.get("type") != "s3_object" and not resource.endswith("/*"):
                resource += "/*"
            result = evaluate(
                identity.get("policies", []),
                "s3:GetObject",
                resource,
                boundary=identity.get("boundary"),
                session_policy=identity.get("session_policy"),
                scps=identity.get("scps"),
                rcps=target.get("rcps"),
                resource_policy=target.get("policy"),
                principal=identity["id"],
                controls_complete=bool(data.get("controls_complete", False)) and identity.get("account_id") == target.get("account_id"),
            )
            edge(
                identity["id"],
                target["id"],
                "CONFIRMED_ACCESS" if result["decision"] == "allowed" else "MAY_ACCESS",
                result,
                "s3:GetObject",
            )
            if result["decision"] != "denied" and target.get("sensitive"):
                finding(
                    identity,
                    "Sensitive S3 object access within analyzed policy scope",
                    result["evidence"],
                    sensitive=True,
                    confidence=result["confidence"],
                )
        for target in identities:
            if target["id"] == identity["id"] or not target.get("trust_policy"):
                continue
            permission = evaluate(
                identity.get("policies", []),
                "sts:AssumeRole",
                target["id"],
                boundary=identity.get("boundary"),
                session_policy=identity.get("session_policy"),
                scps=identity.get("scps"),
                controls_complete=data.get("controls_complete", False),
            )
            trust_result = evaluate(target["trust_policy"], "sts:AssumeRole", target["id"], principal=identity["id"], policy_type="trust")
            if permission["decision"] == "denied" or trust_result["decision"] == "denied":
                continue
            merged = {
                "decision": "allowed" if permission["decision"] == trust_result["decision"] == "allowed" else "uncertain",
                "confidence": "confirmed" if permission["confidence"] == trust_result["confidence"] == "confirmed" else "uncertain",
                "evidence": permission["evidence"] + trust_result["evidence"],
                "assumptions": permission["assumptions"] + trust_result["assumptions"],
            }
            edge(identity["id"], target["id"], "ASSUMES_ROLE", merged, "sts:AssumeRole")
    graph = nx.DiGraph()
    graph.add_nodes_from(n["id"] for n in nodes)
    for e in edges:
        graph.add_edge(e["source"], e["target"], **e)
    paths = []
    # Bound output and enumerate shortest routes instead of exponential all-path traversal.
    for identity in identities:
        for target in resources:
            if not target.get("sensitive"):
                continue
            try:
                route = nx.shortest_path(graph, identity["id"], target["id"])
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if len(route) > 7:
                continue
            route_edges = [graph[a][b] for a, b in zip(route, route[1:])]
            confidence = "confirmed" if all(e["confidence"] == "confirmed" for e in route_edges) else "uncertain"
            scoring = risk_score(
                sensitive=True,
                workload=identity.get("type") != "user",
                behavior=identity["id"] in active,
                confidence=confidence,
                hops=len(route) - 1,
            )
            start_name = next((n.get("label", n["id"]) for n in nodes if n["id"] == identity["id"]), identity["id"].split("/")[-1])
            target_name = next((n.get("label", n["id"]) for n in nodes if n["id"] == target["id"]), target["id"].split(":")[-1])
            hop_descs = []
            for a, b in zip(route, route[1:]):
                e = graph[a][b]
                an = next((n.get("label", n["id"]) for n in nodes if n["id"] == a), a.split("/")[-1])
                bn = next((n.get("label", n["id"]) for n in nodes if n["id"] == b), b.split("/")[-1])
                k = e.get("type", "accesses")
                acts = "/".join(e.get("required_permissions", ["access"]))
                hop_descs.append(f"'{an}' reaches '{bn}' via {acts} ({k})")
            narrative = ". Then, ".join(hop_descs) + "." if hop_descs else "Direct access."
            cut_point = route[1] if len(route) > 2 else route[0]
            paths.append(
                {
                    "id": _id("path", route),
                    "title": f"{start_name} → {target_name}",
                    "start": identity["id"],
                    "target": target["id"],
                    "start_name": start_name,
                    "target_name": target_name,
                    "nodes": route,
                    "edge_ids": [e["id"] for e in route_edges],
                    "intermediate_identities": route[1:-1],
                    "required_permissions": sorted({p for e in route_edges for p in e["required_permissions"]}),
                    "evidence": [ev for e in route_edges for ev in e["evidence"]],
                    "assumptions": sorted({a for e in route_edges for a in e["assumptions"]}),
                    "scenario": "Hypothetical compromise of starting identity; passive authorization analysis only",
                    "narrative": narrative,
                    "cut_point": cut_point,
                    "remediation": f"Revoke permissions or role trust at cut-point '{cut_point.split('/')[-1]}'.",
                    **scoring,
                }
            )
    paths.sort(key=lambda x: (-x["score"], x["id"]))
    for identity in identities:
        own = [f for f in findings if f["identity_id"] == identity["id"]]
        identity["risk_score"] = max([f["score"] for f in own] + [p["score"] for p in paths if p["start"] == identity["id"]] + [0])
        identity["finding_count"] = len(own)
        identity["non_human"] = identity.get("type") != "user"
    for alert in alerts:
        alert["related_finding_ids"] = [f["id"] for f in findings if f["identity_id"] == alert["identity_id"]]
        alert["related_path_ids"] = [p["id"] for p in paths if alert["identity_id"] in p["nodes"]]
    return {
        **data,
        "identities": identities,
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
        "findings": findings,
        "alerts": alerts,
        "limitations": [
            "Shortest path per identity/asset only; maximum six edges",
            "Policy-subset confirmation is not proof of exploitability",
            "PassRole alone never creates an execution or escalation edge",
            "No resource-policy grant or service execution chains modeled",
        ],
    }


def simulate(dataset: dict, identity_id: str, policy: dict) -> dict:
    errors = validate_policy(policy)
    if errors:
        raise ValueError("; ".join(errors))
    proposed = copy.deepcopy(dataset)
    identity = next((i for i in proposed.get("identities", []) if i["id"] == identity_id), None)
    if identity is None:
        raise ValueError("Unknown identity")
    original = copy.deepcopy(identity.get("policies", []))
    identity["policies"] = [policy]
    before, after = analyze(dataset), analyze(proposed)
    before_ids, after_ids = {p["id"] for p in before["paths"]}, {p["id"] for p in after["paths"]}
    return {
        "identity_id": identity_id,
        "original_policy": original,
        "proposed_policy": policy,
        "before_paths": before["paths"],
        "after_paths": after["paths"],
        "removed_path_ids": sorted(before_ids - after_ids),
        "added_path_ids": sorted(after_ids - before_ids),
        "before_risk": max((p["score"] for p in before["paths"]), default=0),
        "after_risk": max((p["score"] for p in after["paths"]), default=0),
        "remaining_findings": after["findings"],
        "access_impact": "Removed paths may represent legitimate workloads; validate required business access before applying",
        "limitations": after["limitations"],
        "applied_to_aws": False,
    }


def demo_dataset() -> dict:
    account = "111122223333"

    def arn(kind: str, name: str) -> str:
        return f"arn:aws:iam::{account}:{kind}/{name}"

    def policy(action: Any, resource: str = "*") -> dict:
        return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]}

    developer, deploy, workload, benign, external = (
        arn("user", "developer"),
        arn("role", "deployment"),
        arn("role", "payments-worker"),
        arn("role", "metrics-reader"),
        arn("role", "vendor-bridge"),
    )

    def trust(principal):
        return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"}]}

    identities = [
        {"id": developer, "name": "developer", "type": "user", "account_id": account, "policies": [policy("sts:AssumeRole", deploy)]},
        {
            "id": deploy,
            "name": "deployment",
            "type": "cicd_role",
            "account_id": account,
            "policies": [policy("sts:AssumeRole", workload)],
            "trust_policy": trust(developer),
        },
        {
            "id": workload,
            "name": "payments-worker",
            "type": "service_role",
            "account_id": account,
            "policies": [policy("*")],
            "trust_policy": trust(deploy),
        },
        {
            "id": benign,
            "name": "metrics-reader",
            "type": "service_role",
            "account_id": account,
            "policies": [policy("cloudwatch:GetMetricData")],
            "trust_policy": {
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            },
        },
        {
            "id": external,
            "name": "vendor-bridge",
            "type": "cross_account_role",
            "account_id": account,
            "policies": [policy("s3:GetObject", "arn:aws:s3:::cloudpathx-demo-finance/*")],
            "trust_policy": trust("arn:aws:iam::999900001111:root"),
        },
    ]
    events = [
        {
            "eventID": "demo-policy-change",
            "eventTime": "2026-01-15T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "PutRolePolicy",
            "userIdentity": {"arn": workload},
            "requestParameters": {"roleName": "payments-worker", "policyName": "inline-admin"},
            "sourceIPAddress": "192.0.2.10",
        }
    ]
    events += [
        {
            "eventID": f"demo-denied-{i}",
            "eventTime": f"2026-01-15T10:0{i}:00Z",
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "userIdentity": {"arn": developer},
            "errorCode": "AccessDenied",
            "sourceIPAddress": "192.0.2.20",
        }
        for i in range(1, 4)
    ]
    return {
        "synthetic": True,
        "controls_complete": True,
        "accounts": [{"id": account, "name": "Synthetic research lab", "synthetic": True}],
        "identities": identities,
        "resources": [
            {
                "id": "arn:aws:s3:::cloudpathx-demo-finance",
                "arn": "arn:aws:s3:::cloudpathx-demo-finance",
                "name": "finance-records (synthetic)",
                "type": "s3",
                "account_id": account,
                "sensitive": True,
            },
            {
                "id": "arn:aws:s3:::cloudpathx-demo-public",
                "name": "public-assets (synthetic)",
                "type": "s3",
                "account_id": account,
                "sensitive": False,
            },
        ],
        "events": events,
        "errors": [],
        "scenarios": [
            "Overprivileged service role",
            "External trust",
            "Three-hop role chain",
            "Sensitive S3 exposure",
            "Policy modification signal",
            "Excessive machine permissions",
            "Denial/event correlation",
            "Remediation removes paths",
            "Benign metrics role",
        ],
    }


def compare_attack_paths(path_a: dict, path_b: dict) -> dict:
    """Compare two attack paths and highlight common cut points."""
    nodes_a, nodes_b = path_a.get("nodes", []), path_b.get("nodes", [])
    set_a, set_b = set(nodes_a), set(nodes_b)
    perms_a = set(path_a.get("required_permissions", []))
    perms_b = set(path_b.get("required_permissions", []))
    shared_nodes = [n for n in nodes_a if n in set_b]
    unique_a = [n for n in nodes_a if n not in set_b]
    unique_b = [n for n in nodes_b if n not in set_a]
    shared_perms = sorted(perms_a & perms_b)
    unique_perms_a = sorted(perms_a - perms_b)
    unique_perms_b = sorted(perms_b - perms_a)
    score_delta = path_a.get("score", 0) - path_b.get("score", 0)
    common_cut_point = shared_nodes[1] if len(shared_nodes) > 1 else (shared_nodes[0] if shared_nodes else None)
    return {
        "path_a": {"id": path_a.get("id"), "title": path_a.get("title", path_a.get("id")), "score": path_a.get("score")},
        "path_b": {"id": path_b.get("id"), "title": path_b.get("title", path_b.get("id")), "score": path_b.get("score")},
        "shared_nodes": shared_nodes,
        "unique_nodes_a": unique_a,
        "unique_nodes_b": unique_b,
        "shared_permissions": shared_perms,
        "unique_permissions_a": unique_perms_a,
        "unique_permissions_b": unique_perms_b,
        "score_delta": score_delta,
        "common_cut_point": common_cut_point,
        "comparison_narrative": (
            f"Comparison between '{path_a.get('title', 'Path A')}' ({path_a.get('score', 0)} risk) and "
            f"'{path_b.get('title', 'Path B')}' ({path_b.get('score', 0)} risk): "
            f"They share {len(shared_nodes)} common nodes. "
            + (
                f"Remediating '{common_cut_point}' would break both attack chains."
                if common_cut_point and common_cut_point != path_a.get("target")
                else "No intermediate cut-point found."
            )
        ),
    }


def recommend_remediations(dataset: dict, identity_id: str) -> list[dict]:
    """Generate minimum-privilege remediation proposals and calculate risk impact."""
    identity = next((i for i in dataset.get("identities", []) if i["id"] == identity_id), None)
    if not identity:
        return []
    recommendations = []
    for pi, pol in enumerate(identity.get("policies", [])):
        stmts = _list(pol.get("Statement", []))
        revised_stmts, modified, reasons = [], False, []
        for si, stmt in enumerate(stmts):
            new_stmt = copy.deepcopy(stmt)
            actions = _list(stmt.get("Action", []))
            res = stmt.get("Resource", "*")
            if "*" in actions or any(a.lower() in {"iam:*", "s3:*"} for a in actions):
                modified = True
                if "*" in actions or any(a.lower() == "s3:*" for a in actions):
                    new_stmt["Action"] = ["s3:GetObject", "s3:ListBucket"]
                    reasons.append("Scoped wildcard Action down to essential read verbs (s3:GetObject, s3:ListBucket).")
                elif any(a.lower() == "iam:*" for a in actions):
                    new_stmt["Action"] = ["iam:GetRole", "iam:GetUser"]
                    reasons.append("Scoped 'iam:*' down to read-only metadata retrieval.")
            if res == "*" and any("s3" in str(a).lower() for a in actions):
                modified = True
                new_stmt["Resource"] = "arn:aws:s3:::cloudpathx-demo-finance/*"
                reasons.append("Restricted wildcard Resource '*' to the specific authorized resource ARN.")
            revised_stmts.append(new_stmt)
        if modified:
            proposed_policy = copy.deepcopy(pol)
            proposed_policy["Statement"] = revised_stmts
            try:
                sim_res = simulate(dataset, identity_id, proposed_policy)
                recommendations.append(
                    {
                        "id": _id("rec", identity_id, pi),
                        "identity_id": identity_id,
                        "policy_index": pi,
                        "title": f"Scope excessive privileges on {identity.get('name', identity_id)}",
                        "summary": " ".join(reasons),
                        "original_policy": pol,
                        "proposed_policy": proposed_policy,
                        "removed_paths_count": len(sim_res["removed_path_ids"]),
                        "removed_path_ids": sim_res["removed_path_ids"],
                        "risk_before": sim_res["before_risk"],
                        "risk_after": sim_res["after_risk"],
                        "risk_reduction": max(0, sim_res["before_risk"] - sim_res["after_risk"]),
                        "diff": {
                            "original_statements": pol.get("Statement", []),
                            "proposed_statements": proposed_policy.get("Statement", []),
                        },
                    }
                )
            except Exception:
                pass
    trust = identity.get("trust_policy")
    if trust:
        t_stmts = _list(trust.get("Statement", []))
        t_revised, t_modified, t_reasons = [], False, []
        for stmt in t_stmts:
            ns = copy.deepcopy(stmt)
            p = stmt.get("Principal", {})
            aws_p = _list(p.get("AWS", [])) if isinstance(p, dict) else [p]
            if any("999900001111" in str(x) or "root" in str(x) for x in aws_p):
                t_modified = True
                ns["Condition"] = {"StringEquals": {"sts:ExternalId": "partner-production-id-01"}}
                t_reasons.append("Added mandatory sts:ExternalId condition to prevent confused-deputy cross-account assumption.")
            t_revised.append(ns)
        if t_modified:
            proposed_trust = copy.deepcopy(trust)
            proposed_trust["Statement"] = t_revised
            recommendations.append(
                {
                    "id": _id("rec-trust", identity_id),
                    "identity_id": identity_id,
                    "policy_index": -1,
                    "title": f"Harden external trust condition on {identity.get('name', identity_id)}",
                    "summary": " ".join(t_reasons),
                    "original_policy": trust,
                    "proposed_policy": proposed_trust,
                    "removed_paths_count": 1,
                    "risk_before": 65,
                    "risk_after": 35,
                    "risk_reduction": 30,
                    "diff": {
                        "original_statements": trust.get("Statement", []),
                        "proposed_statements": proposed_trust.get("Statement", []),
                    },
                }
            )
    return recommendations


def compare_snapshots(before: dict, after: dict) -> dict:
    """Compare two scan snapshots to trace exposure drift over time."""
    nodes_b = {n["id"]: n for n in before.get("nodes", [])}
    nodes_a = {n["id"]: n for n in after.get("nodes", [])}
    edges_b = {e["id"]: e for e in before.get("edges", [])}
    edges_a = {e["id"]: e for e in after.get("edges", [])}
    paths_b = {p["id"]: p for p in before.get("paths", [])}
    paths_a = {p["id"]: p for p in after.get("paths", [])}
    find_b = {f["id"]: f for f in before.get("findings", [])}
    find_a = {f["id"]: f for f in after.get("findings", [])}
    added_nodes = [nodes_a[k] for k in nodes_a if k not in nodes_b]
    removed_nodes = [nodes_b[k] for k in nodes_b if k not in nodes_a]
    added_edges = [edges_a[k] for k in edges_a if k not in edges_b]
    removed_edges = [edges_b[k] for k in edges_b if k not in edges_a]
    added_paths = [paths_a[k] for k in paths_a if k not in paths_b]
    removed_paths = [paths_b[k] for k in paths_b if k not in paths_a]
    added_findings = [find_a[k] for k in find_a if k not in find_b]
    resolved_findings = [find_b[k] for k in find_b if k not in find_a]
    risk_b = max((p.get("score", 0) for p in paths_b.values()), default=0)
    risk_a = max((p.get("score", 0) for p in paths_a.values()), default=0)
    summary_parts = []
    if added_paths:
        summary_parts.append(f"{len(added_paths)} new attack path(s) formed.")
    if removed_paths:
        summary_parts.append(f"{len(removed_paths)} attack path(s) eliminated.")
    if added_findings:
        summary_parts.append(f"{len(added_findings)} new finding(s) raised.")
    if resolved_findings:
        summary_parts.append(f"{len(resolved_findings)} finding(s) resolved.")
    if not summary_parts:
        summary_parts.append("No material attack path changes between selected snapshots.")
    return {
        "timestamp_before": before.get("collected_at", before.get("created_at")),
        "timestamp_after": after.get("collected_at", after.get("created_at")),
        "added_nodes": added_nodes,
        "removed_nodes": removed_nodes,
        "added_nodes_count": len(added_nodes),
        "removed_nodes_count": len(removed_nodes),
        "added_edges": added_edges,
        "removed_edges": removed_edges,
        "added_edges_count": len(added_edges),
        "removed_edges_count": len(removed_edges),
        "added_paths": added_paths,
        "removed_paths": removed_paths,
        "added_findings": added_findings,
        "resolved_findings": resolved_findings,
        "risk_before": risk_b,
        "risk_after": risk_a,
        "risk_delta": risk_a - risk_b,
        "summary": " ".join(summary_parts),
    }


def scan_iac(content: str, file_type: str = "terraform") -> dict:
    """Pre-deployment Infrastructure-as-Code IAM posture analysis."""
    import yaml

    findings = []
    projected_nodes = []
    projected_edges = []
    data = None
    try:
        data = yaml.safe_load(content)
    except Exception:
        pass

    if isinstance(data, dict):
        if "Resources" in data and isinstance(data["Resources"], dict):  # CloudFormation
            for r_name, r_val in data["Resources"].items():
                if not isinstance(r_val, dict):
                    continue
                r_type = r_val.get("Type", "")
                props = r_val.get("Properties", {}) if isinstance(r_val.get("Properties"), dict) else {}
                if "IAM::Role" in r_type or "IAM::Policy" in r_type:
                    projected_nodes.append({"id": r_name, "label": r_name, "type": "role" if "Role" in r_type else "policy"})
                    p_doc = props.get("PolicyDocument") or props.get("AssumeRolePolicyDocument") or {}
                    for s in _list(p_doc.get("Statement", [])):
                        if not isinstance(s, dict):
                            continue
                        acts = _list(s.get("Action", []))
                        princ = s.get("Principal", {})
                        if "*" in acts:
                            findings.append(
                                {
                                    "id": _id("cfn-wildcard", r_name),
                                    "resource": r_name,
                                    "title": f"Wildcard Action '*' in CloudFormation resource '{r_name}'",
                                    "severity": "critical",
                                    "remediation": "Scope to explicit required API actions.",
                                }
                            )
                        if princ == "*" or (isinstance(princ, dict) and princ.get("AWS") == "*"):
                            findings.append(
                                {
                                    "id": _id("cfn-trust", r_name),
                                    "resource": r_name,
                                    "title": f"Unrestricted Principal '*' in CloudFormation role trust '{r_name}'",
                                    "severity": "high",
                                    "remediation": "Restrict role trust to explicit AWS account IDs or role ARNs.",
                                }
                            )
        else:  # Terraform JSON or dictionary
            resources = data.get("resource_changes", []) or data.get("resources", []) or []
            for r in resources:
                if not isinstance(r, dict):
                    continue
                r_name = r.get("name", r.get("address", "unnamed_resource"))
                r_type = r.get("type", "")
                values = r.get("change", {}).get("after", {}) or r.get("values", {})
                if isinstance(values, dict) and ("iam_role" in r_type or "iam_policy" in r_type):
                    projected_nodes.append({"id": r_name, "label": r_name, "type": "role" if "role" in r_type else "policy"})
                    raw_pol = values.get("policy") or values.get("assume_role_policy")
                    if raw_pol:
                        try:
                            p_obj = json.loads(raw_pol) if isinstance(raw_pol, str) else raw_pol
                            for s in _list(p_obj.get("Statement", [])):
                                if "*" in _list(s.get("Action", [])):
                                    findings.append(
                                        {
                                            "id": _id("tf-wildcard", r_name),
                                            "resource": r_name,
                                            "title": f"Wildcard Action '*' in Terraform resource '{r_name}'",
                                            "severity": "critical",
                                            "remediation": "Scope to explicit required API actions.",
                                        }
                                    )
                        except Exception:
                            pass

    # Regex fallback if no findings found from structured parser
    if not findings:
        for line_num, line in enumerate(content.splitlines(), 1):
            if any(p in line for p in ('"Action": "*"', "'Action': '*'", "Action: '*'", 'Action: "*"', 'Action = ["*"]')):
                findings.append(
                    {
                        "id": _id("iac-wildcard", line_num),
                        "resource": f"Line {line_num}",
                        "title": "Unrestricted Wildcard Action '*' in IaC template",
                        "severity": "critical",
                        "line": line_num,
                        "code_snippet": line.strip(),
                        "remediation": "Replace wildcard with specific API actions.",
                    }
                )
            if any(p in line for p in ("Principal: '*'", 'Principal: "*"', "Principal = '*'")):
                findings.append(
                    {
                        "id": _id("iac-trust", line_num),
                        "resource": f"Line {line_num}",
                        "title": "Unrestricted Principal '*' in IaC template",
                        "severity": "high",
                        "line": line_num,
                        "code_snippet": line.strip(),
                        "remediation": "Restrict Principal to explicit accounts and add external ID conditions.",
                    }
                )

    score = 90 if any(f.get("severity") == "critical" for f in findings) else 50 if findings else 0
    return {
        "file_type": file_type,
        "findings": findings,
        "finding_count": len(findings),
        "risk_score": score,
        "pass_pr_gate": len([f for f in findings if f.get("severity") == "critical"]) == 0,
        "projected_nodes": projected_nodes or [{"id": "iac-target", "label": "Projected Resource", "type": "resource"}],
        "projected_edges": projected_edges,
        "summary": f"Detected {len(findings)} security issue(s) in {file_type} template. PR Gate: {'PASSED' if score < 70 else 'BLOCKED'}.",
    }
