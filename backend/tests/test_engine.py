from copy import deepcopy

import pytest

from app.engine import _condition, _match, analyze, demo_dataset, detect_events, evaluate, risk_score, simulate, validate_policy


def policy(action="s3:GetObject", resource="*", effect="Allow", **kw):
    return {"Statement": [{"Effect": effect, "Action": action, "Resource": resource, **kw}]}


def test_explicit_deny_and_union():
    assert evaluate([policy(), policy(effect="Deny")], "s3:GetObject", "x")["decision"] == "denied"
    assert evaluate([policy("ec2:DescribeInstances"), policy()], "s3:GetObject", "x")["decision"] == "allowed"
    assert evaluate(policy(), "s3:PutObject", "x")["decision"] == "denied"


def test_iam_wildcards_not_shell_patterns():
    assert _match("S3:Get*", "s3:GetObject", True)
    assert _match("bucket/?", "bucket/a")
    assert not _match("bucket/[ab]", "bucket/a")
    assert not _match("ARN:A", "arn:a")


def test_not_action_not_resource():
    p = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "NotResource": "arn:secret:*"}]}
    assert evaluate(p, "s3:GetObject", "arn:public:a")["decision"] == "allowed"
    assert evaluate(p, "iam:GetRole", "arn:public:a")["decision"] == "denied"
    assert evaluate(p, "s3:GetObject", "arn:secret:a")["decision"] == "denied"


def test_boundaries_session_and_org_layers():
    for key in ["boundary", "session_policy"]:
        assert evaluate(policy("*"), "s3:GetObject", "x", **{key: policy("ec2:*")})["decision"] == "denied"
    for key in ["scps", "rcps"]:
        assert evaluate(policy("*"), "s3:GetObject", "x", **{key: [policy("*"), policy(effect="Deny")]})["decision"] == "denied"
    assert evaluate(policy(), "s3:GetObject", "x", controls_complete=False)["decision"] == "uncertain"
    assert evaluate(policy(), "s3:GetObject", "x", unsupported=True)["decision"] == "uncertain"


def test_unknown_conditions_do_not_confirm_or_erase_deny():
    conditional = policy(Condition={"StringEquals": {"aws:SourceVpce": "vpce-123"}})
    assert evaluate(conditional, "s3:GetObject", "x")["decision"] == "uncertain"
    assert evaluate(conditional, "s3:GetObject", "x", {"aws:SourceVpce": "vpce-123"})["decision"] == "allowed"
    assert evaluate(conditional, "s3:GetObject", "x", {"aws:SourceVpce": "vpce-other"})["decision"] == "denied"
    deny = policy(effect="Deny", Condition={"Unsupported": {"key": "x"}})
    assert evaluate([policy(), deny], "s3:GetObject", "x", {"key": "x"})["decision"] == "uncertain"
    assert evaluate([conditional, policy(effect="Deny")], "s3:GetObject", "x")["decision"] == "denied"


@pytest.mark.parametrize(
    "operator,actual,expected,result",
    [
        ("StringEqualsIgnoreCase", "YES", "yes", True),
        ("StringLike", "team-a", "team-*", True),
        ("ArnEquals", "arn:a", "arn:a", True),
        ("ArnNotEquals", "arn:a", "arn:b", True),
        ("StringNotEquals", "x", ["a", "b"], True),
        ("StringNotLike", "abc", "a*", False),
        ("ArnNotLike", "arn:a", "arn:b*", True),
        ("Bool", True, "true", True),
        ("IpAddress", "192.0.2.1", "192.0.2.0/24", True),
        ("NotIpAddress", "192.0.2.1", "10.0.0.0/8", True),
        ("NumericLessThan", 1, 2, True),
        ("NumericGreaterThanEquals", 2, 2, True),
        ("DateGreaterThan", "2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z", True),
        ("NumericNoSuch", 1, 1, None),
        ("IpAddress", "invalid", "10.0.0.0/8", None),
    ],
)
def test_condition_operators(operator, actual, expected, result):
    assert _condition({operator: {"key": expected}}, {"key": actual})[0] is result


def test_condition_unknown_and_null():
    assert _condition({"Null": {"key": "true"}}, {"key": None})[0] is True
    assert _condition({"Null": {"key": "true"}}, {"key": "x"})[0] is False
    assert _condition({"Null": {"key": "true"}}, {})[0] is None
    assert _condition({"StringEqualsIfExists": {"key": "x"}}, {"__complete__": True})[0] is True
    assert _condition({"ForAllValues:StringEquals": {"key": "x"}}, {"key": "x"})[0] is None
    assert _condition({"StringEquals": {"key": "${variable}"}}, {"key": "x"})[0] is None
    assert _condition({"StringEquals": []}, {})[0] is None


def test_resource_policy_conservative():
    assert evaluate(policy(), "s3:GetObject", "x", resource_policy=policy(effect="Deny"))["decision"] == "denied"
    assert evaluate(policy("ec2:*"), "s3:GetObject", "x", resource_policy=policy())["decision"] == "uncertain"
    assert evaluate(policy(resource="${aws:username}"), "s3:GetObject", "x")["decision"] == "uncertain"


def test_trust_matching():
    source = "arn:aws:iam::111122223333:user/alice"
    for principal in ["*", {"AWS": source}, {"AWS": "111122223333"}, {"AWS": "arn:aws:iam::111122223333:root"}]:
        assert evaluate(policy("sts:AssumeRole", Principal=principal), "sts:AssumeRole", "x", principal=source)["decision"] == "allowed"
    assert (
        evaluate(policy("sts:AssumeRole", Principal={"AWS": "999900001111"}), "sts:AssumeRole", "x", principal=source)["decision"]
        == "denied"
    )
    assert (
        evaluate(policy("sts:AssumeRole", Principal={"Service": "lambda.amazonaws.com"}), "sts:AssumeRole", "x", principal=source)[
            "decision"
        ]
        == "denied"
    )
    assert evaluate(policy(Principal="*"), "s3:GetObject", "x")["decision"] == "uncertain"
    assert evaluate(policy(NotPrincipal="*"), "s3:GetObject", "x", principal=source)["decision"] == "uncertain"
    assert evaluate(policy(Principal={"Federated": "x"}), "s3:GetObject", "x", principal="federated")["decision"] == "uncertain"


@pytest.mark.parametrize(
    "p",
    [
        None,
        {},
        {"Statement": [1]},
        policy(effect="Invalid"),
        {"Statement": [{"Effect": "Allow"}]},
        policy(NotAction="*"),
        policy(NotResource="x"),
        policy(action=[]),
        policy(Condition=[]),
        policy(action=3),
    ],
)
def test_policy_validation(p):
    assert validate_policy(p)
    assert evaluate(p, "s3:GetObject", "x")["decision"] == "uncertain"


def test_demo_expected_paths_and_benign():
    data = demo_dataset()
    result = analyze(data)
    developer = next(i for i in result["identities"] if i["name"] == "developer")
    benign = next(i for i in result["identities"] if i["name"] == "metrics-reader")
    path = next(p for p in result["paths"] if p["start"] == developer["id"])
    assert len(path["nodes"]) == 4
    assert path["confidence"] == "confirmed"
    assert path["evidence"]
    assert benign["risk_score"] == 0
    assert len(result["paths"]) == 4
    assert len(result["alerts"]) == 2
    assert any(a["related_path_ids"] for a in result["alerts"])
    assert data == demo_dataset(), "analysis must not mutate source"


def test_live_unknown_controls_and_trust_prerequisites():
    data = demo_dataset()
    data["controls_complete"] = False
    assert all(p["confidence"] == "uncertain" for p in analyze(data)["paths"])
    data = demo_dataset()
    data["identities"][1]["trust_policy"] = policy("sts:AssumeRole", Principal={"AWS": "999900001111"})
    assert not any(p["start"] == data["identities"][0]["id"] for p in analyze(data)["paths"])
    data["identities"][0]["policies"] = [policy("iam:PassRole")]
    assert not any(p["start"] == data["identities"][0]["id"] for p in analyze(data)["paths"])


def test_remediation_is_pure_and_removes_chain():
    data = demo_dataset()
    before = deepcopy(data)
    result = simulate(data, data["identities"][2]["id"], policy("cloudwatch:GetMetricData"))
    assert len(result["removed_path_ids"]) == 3
    assert len(result["after_paths"]) == 1
    assert not result["applied_to_aws"]
    assert data == before
    with pytest.raises(ValueError):
        simulate(data, "unknown", policy())
    with pytest.raises(ValueError):
        simulate(data, data["identities"][0]["id"], {})


def test_event_failed_mutation_not_successful_signal_and_duplicates():
    event = {"eventID": "a", "eventName": "CreateAccessKey", "userIdentity": {"arn": "x"}}
    assert len(detect_events([event, event])) == 1
    assert not detect_events([{**event, "errorCode": "AccessDenied"}])
    cross = {
        "eventID": "b",
        "eventName": "AssumeRole",
        "userIdentity": {"arn": "arn:aws:iam::111122223333:user/x"},
        "requestParameters": {"roleArn": "arn:aws:iam::999900001111:role/y"},
    }
    assert detect_events([cross])[0]["rule"] == "cross_account_assumption"
    assert not detect_events([{**cross, "errorCode": "AccessDenied"}])
    events = [
        {"eventID": str(i), "eventName": "GetObject", "eventTime": f"2026-01-01T0{i}:00:00Z", "errorCode": "AccessDenied"} for i in range(3)
    ]
    assert not detect_events(events)
    events[0]["eventTime"] = "invalid"
    assert not detect_events(events)


def test_scoring_reproducible_explained():
    a = risk_score(sensitive=True, external=True, workload=True, behavior=True)
    assert a["score"] == sum(a["factors"].values()) == 90
    assert a["severity"] == "critical"
    assert risk_score(sensitive=True, external=True)["severity"] == "high"
    assert risk_score()["severity"] == "low"
    assert risk_score(sensitive=True, confidence="uncertain", hops=3)["score"] < risk_score(sensitive=True)["score"]


def test_malformed_policy_and_resource_skip():
    data = demo_dataset()
    data["identities"][0]["policies"] = [{}]
    data["resources"].append({"id": "lambda", "type": "lambda", "sensitive": True})
    result = analyze(data)
    assert any(f["title"] == "Policy could not be analyzed" for f in result["findings"])
    assert not any(p["target"] == "lambda" for p in result["paths"])


def test_missing_resource_only_permitted_in_trust_mode():
    p = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}]}
    assert evaluate(p, "sts:AssumeRole", "x", principal="arn:aws:iam::111122223333:user/a")["decision"] == "uncertain"
    assert evaluate(p, "sts:AssumeRole", "x", principal="arn:aws:iam::111122223333:user/a", policy_type="trust")["decision"] == "allowed"


def test_multivalued_context_and_empty_resource_policy():
    assert _condition({"StringEquals": {"key": "a"}}, {"key": ["a", "b"]})[0] is None
    assert evaluate(policy("ec2:*"), "s3:GetObject", "x", resource_policy={})["decision"] == "denied"
    assert evaluate(policy("ec2:*"), "s3:GetObject", "x", resource_policy=policy("s3:PutObject"))["decision"] == "denied"
    assert not detect_events([{"eventID": "a", "eventName": "PutRolePolicy", "errorCode": "LimitExceeded"}])
