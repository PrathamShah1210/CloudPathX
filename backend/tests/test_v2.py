"""Comprehensive test suite for CloudPathX V2.0 enterprise capabilities."""
import os
import tempfile

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mktemp(prefix="cloudpathx-v2-", suffix=".db")

import pytest
from fastapi.testclient import TestClient
from app.db import Base, SessionLocal, User, engine
from app.main import app, login_attempts
from app.security import password_hash
from app.worker import tick
from app.engine import analyze, compare_attack_paths, compare_snapshots, demo_dataset, recommend_remediations, scan_iac
from app.copilot import query_copilot


@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    login_attempts.clear()
    with SessionLocal() as db:
        for role, email in [
            ("Administrator", "admin@example.test"),
            ("Viewer", "viewer@example.test"),
            ("Security Analyst", "analyst@example.test"),
        ]:
            db.add(User(email=email, password_hash=password_hash("test-only-password-123"), role=role))
        db.commit()
    with TestClient(app) as c:
        yield c


def auth(client, email="analyst@example.test"):
    result = client.post("/api/v1/auth/login", json={"email": email, "password": "test-only-password-123"})
    assert result.status_code == 200
    return {"Authorization": f"Bearer {result.json()['token']}"}


def test_compare_attack_paths():
    data = demo_dataset()
    res = analyze(data)
    paths = res["paths"]
    assert len(paths) >= 2
    comp = compare_attack_paths(paths[0], paths[1])
    assert "shared_nodes" in comp
    assert "score_delta" in comp
    assert "comparison_narrative" in comp
    assert isinstance(comp["shared_nodes"], list)


def test_recommend_remediations():
    data = demo_dataset()
    payments_worker = next(i for i in data["identities"] if i["name"] == "payments-worker")
    recs = recommend_remediations(data, payments_worker["id"])
    assert len(recs) >= 1
    rec = recs[0]
    assert "diff" in rec
    assert rec["risk_reduction"] >= 0
    assert "proposed_policy" in rec


def test_compare_snapshots():
    data1 = demo_dataset()
    res1 = analyze(data1)
    # Simulate a mutation: add an extra benign identity
    data2 = demo_dataset()
    data2["identities"].append({
        "id": "arn:aws:iam::111122223333:role/new-worker",
        "name": "new-worker",
        "type": "service_role",
        "account_id": "111122223333",
        "policies": [{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}]
    })
    res2 = analyze(data2)
    delta = compare_snapshots(res1, res2)
    assert delta["added_nodes_count"] >= 1
    assert "summary" in delta


def test_scan_iac_terraform_and_cloudformation():
    tf_content = """
    resource "aws_iam_role_policy" "admin" {
      name = "admin-access"
      role = "worker"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Action = ["*"]
            Effect = "Allow"
            Resource = "*"
          }
        ]
      })
    }
    """
    res_tf = scan_iac(tf_content, "terraform")
    assert res_tf["finding_count"] >= 1
    assert any(f["severity"] == "critical" for f in res_tf["findings"])
    assert res_tf["pass_pr_gate"] is False

    cfn_content = """
    AWSTemplateFormatVersion: '2010-09-09'
    Resources:
      AppRole:
        Type: 'AWS::IAM::Role'
        Properties:
          AssumeRolePolicyDocument:
            Statement:
              - Effect: Allow
                Principal: '*'
                Action: 'sts:AssumeRole'
    """
    res_cfn = scan_iac(cfn_content, "cloudformation")
    assert res_cfn["finding_count"] >= 1


def test_copilot_grounded_queries():
    data = demo_dataset()
    res = analyze(data)
    context = {
        "identities": res["identities"],
        "paths": res["paths"],
        "findings": res["findings"],
        "alerts": res["alerts"],
        "resources": res["resources"],
    }
    # Query 1: Path reasoning
    ans1 = query_copilot("Why can payments-worker access the finance bucket?", context)
    assert "citations" in ans1
    assert len(ans1["citations"]) >= 1
    assert "finance" in ans1["answer"].lower() or "attack path" in ans1["answer"].lower()

    # Query 2: Risk ranking
    ans2 = query_copilot("Which identities have the most dangerous permissions?", context)
    assert "High-Risk" in ans2["answer"]

    # Query 3: Remediation
    ans3 = query_copilot("How to remediate this attack path?", context)
    assert "Remediation" in ans3["answer"]


def test_v2_api_endpoints(client):
    headers = auth(client, "analyst@example.test")

    # Queue a demo scan
    scan_resp = client.post("/api/v1/scans", json={"mode": "demo"}, headers=headers)
    assert scan_resp.status_code == 202

    # Process scan directly
    tick()

    # 1. Snapshots endpoint
    snap_resp = client.get("/api/v1/snapshots", headers=headers)
    assert snap_resp.status_code == 200
    snaps = snap_resp.json()["items"]
    assert len(snaps) >= 1

    # 2. Path compare endpoint
    paths_resp = client.get("/api/v1/attack-paths", headers=headers)
    assert paths_resp.status_code == 200
    paths = paths_resp.json()["items"]
    if len(paths) >= 2:
        comp_resp = client.post(
            "/api/v1/attack-paths/compare",
            json={"path_a_id": paths[0]["id"], "path_b_id": paths[1]["id"]},
            headers=headers,
        )
        assert comp_resp.status_code == 200
        assert "shared_nodes" in comp_resp.json()

    # 3. Remediation recommend endpoint
    identities_resp = client.get("/api/v1/identities", headers=headers)
    assert identities_resp.status_code == 200
    identities = identities_resp.json()["items"]
    payments = next((i for i in identities if "payments" in i.get("name", "")), identities[0])
    rec_resp = client.post(
        "/api/v1/remediation/recommend",
        json={"identity_id": payments["id"]},
        headers=headers,
    )
    assert rec_resp.status_code == 200
    assert "items" in rec_resp.json()

    # 4. IaC scan endpoint
    iac_resp = client.post(
        "/api/v1/iac/scan",
        json={"content": '{"resource_changes": []}', "file_type": "terraform"},
        headers=headers,
    )
    assert iac_resp.status_code == 200
    assert "findings" in iac_resp.json()

    # 5. Copilot query endpoint
    copilot_resp = client.post(
        "/api/v1/copilot/query",
        json={"query": "Which identities have dangerous permissions?"},
        headers=headers,
    )
    assert copilot_resp.status_code == 200
    assert "answer" in copilot_resp.json()

    # 6. Notification test endpoint (admin only)
    admin_headers = auth(client, "admin@example.test")
    notif_resp = client.post(
        "/api/v1/notifications/test",
        json={"channel": "webhook", "endpoint": "https://example.com/webhook"},
        headers=admin_headers,
    )
    assert notif_resp.status_code == 200
    assert notif_resp.json()["status"] == "success"

    # 7. Evaluation run endpoint
    eval_resp = client.post("/api/v1/evaluation/run", headers=headers)
    assert eval_resp.status_code == 200
    assert "methods" in eval_resp.json()

    eval_get = client.get("/api/v1/evaluation/results", headers=headers)
    assert eval_get.status_code == 200
