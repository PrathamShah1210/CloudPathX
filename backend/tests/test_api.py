import os
import tempfile
os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mktemp(prefix="cloudpathx-api-", suffix=".db")
import pytest
from fastapi.testclient import TestClient
from app.db import Base, SessionLocal, User, engine
from app.main import app, login_attempts
from app.security import password_hash
from app.worker import tick

@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    login_attempts.clear()
    with SessionLocal() as db:
        for role, email in [("Administrator", "admin@example.test"), ("Viewer", "viewer@example.test"), ("Security Analyst", "analyst@example.test")]:
            db.add(User(email=email, password_hash=password_hash("test-only-password-123"), role=role))
        db.commit()
    with TestClient(app) as c:
        yield c

def auth(client, email="admin@example.test"):
    result = client.post("/api/v1/auth/login", json={"email": email, "password": "test-only-password-123"})
    assert result.status_code == 200
    return {"Authorization": "Bearer " + result.json()["token"]}

def test_auth_rbac_logout(client):
    assert client.get("/api/v1/identities").status_code == 401
    viewer = auth(client, "viewer@example.test")
    assert client.get("/api/v1/identities", headers=viewer).status_code == 200
    assert client.post("/api/v1/scans", headers=viewer, json={"mode": "demo"}).status_code == 403
    assert client.get("/api/v1/users", headers=viewer).status_code == 403
    assert client.patch("/api/v1/settings", headers=viewer, json={}).status_code == 403
    assert client.post("/api/v1/auth/logout", headers=viewer).status_code == 200
    assert client.get("/api/v1/auth/me", headers=viewer).status_code == 401

def test_scan_workflow_and_remediation(client):
    headers = auth(client)
    result = client.post("/api/v1/scans", headers=headers, json={"mode": "demo"})
    assert result.status_code == 202
    assert tick()
    scan = client.get("/api/v1/scans", headers=headers).json()["items"][0]
    assert scan["status"] == "completed", scan
    graph = client.get("/api/v1/graph", headers=headers).json()
    assert graph["nodes"] and graph["edges"]
    assert client.get("/api/v1/analytics", headers=headers).json()["identities"] > 0
    identities = client.get("/api/v1/identities", headers=headers).json()["items"]
    simulation = client.post("/api/v1/remediation", headers=headers, json={"identity_id": identities[0]["id"], "policy": {"Version": "2012-10-17", "Statement": []}})
    assert simulation.status_code == 200, simulation.text
    assert "before_paths" in simulation.json()
    findings = client.get("/api/v1/findings", headers=headers).json()["items"]
    finding = findings[0]
    assert client.patch("/api/v1/findings/" + finding["id"], headers=headers, json={"status": "Investigating", "note": "Evidence reviewed"}).status_code == 200
    incident = client.post("/api/v1/incidents", headers=headers, json={"title": "Investigation", "finding_ids": [finding["id"]]})
    assert incident.status_code == 201
    assert client.patch("/api/v1/incidents/" + incident.json()["id"], headers=headers, json={"note": "Review recorded", "status": "Mitigated"}).status_code == 200
    exported = client.get("/api/v1/reports", headers=headers)
    assert exported.status_code == 200 and exported.json()["synthetic"]
    pdf = client.get("/api/v1/reports?format=pdf", headers=headers)
    assert pdf.content.startswith(b"%PDF")
    assert client.get("/api/v1/audit", headers=headers).json()["total"] >= 6
    stream = client.get(f'/api/v1/scans/{scan["id"]}/stream', headers=headers)
    assert "completed" in stream.text

def test_validation_and_accounts(client):
    headers = auth(client)
    assert client.post("/api/v1/accounts", headers=headers, json={"name": "bad", "expected_account_id": "x"}).status_code == 422
    created = client.post("/api/v1/accounts", headers=headers, json={"name": "Research", "expected_account_id": "123456789012", "region": "us-east-1"})
    assert created.status_code == 201
    assert client.post("/api/v1/scans", headers=headers, json={"mode": "aws", "account_id": "missing"}).status_code == 422
    assert client.post("/api/v1/users", headers=headers, json={"email": "new@example.test", "password": "long-test-password", "role": "Viewer"}).status_code == 201
    assert client.post("/api/v1/users", headers=headers, json={"email": "new@example.test", "password": "long-test-password", "role": "Viewer"}).status_code == 409
    assert client.patch("/api/v1/settings", headers=headers, json={"retention_days": 30, "scan_interval_minutes": 60}).status_code == 200
    assert client.get("/api/v1/settings", headers=headers).json()["retention_days"] == 30
    assert client.post("/api/v1/events/import", headers=headers, json={"Records": [{}]}).status_code == 422
    assert client.get("/api/v1/identities?limit=1000", headers=headers).status_code == 422

def test_events_policy_and_viewer_report(client):
    headers = auth(client, "analyst@example.test")
    record = {"eventID": "e1", "eventTime": "2026-10-25T10:00:00Z", "eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test"}}
    result = client.post("/api/v1/events/import", headers=headers, json={"Records": [record]})
    assert result.status_code == 200
    assert client.get("/api/v1/events", headers=headers).json()["total"] == 1
    again = client.post("/api/v1/events/import", headers=headers, json={"Records": [record]})
    assert again.status_code == 200
    assert client.get("/api/v1/events", headers=headers).json()["total"] == 1
    analyzed = client.post("/api/v1/policies/analyze", headers=headers, json={"policy": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}, "action": "s3:GetObject", "resource": "arn:aws:s3:::test/item"})
    assert analyzed.status_code == 200
    viewer = auth(client, "viewer@example.test")
    assert client.get("/api/v1/reports", headers=viewer).status_code == 200
    assert client.post("/api/v1/policies/analyze", headers=viewer, json={"policy": {}, "action": "a", "resource": "*"}).status_code == 403

def test_login_failure_rate_limit(client):
    for _ in range(10):
        assert client.post("/api/v1/auth/login", json={"email": "bad@example.test", "password": "bad"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "bad@example.test", "password": "bad"}).status_code == 429
