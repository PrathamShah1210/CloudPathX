"""Versioned API with server-side RBAC and source-evidence preservation."""
import asyncio
import copy
import io
import json
import logging
import os
import time
from collections import defaultdict, deque
from typing import Literal
from xml.sax.saxutils import escape
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, select, text
from .db import Audit, MODELS, Scan, Session, SessionLocal, User, now, uid
from .security import admin, analyst, bearer, current_user, digest_token, issue_session, password_hash, verify_password
from .store import active_scans, audit, latest_scan, records, scan_json, settings, upsert

app = FastAPI(title="CloudPathX", version="0.1.0", description="Evidence-aware AWS identity analysis. Offline records are synthetic. Supported IAM subset only.")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8080").split(","), allow_credentials=False, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    FastAPIInstrumentor.instrument_app(app)
except ImportError:
    pass
PREFIX = "/api/v1"
log = logging.getLogger("cloudpathx.api")
login_attempts: dict[str, deque[float]] = defaultdict(deque)

@app.middleware("http")
async def limits_and_headers(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and (not length.isdigit() or int(length) > 5_000_000):
        return Response("Request body exceeds 5 MB", status_code=413)
    # Bound chunked as well as Content-Length bodies, before JSON parsing.
    if request.method in {"POST", "PATCH", "PUT"}:
        chunks = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 5_000_000:
                return Response("Request body exceeds 5 MB", status_code=413)
            chunks.append(chunk)
        request._body = b"".join(chunks)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")

class Login(Input):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)

class UserCreate(Login):
    password: str = Field(min_length=12, max_length=1024)
    role: Literal["Administrator", "Security Analyst", "Viewer"] = "Viewer"

class AccountInput(Input):
    name: str = Field(min_length=1, max_length=100)
    profile: str | None = Field(default=None, max_length=100, pattern=r"^[\w.-]+$")
    role_arn: str | None = Field(default=None, max_length=2048, pattern=r"^arn:aws[a-z-]*:iam::[0-9]{12}:role/[\w+=,.@/-]+$")
    region: str = Field(default="us-east-1", pattern=r"^[a-z]{2}(-[a-z]+)+-[0-9]+$")
    expected_account_id: str = Field(pattern=r"^[0-9]{12}$")

class ScanInput(Input):
    mode: Literal["demo", "aws"] = "demo"
    account_id: str | None = None

class PolicyInput(Input):
    policy: dict
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(min_length=1, max_length=2048)
    context: dict = Field(default_factory=dict)

class SimulationInput(Input):
    identity_id: str
    policy: dict

class FindingUpdate(Input):
    status: Literal["Open", "Investigating", "Mitigated", "Accepted Risk", "False Positive"]
    assignee: str | None = Field(default=None, max_length=254)
    note: str | None = Field(default=None, max_length=5000)

class IncidentInput(Input):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    finding_ids: list[str] = Field(default_factory=list, max_length=100)

class IncidentUpdate(Input):
    status: Literal["Open", "Investigating", "Mitigated", "Accepted Risk", "False Positive"] | None = None
    note: str | None = Field(default=None, max_length=5000)

class EventImport(Input):
    Records: list[dict] = Field(max_length=5000)

    @field_validator("Records")
    @classmethod
    def validate_events(cls, events):
        for event in events:
            if not all(isinstance(event.get(k), str) and event[k] for k in ("eventName", "eventTime", "eventSource")):
                raise ValueError("Every event requires eventName, eventTime and eventSource strings")
        return events

class SettingsInput(Input):
    scan_interval_minutes: int = Field(default=0, ge=0, le=10080)
    retention_days: int = Field(default=90, ge=1, le=3650)
    notifications_enabled: bool = True


def public_user(user):
    return {"id": user.id, "email": user.email, "role": user.role}

@app.get(PREFIX + "/health")
def health():
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected", "version": "0.1.0"}

@app.post(PREFIX + "/auth/login")
def login(body: Login, request: Request):
    ip = request.client.host if request.client else "unknown"
    queue = login_attempts[ip]
    cutoff = time.monotonic() - 60
    while queue and queue[0] < cutoff:
        queue.popleft()
    if len(queue) >= 10:
        raise HTTPException(429, "Too many attempts; try again in one minute")
    queue.append(time.monotonic())
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == body.email.lower().strip()))
        valid = verify_password(body.password, user.password_hash if user else "scrypt$" + "00" * 16 + "$" + "00" * 64)
        if not user or not valid:
            audit(db, None, "auth.login_failed", "session")
            db.commit()
            raise HTTPException(401, "Invalid email or password")
        token = issue_session(db, user)
        audit(db, user, "auth.login", user.id)
        db.commit()
        return {"token": token, "expires_in": 3600, "user": public_user(user)}

@app.get(PREFIX + "/auth/me")
def me(user=Depends(current_user)):
    return public_user(user)

@app.post(PREFIX + "/auth/logout")
def logout(user=Depends(current_user), credentials=Depends(bearer)):
    with SessionLocal() as db:
        db.execute(delete(Session).where(Session.token_hash == digest_token(credentials.credentials)))
        audit(db, user, "auth.logout", user.id)
        db.commit()
    return {"ok": True}

@app.post(PREFIX + "/users", status_code=201)
def create_user(body: UserCreate, user=Depends(admin)):
    with SessionLocal() as db:
        email = body.email.lower().strip()
        if db.scalar(select(User).where(User.email == email)):
            raise HTTPException(409, "Email already exists")
        new = User(email=email, password_hash=password_hash(body.password), role=body.role)
        db.add(new)
        db.flush()
        audit(db, user, "user.create", new.id, {"role": new.role})
        db.commit()
        return public_user(new)

@app.get(PREFIX + "/users")
def users(user=Depends(admin), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with SessionLocal() as db:
        items = [public_user(u) for u in db.scalars(select(User).order_by(User.email))]
        return {"items": items[offset:offset + limit], "total": len(items)}

@app.post(PREFIX + "/accounts", status_code=201)
def create_account(body: AccountInput, user=Depends(admin)):
    with SessionLocal() as db:
        item = upsert(db, "accounts", {"id": uid(), **body.model_dump(), "synthetic": False, "status": "Not scanned"})
        audit(db, user, "account.create", item["id"])
        db.commit()
        return item

@app.post(PREFIX + "/scans", status_code=202)
def create_scan(body: ScanInput, user=Depends(analyst)):
    with SessionLocal() as db:
        if body.mode == "aws" and not db.get(MODELS["accounts"], body.account_id or ""):
            raise HTTPException(422, "Select a configured AWS account")
        pending = db.scalar(select(Scan).where(Scan.status.in_(["queued", "running"]), Scan.mode == body.mode, Scan.account_id == body.account_id))
        if pending:
            return scan_json(pending)
        scan = Scan(mode=body.mode, account_id=body.account_id)
        db.add(scan)
        db.flush()
        audit(db, user, "scan.queue", scan.id, {"mode": body.mode})
        db.commit()
        return scan_json(scan)

@app.get(PREFIX + "/scans")
def scans(user=Depends(current_user), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with SessionLocal() as db:
        items = [scan_json(s) for s in db.scalars(select(Scan).order_by(Scan.created_at.desc()))]
        return {"items": items[offset:offset + limit], "total": len(items)}

@app.get(PREFIX + "/scans/{scan_id}/stream")
def scan_stream(scan_id: str, user=Depends(current_user)):
    with SessionLocal() as db:
        if not db.get(Scan, scan_id):
            raise HTTPException(404, "Scan not found")
    async def stream():
        for _ in range(120):
            with SessionLocal() as db:
                scan = db.get(Scan, scan_id)
                if scan is None:
                    break
                yield "data: " + json.dumps(scan_json(scan)) + "\n\n"
                if scan.status in {"completed", "partial", "failed"}:
                    break
            await asyncio.sleep(1)
    return StreamingResponse(stream(), media_type="text/event-stream")

@app.get(PREFIX + "/graph")
def graph(user=Depends(current_user)):
    with SessionLocal() as db:
        scans = active_scans(db)
        return {"nodes": [n for s in scans for n in s.result.get("nodes", [])], "edges": [e for s in scans for e in s.result.get("edges", [])], "scan_ids": [s.id for s in scans]}

@app.get(PREFIX + "/analytics")
def analytics(user=Depends(current_user)):
    with SessionLocal() as db:
        ids = records(db, "identities")
        findings = records(db, "findings")
        history = list(db.scalars(select(Scan).where(Scan.status.in_(["completed", "partial"])).order_by(Scan.created_at)))
        latest = history[-1] if history else None
        current_findings = latest.result.get("findings", []) if latest else []
        high_ids = {f.get("identity_id") for f in current_findings if f.get("score", 0) >= 70}
        return {"accounts": len(records(db, "accounts")), "identities": len(ids), "non_human_identities": sum(i.get("type", "").lower() not in {"user", "iam_user", "human"} for i in ids), "high_risk_identities": len(high_ids - {None}), "resources": len(records(db, "resources")), "exposed_resources": len({p.get("target") or p.get("target_resource") for p in (latest.result.get("paths", []) if latest else [])}), "attack_paths": len(latest.result.get("paths", [])) if latest else 0, "critical_findings": sum(f.get("severity", "").lower() == "critical" and f.get("status", "Open") not in {"Mitigated", "False Positive"} for f in findings), "alerts": len(records(db, "alerts")), "scans": len(history), "scan_health": latest.status if latest else "No scans", "synthetic": bool(latest and latest.mode == "demo"), "trend": [{"date": s.created_at.isoformat(), "score": max((f.get("score", 0) for f in s.result.get("findings", [])), default=0)} for s in history[-30:]], "latest_scan": scan_json(latest) if latest else None}

@app.post(PREFIX + "/policies/analyze")
def policy_analyze(body: PolicyInput, user=Depends(analyst)):
    from .engine import evaluate
    try:
        result = evaluate(body.policy, body.action, body.resource, body.context)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, "Invalid or unsupported policy structure") from exc
    with SessionLocal() as db:
        audit(db, user, "policy.analyze", "inline", {"action": body.action})
        db.commit()
    return result

@app.post(PREFIX + "/events/import")
def event_import(body: EventImport, user=Depends(analyst)):
    from .engine import analyze, detect_events
    with SessionLocal() as db:
        for event in body.Records:
            upsert(db, "events", event)
        db.flush()
        all_events = records(db, "events")
        alerts = detect_events(all_events)
        correlated = []
        for scan in active_scans(db):
            dataset = copy.deepcopy(scan.dataset)
            dataset["events"] = all_events
            correlated.append(analyze(dataset))
        for alert in alerts:
            principal = alert.get("identity_id")
            related_findings = [f for result in correlated for f in result.get("findings", []) if f.get("identity_id") == principal]
            related_paths = [p for result in correlated for p in result.get("paths", []) if principal in p.get("nodes", []) or p.get("start") == principal]
            alert["related_finding_ids"] = [f["id"] for f in related_findings]
            alert["related_path_ids"] = [p["id"] for p in related_paths]
            alert["correlated_risk"] = max((f.get("score", 0) for f in related_findings), default=0)
            alert["correlation_scope"] = "Current inventory with imported event evidence; scan snapshots remain immutable"
            upsert(db, "alerts", alert)
            rule = alert.get("rule", "unknown")
            upsert(db, "rules", {"id": rule, "name": rule, "technique": alert.get("mitre_technique")})
        audit(db, user, "events.import", "cloudtrail", {"count": len(body.Records)})
        db.commit()
        return {"imported": len(body.Records), "alerts": alerts, "total_alerts": len(alerts)}

@app.patch(PREFIX + "/findings/{finding_id:path}")
def update_finding(finding_id: str, body: FindingUpdate, user=Depends(analyst)):
    with SessionLocal() as db:
        row = db.get(MODELS["findings"], finding_id)
        if not row:
            raise HTTPException(404, "Finding not found")
        data = {**row.data, **body.model_dump(exclude={"note"}, exclude_unset=True)}
        if body.note:
            data["notes"] = [*data.get("notes", []), {"text": body.note, "author": user.email, "at": now().isoformat()}]
        row.data = data
        row.updated_at = now()
        audit(db, user, "finding.update", finding_id, body.model_dump(exclude_none=True))
        db.commit()
        return data

@app.post(PREFIX + "/incidents", status_code=201)
def create_incident(body: IncidentInput, user=Depends(analyst)):
    with SessionLocal() as db:
        if any(db.get(MODELS["findings"], fid) is None for fid in body.finding_ids):
            raise HTTPException(422, "Unknown finding reference")
        item = upsert(db, "incidents", {"id": uid(), **body.model_dump(), "status": "Open", "notes": [], "created_by": user.email, "created_at": now().isoformat()})
        audit(db, user, "incident.create", item["id"])
        db.commit()
        return item

@app.patch(PREFIX + "/incidents/{incident_id}")
def update_incident(incident_id: str, body: IncidentUpdate, user=Depends(analyst)):
    with SessionLocal() as db:
        row = db.get(MODELS["incidents"], incident_id)
        if not row:
            raise HTTPException(404, "Incident not found")
        data = dict(row.data)
        if body.status:
            data["status"] = body.status
        if body.note:
            data["notes"] = [*data.get("notes", []), {"text": body.note, "author": user.email, "at": now().isoformat()}]
        row.data = data
        row.updated_at = now()
        audit(db, user, "incident.update", incident_id, body.model_dump(exclude_none=True))
        db.commit()
        return data

@app.post(PREFIX + "/remediation")
def remediation(body: SimulationInput, user=Depends(analyst)):
    from .engine import analyze, evaluate
    try:
        evaluate(body.policy, "s3:GetObject", "*")
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, "Invalid policy") from exc
    with SessionLocal() as db:
        scan = latest_scan(db)
        if not scan:
            raise HTTPException(409, "Run a scan first")
        dataset = copy.deepcopy(scan.dataset)
        identity = next((i for i in dataset.get("identities", []) if i["id"] == body.identity_id), None)
        if identity is None:
            raise HTTPException(404, "Identity not in latest scan")
        original = identity.get("policies", [])
        identity["policies"] = [body.policy]
        result = analyze(dataset)
        before_paths = scan.result.get("paths", [])
        after_paths = result.get("paths", [])
        before_score = max((f.get("score", 0) for f in scan.result.get("findings", [])), default=0)
        after_score = max((f.get("score", 0) for f in result.get("findings", [])), default=0)
        item = {"id": uid(), "identity_id": body.identity_id, "scan_id": scan.id, "before": {"paths": before_paths, "risk": before_score}, "after": {"paths": after_paths, "risk": after_score}, "before_paths": before_paths, "after_paths": after_paths, "original_risk": before_score, "proposed_risk": after_score, "original_policy": original, "proposed_policy": body.policy, "removed_paths": len(before_paths) - len(after_paths), "remaining_risks": result.get("findings", []), "access_impact": "All identity-attached policies replaced in this hypothetical copy; legitimate access can be lost.", "limitations": ["Supported policy subset only", "No AWS configuration was changed", "Unknown organization, session and resource controls remain unresolved"], "created_at": now().isoformat()}
        upsert(db, "remediation", item, scan.id)
        audit(db, user, "remediation.simulate", item["id"], {"identity_id": body.identity_id})
        db.commit()
        return item

@app.get(PREFIX + "/settings")
def get_settings(user=Depends(current_user)):
    with SessionLocal() as db:
        return settings(db)

@app.patch(PREFIX + "/settings")
def update_settings(body: SettingsInput, user=Depends(admin)):
    with SessionLocal() as db:
        item = {**settings(db), **body.model_dump(), "id": "global"}
        upsert(db, "settings", item)
        audit(db, user, "settings.update", "global", body.model_dump())
        db.commit()
        return item

@app.get(PREFIX + "/audit")
def audit_log(user=Depends(admin), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with SessionLocal() as db:
        rows = list(db.scalars(select(Audit).order_by(Audit.created_at.desc())))
        return {"items": [{"id": r.id, "actor_id": r.actor_id, "action": r.action, "target": r.target, "detail": r.detail, "created_at": r.created_at.isoformat()} for r in rows[offset:offset + limit]], "total": len(rows)}

@app.get(PREFIX + "/reports")
def report(format: Literal["json", "pdf"] = "json", user=Depends(current_user)):
    with SessionLocal() as db:
        scan = latest_scan(db)
        data = {"generated_at": now().isoformat(), "synthetic": bool(scan and scan.mode == "demo"), "scan": scan_json(scan) if scan else None, "findings": records(db, "findings"), "paths": scan.result.get("paths", []) if scan else [], "alerts": records(db, "alerts"), "limitations": ["Passive analysis; potential paths are not proof of exploitation", "Only supported IAM semantics evaluated; see IAM_ANALYSIS.md"]}
        audit(db, user, "report.export", format)
        db.commit()
    if format == "json":
        return Response(json.dumps(data, indent=2, default=str), media_type="application/json", headers={"Content-Disposition": 'attachment; filename="cloudpathx-report.json"'})
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, title="CloudPathX Security Report", leftMargin=48, rightMargin=48)
    styles = getSampleStyleSheet()
    styles["Title"].textColor = colors.HexColor("#16324f")
    story = [Paragraph("CloudPathX Security Report", styles["Title"]), Paragraph("SYNTHETIC DEMONSTRATION DATA" if data["synthetic"] else "Passive security analysis", styles["Heading2"]), Paragraph(escape(data["generated_at"]), styles["Normal"]), Spacer(1, 16)]
    for item in data["findings"]:
        story.extend([Paragraph(escape(str(item.get("title", "Finding"))), styles["Heading2"]), Paragraph(escape(f'Severity: {item.get("severity")} | Score: {item.get("score")} | Confidence: {item.get("confidence")}'), styles["Normal"]), Paragraph(escape(str(item.get("remediation", "Review supporting evidence"))), styles["Normal"]), Paragraph(escape(json.dumps(item.get("evidence", []), default=str)), styles["Code"]), Spacer(1, 12)])
    story.append(Paragraph("Limitations", styles["Heading2"]))
    story.extend(Paragraph(escape(item), styles["Normal"]) for item in data["limitations"])
    doc.build(story)
    return Response(buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": 'attachment; filename="cloudpathx-report.pdf"'})

# Read-only collection endpoints share bounded pagination and text filtering.
def collection(kind):
    def handler(q: str = Query("", max_length=200), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), user=Depends(current_user)):
        with SessionLocal() as db:
            if kind == "attack-paths":
                items = [p for s in active_scans(db) for p in s.result.get("paths", [])]
            else:
                items = records(db, kind)
            if q:
                items = [i for i in items if q.lower() in json.dumps(i, default=str).lower()]
            return {"items": items[offset:offset + limit], "total": len(items)}
    handler.__name__ = f"list_{kind.replace('-', '_')}"
    return handler

for kind in ("accounts", "identities", "policies", "resources", "findings", "events", "alerts", "incidents", "attack-paths"):
    app.get(PREFIX + "/" + kind)(collection(kind))
