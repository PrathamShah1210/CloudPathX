import hashlib
import json
from sqlalchemy import select
from .db import Audit, MODELS, Scan, now

STATUSES = {"Open", "Investigating", "Mitigated", "Accepted Risk", "False Positive"}
DEFAULT_SETTINGS = {"scan_interval_minutes": 0, "retention_days": 90, "notifications_enabled": True, "scoring": {"method": "Evidence-aware v1", "custom_weights_supported": False}}

def audit(db, user, action, target, detail=None):
    db.add(Audit(actor_id=getattr(user, "id", None), action=action, target=str(target), detail=detail or {}))

def upsert(db, kind, data, scan_id=None):
    item = dict(data)
    key = str(item.get("id") or item.get("eventID") or hashlib.sha256(json.dumps(item, sort_keys=True, default=str).encode()).hexdigest()[:32])
    item["id"] = key
    model = MODELS[kind]
    existing = db.get(model, key)
    if existing:
        # Analyst disposition survives repeat scans; source evidence refreshes.
        if kind == "findings":
            for field in ("status", "assignee", "notes"):
                if field in existing.data:
                    item[field] = existing.data[field]
        existing.data = item
        existing.updated_at = now()
        existing.scan_id = scan_id or existing.scan_id
    else:
        db.add(model(id=key, data=item, scan_id=scan_id))
    return item

def active_scans(db):
    latest: dict[tuple[str, str | None], Scan] = {}
    for scan in db.scalars(select(Scan).where(Scan.status.in_(["completed", "partial"])).order_by(Scan.created_at.desc())):
        latest.setdefault((scan.mode, scan.account_id), scan)
    return list(latest.values())

def records(db, kind):
    query = select(MODELS[kind]).order_by(MODELS[kind].created_at.desc())
    if kind in {"identities", "resources", "policies", "nodes", "edges", "findings", "attack-paths", "risk_assessments"}:
        query = query.where(MODELS[kind].scan_id.in_([s.id for s in active_scans(db)]))
    items = [dict(row.data, id=row.id, scan_id=row.scan_id) for row in db.scalars(query)]
    if kind == "accounts":
        configured = {item.get("expected_account_id") for item in items if item.get("expected_account_id")}
        items = [item for item in items if item.get("expected_account_id") or item["id"] not in configured]
    return items

def latest_scan(db):
    return db.scalar(select(Scan).where(Scan.status.in_(["completed", "partial"])).order_by(Scan.created_at.desc()).limit(1))

def settings(db):
    row = db.get(MODELS["settings"], "global")
    return {**DEFAULT_SETTINGS, **(row.data if row else {})}

def scan_json(scan):
    return {"id": scan.id, "mode": scan.mode, "account_id": scan.account_id, "status": scan.status, "created_at": scan.created_at.isoformat(), "updated_at": scan.updated_at.isoformat(), "errors": scan.errors, "summary": scan.result.get("summary", {}), "comparison": scan.result.get("comparison", {})}
