"""Durable queue worker. PostgreSQL row locks prevent duplicate claims."""
import logging
import time
from datetime import timedelta
from sqlalchemy import delete, select
from .db import MODELS, Scan, Session, SessionLocal, now
from .store import records, settings, upsert

log = logging.getLogger("cloudpathx.worker")

def process_scan(scan_id):
    from .engine import analyze, demo_dataset
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        mode, account_id = scan.mode, scan.account_id
    try:
        if mode == "demo":
            dataset = demo_dataset()
        else:
            from .aws import collect
            with SessionLocal() as db:
                account = db.get(MODELS["accounts"], account_id)
                if not account:
                    raise ValueError("Configured account is missing")
                config = account.data
            dataset = collect(**{k: config[k] for k in ("profile", "role_arn", "region", "expected_account_id") if config.get(k)})
        result = analyze(dataset)
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            assert scan is not None
            previous = db.scalar(select(Scan).where(Scan.status.in_(["completed", "partial"]), Scan.mode == mode, Scan.account_id == account_id).order_by(Scan.created_at.desc()).limit(1))
            old = {f["id"] for f in previous.result.get("findings", [])} if previous else set()
            new = {f["id"] for f in result.get("findings", [])}
            result["comparison"] = {"new_findings": len(new - old), "no_longer_observed": len(old - new), "previous_scan_id": previous.id if previous else None}
            scan.dataset = dataset
            scan.result = result
            scan.errors = dataset.get("errors", [])
            scan.status = "partial" if scan.errors else "completed"
            scan.updated_at = now()
            for kind in ("accounts", "identities", "resources", "events"):
                for item in result.get(kind, dataset.get(kind, [])):
                    upsert(db, kind, item, scan.id)
            for kind, key in (("nodes", "nodes"), ("edges", "edges"), ("attack-paths", "paths"), ("findings", "findings"), ("alerts", "alerts")):
                for item in result.get(key, []):
                    if kind == "findings":
                        item = {"status": "Open", **item}
                    upsert(db, kind, item, scan.id)
            for identity in dataset.get("identities", []):
                for index, policy in enumerate(identity.get("policies", [])):
                    pid = f'{identity["id"]}:policy:{index}'
                    upsert(db, "policies", {"id": pid, "name": f'{identity.get("name", identity["id"])} / Policy {index + 1}', "identity_id": identity["id"], "policy": policy}, scan.id)
                    upsert(db, "policy_versions", {"id": f"{pid}:{scan.id}", "policy_id": pid, "policy": policy}, scan.id)
                if identity.get("trust_policy"):
                    upsert(db, "trust_relationships", {"id": identity["id"], "identity_id": identity["id"], "policy": identity["trust_policy"]}, scan.id)
            for finding in result.get("findings", []):
                upsert(db, "risk_assessments", {"id": finding["id"], "finding_id": finding["id"], "score": finding.get("score"), "confidence": finding.get("confidence"), "explanation": finding.get("explanation")}, scan.id)
                for index, evidence in enumerate(finding.get("evidence", [])):
                    upsert(db, "evidence", {"id": f'{scan.id}:{finding["id"]}:{index}', "finding_id": finding["id"], "source": evidence}, scan.id)
            for alert in result.get("alerts", []):
                rule = alert.get("rule_id") or alert.get("rule") or alert.get("title", "Unknown detection")
                upsert(db, "rules", {"id": str(rule), "name": str(rule), "source": "deterministic_engine", "technique": alert.get("mitre_technique")})
            for index, error in enumerate(scan.errors):
                upsert(db, "scan_errors", {"id": f"{scan.id}:{index}", "error": error}, scan.id)
            db.commit()
    except Exception as exc:
        log.error("scan_failed", extra={"scan_id": scan_id, "error_type": type(exc).__name__})
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.errors = [{"code": type(exc).__name__, "message": "Scan failed; check configuration and worker logs. Credentials are never included."}]
                scan.updated_at = now()
                db.commit()

def tick():
    with SessionLocal() as db:
        # A worker that died during a scan leaves a visible failed scan after its lease.
        stale = db.scalars(select(Scan).where(Scan.status == "running", Scan.updated_at < now() - timedelta(minutes=30)))
        for stale_scan in stale:
            stale_scan.status = "failed"
            stale_scan.errors = [{"code": "WorkerLeaseExpired", "message": "Worker stopped or exceeded 30 minute scan lease; rescan manually."}]
        scan = db.scalar(select(Scan).where(Scan.status == "queued").order_by(Scan.created_at).with_for_update(skip_locked=True).limit(1))
        scan_id = None
        if scan:
            scan.status = "running"
            scan.updated_at = now()
            scan_id = scan.id
        db.commit()
    if scan_id:
        process_scan(scan_id)
    return bool(scan_id)

def maintenance():
    with SessionLocal() as db:
        config = settings(db)
        db.execute(delete(Session).where(Session.expires_at < now()))
        interval = config.get("scan_interval_minutes", 0)
        if interval:
            for account in records(db, "accounts"):
                if account.get("synthetic") or not account.get("expected_account_id"):
                    continue
                latest = db.scalar(select(Scan).where(Scan.account_id == account["id"]).order_by(Scan.created_at.desc()).limit(1))
                if latest is None or (latest.status not in {"queued", "running"} and latest.created_at.replace(tzinfo=now().tzinfo) < now() - timedelta(minutes=interval)):
                    db.add(Scan(mode="aws", account_id=account["id"]))
        # Preserve findings and audit history; prune old raw CloudTrail records only.
        cutoff = now() - timedelta(days=config["retention_days"])
        db.execute(delete(MODELS["events"]).where(MODELS["events"].created_at < cutoff))
        db.commit()

def main():
    logging.basicConfig(level=logging.INFO, format='{"level":"%(levelname)s","event":"%(message)s"}')
    last = 0.0
    while True:
        try:
            if time.monotonic() - last > 60:
                maintenance()
                last = time.monotonic()
            if not tick():
                time.sleep(1)
        except Exception as exc:
            log.error("worker_retry_%s", type(exc).__name__)
            time.sleep(5)

if __name__ == "__main__":
    main()
