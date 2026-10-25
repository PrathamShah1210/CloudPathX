"""Explicit local administration; no publicly known bootstrap credentials."""
import argparse
import getpass
import os
from sqlalchemy import select
from .db import Scan, SessionLocal, User
from .security import password_hash
from .store import audit, upsert

def main():
    parser = argparse.ArgumentParser(description="CloudPathX local administration")
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap")
    bootstrap.add_argument("--email", required=True)
    commands.add_parser("demo")
    args = parser.parse_args()
    with SessionLocal() as db:
        if args.command == "bootstrap":
            email = args.email.strip().lower()
            if "@" not in email or len(email) > 254:
                parser.error("Provide a valid email")
            if db.scalar(select(User).where(User.email == email)):
                parser.error("User already exists; bootstrap never resets existing accounts")
            password = os.getenv("CLOUDPATHX_ADMIN_PASSWORD") or getpass.getpass("New administrator password (12+ characters): ")
            if len(password) < 12:
                parser.error("Password must contain at least 12 characters")
            user = User(email=email, password_hash=password_hash(password), role="Administrator")
            db.add(user)
            db.flush()
            for role in ("Administrator", "Security Analyst", "Viewer"):
                upsert(db, "roles", {"id": role, "name": role})
            audit(db, user, "user.bootstrap", user.id)
            db.commit()
            print("Administrator created. Sign in at the frontend; sessions expire after one hour.")
        else:
            existing = db.scalar(select(Scan).where(Scan.mode == "demo", Scan.status.in_(["queued", "running", "completed", "partial"])))
            if existing:
                print(f"Demo already present: {existing.id} ({existing.status})")
            else:
                scan = Scan(mode="demo")
                db.add(scan)
                db.commit()
                print(f"Queued synthetic demo scan: {scan.id}. Start python -m app.worker to process it.")

if __name__ == "__main__":
    main()
