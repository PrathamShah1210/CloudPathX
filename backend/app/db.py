"""PostgreSQL persistence. SQLite is supported only by isolated unit tests."""
import os
from typing import Any
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

def now():
    return datetime.now(timezone.utc)

def uid():
    return str(uuid4())

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, pool_pre_ping=True, **({"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}))
SessionLocal = sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(30), default="Viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    mode: Mapped[str] = mapped_column(String(20))
    account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    dataset: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    errors: Mapped[list] = mapped_column(JSON, default=list)

class Audit(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    target: Mapped[str] = mapped_column(String(512))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)

class RecordMixin:
    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

# Dedicated tables preserve entity-level provenance while retaining AWS-native documents.
TABLES = {
    "accounts": "cloud_accounts", "identities": "cloud_identities", "policies": "iam_policies",
    "policy_versions": "policy_versions", "trust_relationships": "trust_relationships",
    "resources": "cloud_resources", "nodes": "graph_nodes", "edges": "graph_edges",
    "evidence": "graph_evidence", "attack-paths": "attack_paths", "findings": "security_findings",
    "risk_assessments": "risk_assessments", "events": "cloudtrail_events", "rules": "detection_rules",
    "alerts": "alerts", "incidents": "incidents", "remediation": "remediation_simulations",
    "settings": "platform_settings", "roles": "roles", "scan_errors": "scan_errors",
}
MODELS: dict[str, Any] = {key: type(table.title().replace("_", ""), (RecordMixin, Base), {"__tablename__": table}) for key, table in TABLES.items()}
Index("ix_findings_scan_created", MODELS["findings"].scan_id, MODELS["findings"].created_at)
