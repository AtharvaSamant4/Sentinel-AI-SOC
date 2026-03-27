"""
db/models.py
------------
SQLAlchemy ORM table definitions for SENTINEL AI-SOC.

Tables
------
  Event     – raw security events ingested into the pipeline
  Threat    – enriched threat objects produced by the intelligence layer
  AuditLog  – every automated and operator action taken by the response engine
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.session import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------

class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    country: Mapped[str] = mapped_column(String(8), nullable=False, default="XX")
    is_attack: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Serialised JSON of the full raw event dict for auditability.
    raw_data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(
        String(64), nullable=False, default=lambda: _utcnow().isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "event_type": self.event_type,
            "protocol": self.protocol,
            "status": self.status,
            "country": self.country,
            "is_attack": self.is_attack,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Threat
# ---------------------------------------------------------------------------

class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False, default="unknown")
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW", index=True)
    mitre_technique: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    mitre_tactic: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    country: Mapped[str] = mapped_column(String(8), nullable=False, default="XX")
    threat_actor: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    created_at: Mapped[str] = mapped_column(
        String(64), nullable=False, default=lambda: _utcnow().isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "attack_type": self.attack_type,
            "anomaly_score": self.anomaly_score,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "description": self.description,
            "country": self.country,
            "threat_actor": self.threat_actor,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    trigger_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    operator: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    action_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[str] = mapped_column(
        String(64), nullable=False, default=lambda: _utcnow().isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "action": self.action,
            "target": self.target,
            "trigger_reason": self.trigger_reason,
            "status": self.status,
            "operator": self.operator,
            "action_id": self.action_id,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# BlockedIP  – persisted blocked IP list (survives server restarts)
# ---------------------------------------------------------------------------

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    reason: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    blocked_at: Mapped[str] = mapped_column(
        String(64), nullable=False, default=lambda: _utcnow().isoformat()
    )
