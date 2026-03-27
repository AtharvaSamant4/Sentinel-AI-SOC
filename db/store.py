"""
db/store.py
-----------
Fire-and-forget write helpers called from the hot path (intelligence and
response layers).  Every function:

  * opens its own short-lived session
  * commits and closes in one shot
  * catches all exceptions and logs them — a DB write failure must NEVER
    crash the detection/response pipeline

Read helpers for the API endpoints are also here, returning plain dicts so
callers have no SQLAlchemy dependency.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from db.session import SessionLocal
from db.models import AuditLog, BlockedIP, Event, Threat

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def save_event(event: dict[str, Any]) -> None:
    """Persist a raw security event.  Silent on failure."""
    try:
        with _session() as db:
            row = Event(
                timestamp=str(event.get("timestamp") or ""),
                source_ip=str(event.get("source_ip") or "0.0.0.0"),
                destination_ip=str(event.get("destination_ip") or "unknown"),
                destination_port=int(event.get("destination_port") or 0),
                event_type=str(event.get("event_type") or "connection"),
                protocol=str(event.get("protocol") or "TCP"),
                status=str(event.get("status") or "unknown"),
                country=str(event.get("country") or "XX"),
                is_attack=bool(event.get("is_attack", False)),
                raw_data=_safe_json(event),
            )
            db.add(row)
    except Exception:
        logger.exception("[db] save_event failed")


def save_threat(threat: dict[str, Any]) -> None:
    """Persist an enriched threat object.  Silent on failure."""
    try:
        mitre = threat.get("mitre") or {}
        actor = threat.get("threat_actor") or {}
        actor_name = str(actor.get("name", "")) if isinstance(actor, dict) else ""

        with _session() as db:
            row = Threat(
                timestamp=str(threat.get("timestamp") or ""),
                source_ip=str(threat.get("source_ip") or "unknown"),
                destination_ip=str(threat.get("destination_ip") or "unknown"),
                destination_port=int(threat.get("destination_port") or 0),
                attack_type=str(threat.get("attack_type") or "UNKNOWN"),
                anomaly_score=float(threat.get("anomaly_score") or 0.0),
                risk_score=int(threat.get("risk_score") or 0),
                severity=str(threat.get("severity") or "LOW"),
                mitre_technique=str(mitre.get("technique_id", "") if isinstance(mitre, dict) else ""),
                mitre_tactic=str(mitre.get("tactic", "") if isinstance(mitre, dict) else ""),
                description=str(threat.get("reason") or ""),
                country=str(threat.get("country") or "XX"),
                threat_actor=actor_name,
            )
            db.add(row)
    except Exception:
        logger.exception("[db] save_threat failed")


def save_blocked_ip(ip: str, reason: str = "") -> None:
    """Persist a blocked IP so it survives server restarts. Silent on failure."""
    try:
        with _session() as db:
            existing = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
            if existing is None:
                db.add(BlockedIP(ip=ip, reason=reason))
    except Exception:
        logger.exception("[db] save_blocked_ip failed")


def load_blocked_ips() -> set[str]:
    """Return all currently blocked IPs from the database."""
    try:
        with _session() as db:
            rows = db.query(BlockedIP.ip).all()
            return {row.ip for row in rows}
    except Exception:
        logger.exception("[db] load_blocked_ips failed")
        return set()


def delete_blocked_ip(ip: str) -> None:
    """Remove a blocked IP from the database (used by rollback). Silent on failure."""
    try:
        with _session() as db:
            db.query(BlockedIP).filter(BlockedIP.ip == ip).delete()
    except Exception:
        logger.exception("[db] delete_blocked_ip failed")


def save_audit_entry(entry: dict[str, Any]) -> None:
    """Persist a response/operator audit log entry.  Silent on failure."""
    try:
        with _session() as db:
            row = AuditLog(
                timestamp=str(entry.get("timestamp") or ""),
                action=str(entry.get("action") or "unknown"),
                target=str(entry.get("target") or "unknown"),
                trigger_reason=str(entry.get("trigger") or entry.get("trigger_reason") or ""),
                status=str(entry.get("status") or "unknown"),
                operator=str(entry.get("operator") or "system"),
                action_id=str(entry.get("action_id") or ""),
            )
            db.add(row)
    except Exception:
        logger.exception("[db] save_audit_entry failed")


# ---------------------------------------------------------------------------
# Read helpers (return plain dicts — no SQLAlchemy objects escape this module)
# ---------------------------------------------------------------------------

def query_threats(limit: int = 20, severity: str | None = None) -> list[dict[str, Any]]:
    """
    Return the most recent threats, newest first.
    Optionally filter by severity ('HIGH', 'CRITICAL', etc.).
    """
    try:
        with _session() as db:
            q = db.query(Threat).order_by(Threat.id.desc())
            if severity:
                q = q.filter(Threat.severity == severity.upper())
            rows = q.limit(limit).all()
            return [r.to_dict() for r in rows]
    except Exception:
        logger.exception("[db] query_threats failed")
        return []


def query_audit_log(limit: int = 50) -> list[dict[str, Any]]:
    """Return the most recent audit log entries, newest first."""
    try:
        with _session() as db:
            rows = (
                db.query(AuditLog)
                .order_by(AuditLog.id.desc())
                .limit(limit)
                .all()
            )
            return [r.to_dict() for r in rows]
    except Exception:
        logger.exception("[db] query_audit_log failed")
        return []


def query_events(limit: int = 100) -> list[dict[str, Any]]:
    """Return the most recent events, newest first."""
    try:
        with _session() as db:
            rows = (
                db.query(Event)
                .order_by(Event.id.desc())
                .limit(limit)
                .all()
            )
            return [r.to_dict() for r in rows]
    except Exception:
        logger.exception("[db] query_events failed")
        return []


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

class _session:
    """Minimal context manager: open → commit → close, rollback on error."""

    def __init__(self) -> None:
        self._db = SessionLocal()

    def __enter__(self):
        return self._db

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self._db.commit()
        else:
            self._db.rollback()
        self._db.close()
        return False  # never suppress exceptions


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return "{}"
