"""
response/operator.py
--------------------
Human-in-the-loop operator control layer.

Responsibilities
----------------
* Decide whether a threat should be auto-executed, held for approval, or
  only logged (based on severity).
* Maintain an in-memory store of PENDING threats that are awaiting human
  decision.
* Expose approve() / reject() operations that record the decision and,
  on approval, execute the response actions.
* Manage a global override mode that disables all autonomous responses.
* Log every human decision to the shared audit_log.

Decision matrix
---------------
  CRITICAL  → auto_execute immediately (unless override_mode is True)
  HIGH      → auto_execute immediately (unless override_mode is True)
  MEDIUM    → log only (no action)
  LOW/other → no action

Override mode
-------------
  When override_mode = True every severity level is treated as PENDING.
  No automated actions fire.  Operators must manually approve every threat.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from itertools import count
from typing import Any

from response.actions import audit_log, execute_action

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

# Whether autonomous responses are disabled globally.
override_mode: bool = False
_override_lock = threading.Lock()

# In-memory store: threat_id → PendingThreat record.
_pending_store: dict[str, dict[str, Any]] = {}
_store_lock = threading.Lock()

_threat_counter = count(1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def set_override_mode(enabled: bool) -> None:
    """Enable or disable global override mode (thread-safe)."""
    global override_mode
    with _override_lock:
        override_mode = enabled
    state = "ENABLED" if enabled else "DISABLED"
    logger.info("[operator] override mode %s", state)
    _append_audit(
        action="system_override",
        target="all_responses",
        trigger=f"operator set override_mode={enabled}",
        status=state,
        operator="system",
    )


def get_override_mode() -> bool:
    with _override_lock:
        return override_mode


def evaluate_threat(threat: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluate a threat and return a decision record.

    Returns a dict with:
        decision      – "auto_execute" | "pending_approval" | "log_only"
        threat_id     – str (set for pending_approval threats)
        severity      – str
        requires_approval – bool
    """
    severity = str(threat.get("severity", "LOW")).upper()

    with _override_lock:
        _override = override_mode

    if _override:
        # All automated responses suppressed — hold everything as PENDING.
        threat_id = _store_pending(threat, reason="override_mode_active")
        _escalate(threat, severity="ANY", channel="analyst")
        return {
            "decision": "pending_approval",
            "threat_id": threat_id,
            "severity": severity,
            "requires_approval": True,
            "reason": "override_mode_active",
        }

    if severity == "CRITICAL":
        _escalate(threat, severity="CRITICAL", channel="admin")
        return {
            "decision": "auto_execute",
            "threat_id": None,
            "severity": severity,
            "requires_approval": False,
        }

    if severity == "HIGH":
        _escalate(threat, severity="HIGH", channel="analyst")
        return {
            "decision": "auto_execute",
            "threat_id": None,
            "severity": severity,
            "requires_approval": False,
        }

    # MEDIUM / LOW / unknown → log only.
    _log_only(threat, severity)
    return {
        "decision": "log_only",
        "threat_id": None,
        "severity": severity,
        "requires_approval": False,
    }


def approve_threat(threat_id: str, operator: str = "analyst") -> dict[str, Any]:
    """
    Approve a PENDING threat.
    Executes the queued response actions and updates the record to EXECUTED.
    """
    with _store_lock:
        record = _pending_store.get(threat_id)

    if record is None:
        return {"status": "error", "reason": "threat_not_found", "threat_id": threat_id}

    if record["status"] != "PENDING":
        return {
            "status": "error",
            "reason": f"threat_already_{record['status'].lower()}",
            "threat_id": threat_id,
        }

    threat = record["threat"]
    actions_executed: list[dict[str, Any]] = []

    # Execute block_ip + create_ticket as the standard approval response.
    source_ip = str(threat.get("source_ip", "")).strip()
    if source_ip:
        actions_executed.append(
            execute_action("block_ip", threat, trigger=f"APPROVED by {operator}")
        )
    actions_executed.append(
        execute_action("create_ticket", threat, trigger=f"APPROVED by {operator}")
    )

    with _store_lock:
        record["status"] = "EXECUTED"
        record["decided_by"] = operator
        record["decided_at"] = _timestamp()
        record["actions_executed"] = actions_executed

    _append_audit(
        action="approve_threat",
        target=source_ip or "unknown",
        trigger=f"operator approval: {operator}",
        status="EXECUTED",
        operator=operator,
        threat_id=threat_id,
    )
    logger.info("[operator] threat %s APPROVED by %s", threat_id, operator)

    return {
        "status": "approved",
        "threat_id": threat_id,
        "actions_executed": actions_executed,
        "decided_by": operator,
        "decided_at": record["decided_at"],
    }


def reject_threat(threat_id: str, operator: str = "analyst") -> dict[str, Any]:
    """
    Reject a PENDING threat.
    No response actions are executed; record is updated to REJECTED.
    """
    with _store_lock:
        record = _pending_store.get(threat_id)

    if record is None:
        return {"status": "error", "reason": "threat_not_found", "threat_id": threat_id}

    if record["status"] != "PENDING":
        return {
            "status": "error",
            "reason": f"threat_already_{record['status'].lower()}",
            "threat_id": threat_id,
        }

    with _store_lock:
        record["status"] = "REJECTED"
        record["decided_by"] = operator
        record["decided_at"] = _timestamp()

    source_ip = str(record["threat"].get("source_ip", "unknown"))
    _append_audit(
        action="reject_threat",
        target=source_ip,
        trigger=f"operator rejection: {operator}",
        status="REJECTED",
        operator=operator,
        threat_id=threat_id,
    )
    logger.info("[operator] threat %s REJECTED by %s", threat_id, operator)

    return {
        "status": "rejected",
        "threat_id": threat_id,
        "decided_by": operator,
        "decided_at": record["decided_at"],
    }


def get_pending_threats() -> list[dict[str, Any]]:
    """Return all threats currently in PENDING status."""
    with _store_lock:
        return [
            _serialize_record(r)
            for r in _pending_store.values()
            if r["status"] == "PENDING"
        ]


def get_all_threats() -> list[dict[str, Any]]:
    """Return all operator-tracked threats regardless of status."""
    with _store_lock:
        return [_serialize_record(r) for r in _pending_store.values()]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _store_pending(threat: dict[str, Any], reason: str) -> str:
    threat_id = f"thr-{next(_threat_counter)}"
    record = {
        "threat_id": threat_id,
        "status": "PENDING",
        "threat": threat,
        "created_at": _timestamp(),
        "decided_by": None,
        "decided_at": None,
        "actions_executed": [],
        "reason": reason,
    }
    with _store_lock:
        _pending_store[threat_id] = record

    _append_audit(
        action="threat_pending",
        target=str(threat.get("source_ip", "unknown")),
        trigger=reason,
        status="PENDING",
        operator="system",
        threat_id=threat_id,
    )
    logger.info(
        "[operator] threat %s stored as PENDING (%s) source=%s severity=%s",
        threat_id,
        reason,
        threat.get("source_ip", "?"),
        threat.get("severity", "?"),
    )
    return threat_id


def _log_only(threat: dict[str, Any], severity: str) -> None:
    logger.info(
        "[operator] %s threat from %s — log only, no action",
        severity,
        threat.get("source_ip", "?"),
    )


def _escalate(threat: dict[str, Any], severity: str, channel: str) -> None:
    """Simulate escalation notification (logs; extend to real alerting as needed)."""
    source_ip = threat.get("source_ip", "unknown")
    attack_type = threat.get("attack_type", "UNKNOWN")
    risk_score = threat.get("risk_score", 0)

    if channel == "admin":
        logger.warning(
            "[operator] ESCALATION → ADMIN | %s | %s | risk=%s | source=%s",
            severity,
            attack_type,
            risk_score,
            source_ip,
        )
    else:
        logger.info(
            "[operator] ESCALATION → ANALYST | %s | %s | risk=%s | source=%s",
            severity,
            attack_type,
            risk_score,
            source_ip,
        )


def _append_audit(
    action: str,
    target: str,
    trigger: str,
    status: str,
    operator: str,
    threat_id: str | None = None,
) -> None:
    entry: dict[str, Any] = {
        "timestamp": _timestamp(),
        "action": action,
        "target": target,
        "trigger": trigger,
        "status": status,
        "operator": operator,
    }
    if threat_id is not None:
        entry["threat_id"] = threat_id
    audit_log.append(entry)


def _serialize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a safe, serialisable copy of a pending-store record."""
    threat = record.get("threat", {})
    return {
        "threat_id": record["threat_id"],
        "status": record["status"],
        "created_at": record["created_at"],
        "decided_by": record.get("decided_by"),
        "decided_at": record.get("decided_at"),
        "reason": record.get("reason", ""),
        "source_ip": str(threat.get("source_ip", "unknown")),
        "attack_type": str(threat.get("attack_type", "UNKNOWN")),
        "severity": str(threat.get("severity", "LOW")),
        "risk_score": float(threat.get("risk_score", 0) or 0),
        "actions_executed": record.get("actions_executed", []),
    }


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
