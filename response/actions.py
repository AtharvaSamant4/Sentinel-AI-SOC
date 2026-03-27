from __future__ import annotations

from datetime import datetime, timezone
from itertools import count
import json
import os
from pathlib import Path
from typing import Any

from db.store import delete_blocked_ip, load_blocked_ips, save_audit_entry, save_blocked_ip

_AUDIT_FILE = Path(__file__).resolve().parent.parent / "audit_log.json"

alerts: list[dict[str, Any]] = []
audit_log: list[dict[str, Any]] = []
action_history: dict[str, dict[str, Any]] = {}

# Load persisted blocked IPs from DB so restarts don't clear the block list.
try:
    blocked_ips: set[str] = load_blocked_ips()
    if blocked_ips:
        print(f"[actions] loaded {len(blocked_ips)} blocked IP(s) from DB: {blocked_ips}")
except Exception:
    blocked_ips = set()

flagged_ips: set[str] = set()
locked_accounts: set[str] = set()

_action_counter = count(1)


def normalize_ip(ip: str | None) -> str:
    return str(ip or "").strip().lower()


def is_ip_blocked(ip: str | None) -> bool:
    return normalize_ip(ip) in blocked_ips


def _target_asset_label(threat: dict[str, Any] | None) -> str:
    if not isinstance(threat, dict):
        return "unknown"

    destination_ip = str(threat.get("destination_ip", "unknown"))
    destination_port = int(threat.get("destination_port", 0) or 0)
    if destination_port > 0:
        return f"{destination_ip}:{destination_port}"
    return destination_ip


def block_ip(ip: str, trigger: str, threat: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized_ip = normalize_ip(ip)
    action_id = _next_action_id()
    status = "success" if normalized_ip else "skipped"
    if normalized_ip:
        blocked_ips.add(normalized_ip)
        # Persist to DB so the block survives server restarts.
        try:
            save_blocked_ip(normalized_ip, reason=trigger)
        except Exception:
            pass

    result = {
        "action_id": action_id,
        "action": "block_ip",
        "status": status,
        "target": normalized_ip or "unknown",
    }

    if status == "success":
        risk_score = int(float((threat or {}).get("risk_score", 0) or 0))
        result["counterfactual_trigger"] = {
            "ip": normalized_ip,
            "attack_type": str((threat or {}).get("attack_type", "UNKNOWN")),
            "risk_score": risk_score,
            "target_asset": _target_asset_label(threat),
        }

    _record_action(result, trigger)
    return result


def lock_account(username: str, trigger: str) -> dict[str, Any]:
    action_id = _next_action_id()
    status = "success" if username else "skipped"
    if username:
        locked_accounts.add(username)

    result = {
        "action_id": action_id,
        "action": "lock_account",
        "status": status,
        "target": username or "unknown",
    }
    _record_action(result, trigger)
    return result


def flag_ip(ip: str, trigger: str) -> dict[str, Any]:
    action_id = _next_action_id()
    status = "success" if ip else "skipped"
    if ip:
        flagged_ips.add(ip)

    result = {
        "action_id": action_id,
        "action": "flag_ip",
        "status": status,
        "target": ip or "unknown",
    }
    _record_action(result, trigger)
    return result


def create_ticket(threat: dict[str, Any], trigger: str) -> dict[str, Any]:
    action_id = _next_action_id()
    alert = {
        "alert_id": action_id,
        "timestamp": _timestamp(),
        "source_ip": threat.get("source_ip", "unknown"),
        "attack_type": threat.get("attack_type", "UNKNOWN"),
        "risk_score": threat.get("risk_score", 0),
        "severity": threat.get("severity", "LOW"),
        "reason": threat.get("reason", ""),
    }
    alerts.append(alert)

    result = {
        "action_id": action_id,
        "action": "create_ticket",
        "status": "success",
        "target": alert["alert_id"],
    }
    _record_action(result, trigger)
    return result


def create_alert(threat: dict[str, Any], trigger: str) -> dict[str, Any]:
    # Backward-compatible alias for older playbooks.
    return create_ticket(threat, trigger)


def notify_admin(message: str, trigger: str) -> dict[str, Any]:
    action_id = _next_action_id()
    msg = message or "SOC notification"
    sms_sent, sms_detail = _send_admin_sms(msg)

    result = {
        "action_id": action_id,
        "action": "notify_admin",
        "status": "success" if sms_sent else "pending",
        "target": "security_admin",
        "message": msg,
        "sms": {
            "sent": sms_sent,
            "detail": sms_detail,
        },
    }
    _record_action(result, trigger)
    if sms_sent:
        print(f"[response] notify_admin sms sent: {msg}")
    else:
        print(f"[response] notify_admin pending ({sms_detail}): {msg}")
    return result


def quarantine_email(username: str, trigger: str) -> dict[str, Any]:
    action_id = _next_action_id()
    target = username or "mailbox"
    result = {
        "action_id": action_id,
        "action": "quarantine_email",
        "status": "success",
        "target": target,
    }
    _record_action(result, trigger)
    return result


def rollback_action(action_id: str) -> dict[str, Any]:
    record = action_history.get(action_id)
    if not record:
        return {"action_id": action_id, "rollback_status": "failed", "reason": "not_found"}

    if record.get("rolled_back"):
        return {"action_id": action_id, "rollback_status": "skipped", "reason": "already_rolled_back"}

    action = record.get("action")
    target = record.get("target")

    if action == "block_ip" and target in blocked_ips:
        blocked_ips.remove(target)
        try:
            delete_blocked_ip(target)
        except Exception:
            pass
    elif action == "lock_account" and target in locked_accounts:
        locked_accounts.remove(target)
    elif action == "flag_ip" and target in flagged_ips:
        flagged_ips.remove(target)

    record["rolled_back"] = True

    rollback_entry = {
        "timestamp": _timestamp(),
        "action": "rollback",
        "target": target,
        "trigger": f"rollback:{action}",
        "status": "success",
        "action_id": action_id,
    }
    audit_log.append(rollback_entry)

    return {"action_id": action_id, "rollback_status": "success", "rolled_back_action": action}


def execute_action(action_name: str, threat: dict[str, Any], trigger: str) -> dict[str, Any]:
    source_ip = normalize_ip(str(threat.get("source_ip", "")))
    username = str(threat.get("username", ""))

    if action_name == "block_ip":
        return block_ip(source_ip, trigger, threat=threat)
    if action_name == "lock_account":
        return lock_account(username, trigger)
    if action_name == "flag_ip":
        return flag_ip(source_ip, trigger)
    if action_name == "create_ticket":
        return create_ticket(threat, trigger)
    if action_name == "create_alert":
        return create_alert(threat, trigger)
    if action_name == "notify_admin":
        message = (
            f"{threat.get('attack_type', 'THREAT')} from {source_ip} "
            f"risk={threat.get('risk_score', 0)} severity={threat.get('severity', 'LOW')}"
        )
        return notify_admin(message, trigger)
    if action_name == "quarantine_email":
        return quarantine_email(username, trigger)

    return {
        "action_id": _next_action_id(),
        "action": action_name,
        "status": "failed",
        "target": "unknown",
        "reason": "unknown_action",
    }


def _record_action(result: dict[str, Any], trigger: str) -> None:
    ts = _timestamp()
    action_history[result["action_id"]] = {
        **result,
        "trigger": trigger,
        "timestamp": ts,
        "rolled_back": False,
    }

    entry = {
        "timestamp": ts,
        "action": result.get("action"),
        "target": result.get("target"),
        "trigger": trigger,
        "status": result.get("status", "unknown"),
        "action_id": result.get("action_id"),
        "operator": "system",
    }
    audit_log.append(entry)

    # Persist to SQLite DB (fire-and-forget).
    try:
        save_audit_entry(entry)
    except Exception:
        pass

    # Append-only JSON file backup for extra safety.
    try:
        with _AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def _next_action_id() -> str:
    return f"act-{next(_action_counter)}"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _send_admin_sms(message: str) -> tuple[bool, str]:
    """Delegate to the notifications.sms module (uses correct env var names)."""
    try:
        from notifications.sms import _twilio_ready, _twilio_from, _twilio_to, _client

        if not _twilio_ready:
            return False, "twilio_not_configured"

        msg = _client.messages.create(
            body=message[:1600],
            from_=_twilio_from,
            to=_twilio_to,
        )
        return True, msg.sid
    except Exception as exc:
        return False, f"send_failed:{type(exc).__name__}"
