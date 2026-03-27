"""
notifications/sms.py
---------------------
Twilio SMS alert module for SENTINEL AI-SOC.

Sends SMS alerts for CRITICAL threats with:
  - Singleton Twilio client (initialized once from env vars)
  - Anti-spam cooldown (60 seconds per source IP)
  - Audit log entry on every send attempt
  - Graceful degradation: if Twilio is not configured, logs a warning and no-ops

Environment variables (from .env):
  TWILIO_SID    - Twilio Account SID
  TWILIO_TOKEN  - Twilio Auth Token
  TWILIO_PHONE  - Twilio sender phone number (E.164 format, e.g. +13186572566)
  ADMIN_PHONE   - Recipient phone number (E.164 format, e.g. +918698221188)
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singleton client
# ---------------------------------------------------------------------------

_client = None
_twilio_from: str = ""
_twilio_to: str = ""
_twilio_ready: bool = False


def _init_client() -> None:
    global _client, _twilio_from, _twilio_to, _twilio_ready

    account_sid = os.getenv("TWILIO_SID", "").strip()
    auth_token = os.getenv("TWILIO_TOKEN", "").strip()
    _twilio_from = os.getenv("TWILIO_PHONE", "").strip()
    _twilio_to = os.getenv("ADMIN_PHONE", "").strip()

    if not all([account_sid, auth_token, _twilio_from, _twilio_to]):
        logger.warning(
            "[sms] Twilio not fully configured — SMS alerts disabled. "
            "Set TWILIO_SID, TWILIO_TOKEN, TWILIO_PHONE, ADMIN_PHONE in .env"
        )
        _twilio_ready = False
        return

    try:
        from twilio.rest import Client
        _client = Client(account_sid, auth_token)
        _twilio_ready = True
        logger.info("[sms] Twilio client initialized (from=%s, to=%s)", _twilio_from, _twilio_to)
    except Exception as exc:
        logger.warning("[sms] Twilio client init failed: %s — SMS alerts disabled.", exc)
        _twilio_ready = False


# Initialize immediately when module is imported.
_init_client()

# ---------------------------------------------------------------------------
# Anti-spam cooldown state
# ---------------------------------------------------------------------------

# Keyed by source IP → last SMS sent timestamp (epoch float).
_recent_sms: dict[str, float] = {}
_COOLDOWN_SECONDS = 10


def _is_on_cooldown(source_ip: str) -> bool:
    last = _recent_sms.get(source_ip, 0.0)
    return (time.time() - last) < _COOLDOWN_SECONDS


def _record_sent(source_ip: str) -> None:
    _recent_sms[source_ip] = time.time()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_sms_alert(
    threat: dict[str, Any],
    to: str | None = None,
) -> dict[str, Any]:
    """
    Send an SMS alert for a CRITICAL threat.

    Parameters
    ----------
    threat : dict
        Threat object with at least source_ip, attack_type, risk_score, severity.
    to : str | None
        Override recipient number (E.164). Defaults to ADMIN_PHONE env var.

    Returns
    -------
    dict with keys: status ("sent" | "cooldown" | "disabled" | "error"),
                    message_sid (str | None),
                    detail (str)
    """
    source_ip = str(threat.get("source_ip", "unknown"))
    attack_type = str(threat.get("attack_type", "UNKNOWN"))
    risk_score = int(float(threat.get("risk_score", 0) or 0))
    severity = str(threat.get("severity", "UNKNOWN"))
    recipient = (to or _twilio_to).strip()

    result: dict[str, Any] = {
        "source_ip": source_ip,
        "status": "disabled",
        "message_sid": None,
        "detail": "",
    }

    if not _twilio_ready:
        # Try once more in case dotenv wasn't loaded when module was first imported.
        _init_client()

    if not _twilio_ready:
        result["detail"] = "twilio_not_configured"
        _write_audit(result, threat)
        return result

    if _is_on_cooldown(source_ip):
        result["status"] = "cooldown"
        result["detail"] = f"cooldown active for {source_ip} ({_COOLDOWN_SECONDS}s window)"
        logger.debug("[sms] cooldown suppressed alert for %s", source_ip)
        _write_audit(result, threat)
        return result

    body = (
        f"CRITICAL ALERT\n"
        f"Attack: {attack_type}\n"
        f"IP: {source_ip}\n"
        f"Risk: {risk_score}/100\n"
        f"Severity: {severity}\n"
        f"Action: Auto-block executed"
    )

    try:
        message = _client.messages.create(
            body=body[:1600],
            from_=_twilio_from,
            to=recipient,
        )
        _record_sent(source_ip)
        result["status"] = "sent"
        result["message_sid"] = message.sid
        result["detail"] = f"sent to {recipient}"
        logger.info(
            "[sms] alert sent: sid=%s attack=%s ip=%s risk=%d",
            message.sid, attack_type, source_ip, risk_score,
        )
    except Exception as exc:
        result["status"] = "error"
        result["detail"] = f"send_failed:{type(exc).__name__}:{exc}"
        logger.error("[sms] failed to send alert for %s: %s", source_ip, exc)

    _write_audit(result, threat)
    return result


def send_test_sms(to: str | None = None) -> dict[str, Any]:
    """Send a test SMS to verify Twilio configuration."""
    if not _twilio_ready:
        return {"status": "disabled", "message_sid": None, "detail": "twilio_not_configured"}

    recipient = (to or _twilio_to).strip()
    try:
        message = _client.messages.create(
            body="SENTINEL AI-SOC: Test alert — Twilio integration is working correctly.",
            from_=_twilio_from,
            to=recipient,
        )
        logger.info("[sms] test message sent: sid=%s to=%s", message.sid, recipient)
        return {"status": "sent", "message_sid": message.sid, "detail": f"sent to {recipient}"}
    except Exception as exc:
        logger.error("[sms] test send failed: %s", exc)
        return {"status": "error", "message_sid": None, "detail": f"send_failed:{exc}"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _write_audit(result: dict[str, Any], threat: dict[str, Any]) -> None:
    """Fire-and-forget audit log entry for every SMS attempt."""
    try:
        from db.store import save_audit_entry
        from datetime import datetime, timezone

        save_audit_entry({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "sms_alert",
            "target": str(threat.get("source_ip", "unknown")),
            "trigger": "critical_threat",
            "status": result.get("status", "unknown"),
            "action_id": result.get("message_sid") or "sms_no_sid",
            "operator": "system",
        })
    except Exception:
        pass
