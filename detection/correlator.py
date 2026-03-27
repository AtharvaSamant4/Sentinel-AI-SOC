from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

_TRACKED_TYPES = {
    "BRUTE_FORCE": "Brute Force",
    "PHISHING": "Phishing",
    "PORT_SCAN": "Port Scan",
    "SQL_INJECTION": "SQL Injection",
    "C2_BEACON": "C2 Beacon",
}


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)

    text = str(value or "").strip()
    if not text:
        return None

    # Support common ISO payloads with trailing Z.
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _normalize_attack_type(value: Any) -> str:
    normalized = str(value or "").strip().upper().replace(" ", "_")
    if normalized == "BRUTEFORCE":
        return "BRUTE_FORCE"
    if normalized == "PORTSCAN":
        return "PORT_SCAN"
    return normalized


def check_correlation(recent_events: list[dict[str, Any]], window_minutes: int = 10) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)

    recent: list[dict[str, Any]] = []
    for event in recent_events:
        ts = _to_datetime(event.get("timestamp"))
        if ts is None:
            continue
        if ts > cutoff:
            recent.append(event)

    active_types = {
        _TRACKED_TYPES[tag]
        for event in recent
        for tag in [_normalize_attack_type(event.get("attack_type"))]
        if tag in _TRACKED_TYPES
    }

    if len(active_types) >= 3:
        source_countries = sorted(
            {
                str(event.get("country", "XX")).upper()
                for event in recent
                if str(event.get("severity", "")).upper() == "HIGH"
            }
        )
        return {
            "triggered": True,
            "vector_count": len(active_types),
            "attack_types": sorted(active_types),
            "source_countries": source_countries,
            "confidence": "HIGH" if len(active_types) >= 4 else "MEDIUM",
        }

    return {"triggered": False}
