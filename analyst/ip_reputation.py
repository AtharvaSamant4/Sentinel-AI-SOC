from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any
import random

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

_cache: dict[str, tuple[dict[str, Any], datetime]] = {}
CACHE_TTL_MINUTES = 60


def _safe_ip(ip: str) -> str:
    return str(ip or "").strip()


def get_ip_reputation(ip: str) -> dict[str, Any]:
    normalized_ip = _safe_ip(ip)
    if not normalized_ip:
        return {
            "abuse_score": 0,
            "total_reports": 0,
            "last_reported": "Unavailable",
            "country": "Unknown",
            "is_mock": False,
        }

    if normalized_ip in _cache:
        result, expires = _cache[normalized_ip]
        if datetime.now() < expires:
            return result

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    if not api_key:
        mock = {
            "abuse_score": random.randint(72, 97),
            "total_reports": random.randint(200, 1400),
            "last_reported": "2 hours ago",
            "country": "Unknown",
            "is_mock": True,
        }
        _cache[normalized_ip] = (mock, datetime.now() + timedelta(minutes=CACHE_TTL_MINUTES))
        return mock

    if requests is None:
        result = {
            "abuse_score": 0,
            "total_reports": 0,
            "last_reported": "Unavailable",
            "country": "Unknown",
            "is_mock": False,
        }
        _cache[normalized_ip] = (result, datetime.now() + timedelta(minutes=CACHE_TTL_MINUTES))
        return result

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": normalized_ip, "maxAgeInDays": 90, "verbose": "false"},
            timeout=3,
        )
        data = resp.json().get("data", {}) if resp is not None else {}
        result = {
            "abuse_score": int(data.get("abuseConfidenceScore", 0) or 0),
            "total_reports": int(data.get("totalReports", 0) or 0),
            "last_reported": str(data.get("lastReportedAt", "Unknown")),
            "country": str(data.get("countryCode", "Unknown")),
            "is_mock": False,
        }
    except Exception:
        result = {
            "abuse_score": 0,
            "total_reports": 0,
            "last_reported": "Unavailable",
            "country": "Unknown",
            "is_mock": False,
        }

    _cache[normalized_ip] = (result, datetime.now() + timedelta(minutes=CACHE_TTL_MINUTES))
    return result
