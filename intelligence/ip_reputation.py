from __future__ import annotations

import json
import os
from pathlib import Path
import random
import time
from typing import Any
from urllib import parse, request

_CACHE_TTL_SECONDS = 3600
_API_URL = "https://api.abuseipdb.com/api/v2/check"
_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"


class IpReputationService:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}

    def lookup(self, ip_address: str) -> dict[str, Any]:
        normalized_ip = str(ip_address or "").strip()
        if not normalized_ip or normalized_ip == "unknown":
            return self._mock_data("XX")

        cached = self._get_cached(normalized_ip)
        if cached:
            return cached

        api_key = self._resolve_api_key()
        if not api_key:
            data = self._mock_data("XX")
            self._cache[normalized_ip] = (time.time(), data)
            return data

        data = self._fetch_from_abuseipdb(normalized_ip, api_key)
        if not data:
            data = self._mock_data("XX")

        self._cache[normalized_ip] = (time.time(), data)
        return data

    def _get_cached(self, ip_address: str) -> dict[str, Any] | None:
        record = self._cache.get(ip_address)
        if not record:
            return None

        timestamp, payload = record
        if (time.time() - timestamp) > _CACHE_TTL_SECONDS:
            self._cache.pop(ip_address, None)
            return None

        return payload

    def _fetch_from_abuseipdb(self, ip_address: str, api_key: str) -> dict[str, Any] | None:
        query = parse.urlencode({"ipAddress": ip_address, "maxAgeInDays": 90})
        url = f"{_API_URL}?{query}"
        req = request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        req.add_header("Key", api_key)

        try:
            with request.urlopen(req, timeout=6) as resp:
                if int(resp.status) < 200 or int(resp.status) >= 300:
                    return None
                decoded = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

        data = decoded.get("data", {}) if isinstance(decoded, dict) else {}
        if not isinstance(data, dict):
            return None

        return {
            "abuseConfidenceScore": int(data.get("abuseConfidenceScore", 0) or 0),
            "totalReports": int(data.get("totalReports", 0) or 0),
            "lastReportedAt": str(data.get("lastReportedAt") or "unknown"),
            "countryCode": str(data.get("countryCode") or "XX"),
            "isWhitelisted": bool(data.get("isWhitelisted", False)),
            "source": "abuseipdb",
        }

    @staticmethod
    def _resolve_api_key() -> str:
        env_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        if env_key:
            return env_key

        if not _ENV_PATH.exists():
            return ""

        try:
            content = _ENV_PATH.read_text(encoding="utf-8")
        except Exception:
            return ""

        for line in content.splitlines():
            if not line or line.lstrip().startswith("#"):
                continue
            if not line.startswith("ABUSEIPDB_API_KEY"):
                continue
            _, _, value = line.partition("=")
            return value.strip().strip('"').strip("'")

        return ""

    @staticmethod
    def _mock_data(country_code: str) -> dict[str, Any]:
        return {
            "abuseConfidenceScore": random.randint(75, 97),
            "totalReports": random.randint(200, 1200),
            "lastReportedAt": "2 hours ago",
            "countryCode": str(country_code or "XX"),
            "isWhitelisted": False,
            "source": "mock",
        }


ip_reputation_service = IpReputationService()
