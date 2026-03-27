from __future__ import annotations

import ast
from datetime import datetime, timezone
import json
import re
from typing import Any

from analyst.gemini_client import GeminiClient

_PROMPT = (
    "You are a log filter interpreter. Convert the natural language query into "
    "a structured filter object. Return ONLY valid JSON, no explanation.\n\n"
    "Schema: {\n"
    "  'severity': ['high'|'med'|'low'|'info'] or null,\n"
    "  'tag': string or null (e.g. 'Brute Force', 'Phishing'),\n"
    "  'geo_country': string or null,\n"
    "  'time_window_minutes': integer or null,\n"
    "  'ip_contains': string or null,\n"
    "  'keyword': string or null\n"
    "}\n\n"
    "Examples:\n"
    "'failed logins from Russia last 10 min' -> "
    "{'severity':'high','geo_country':'Russia','time_window_minutes':10}\n"
    "'all port scans' -> {'tag':'Port Scan'}\n"
    "'brute force attacks' -> {'tag':'Brute Force','severity':'high'}"
)


class LogQueryService:
    def __init__(self) -> None:
        self._client = GeminiClient(model_name="gemini-1.5-flash")

    def parse_query(self, query: str) -> dict[str, Any]:
        text = str(query or "").strip()
        if not text:
            return self._default_filter()

        prompt = f"{_PROMPT}\n\nUser query: {text}"
        try:
            raw = self._client.generate_analysis(prompt)
            parsed = self._parse_json_like(raw)
            return self._normalize_filter(parsed)
        except Exception:
            return self._heuristic_filter(text)

    def parse_model_response(self, raw: str) -> dict[str, Any]:
        parsed = self._parse_json_like(raw)
        return self._normalize_filter(parsed)

    def apply_filter(
        self,
        events: list[dict[str, Any]],
        filter_obj: dict[str, Any],
        max_results: int = 300,
    ) -> list[dict[str, Any]]:
        severity = str(filter_obj.get("severity") or "").lower().strip()
        tag = str(filter_obj.get("tag") or "").lower().strip()
        geo_country = str(filter_obj.get("geo_country") or "").lower().strip()
        ip_contains = str(filter_obj.get("ip_contains") or "").lower().strip()
        keyword = str(filter_obj.get("keyword") or "").lower().strip()

        minutes = filter_obj.get("time_window_minutes")
        window_seconds = 0
        try:
            window_seconds = int(minutes) * 60 if minutes else 0
        except Exception:
            window_seconds = 0

        now = datetime.now(timezone.utc)
        matched: list[dict[str, Any]] = []

        for event in events:
            if not isinstance(event, dict):
                continue

            if window_seconds > 0 and not self._within_window(event, now, window_seconds):
                continue
            if severity and not self._matches_severity(event, severity):
                continue
            if tag and not self._matches_tag(event, tag):
                continue
            if geo_country and not self._matches_geo(event, geo_country):
                continue
            if ip_contains and ip_contains not in str(event.get("source_ip", "")).lower():
                continue
            if keyword and not self._matches_keyword(event, keyword):
                continue

            matched.append(dict(event))
            if len(matched) >= max_results:
                break

        return matched

    @staticmethod
    def _default_filter() -> dict[str, Any]:
        return {
            "severity": None,
            "tag": None,
            "geo_country": None,
            "time_window_minutes": None,
            "ip_contains": None,
            "keyword": None,
        }

    def _heuristic_filter(self, query: str) -> dict[str, Any]:
        lowered = query.lower()
        data = self._default_filter()

        if "brute" in lowered:
            data["tag"] = "Brute Force"
            data["severity"] = "high"
        elif "port scan" in lowered or "portscan" in lowered:
            data["tag"] = "Port Scan"
        elif "phish" in lowered:
            data["tag"] = "Phishing"

        if "russia" in lowered:
            data["geo_country"] = "Russia"
        elif "china" in lowered:
            data["geo_country"] = "China"
        elif "iran" in lowered:
            data["geo_country"] = "Iran"
        elif "korea" in lowered:
            data["geo_country"] = "North Korea"

        minutes_match = re.search(r"(\d+)\s*(min|minute)", lowered)
        if minutes_match:
            data["time_window_minutes"] = int(minutes_match.group(1))

        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){0,3}\b", lowered)
        if ip_match:
            data["ip_contains"] = ip_match.group(0)

        if "failed login" in lowered:
            # Use a stem so both "failed" and "failure" statuses match.
            data["keyword"] = "fail"
            data["severity"] = data["severity"] or "high"

        return data

    @staticmethod
    def _parse_json_like(raw: str) -> dict[str, Any]:
        text = str(raw or "").strip()
        if not text:
            raise ValueError("empty model response")

        # Strip markdown fences if present.
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()

        try:
            value = json.loads(text)
            if isinstance(value, dict):
                return value
        except Exception:
            pass

        try:
            value = ast.literal_eval(text)
            if isinstance(value, dict):
                return value
        except Exception:
            pass

        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            snippet = match.group(0)
            try:
                value = ast.literal_eval(snippet)
                if isinstance(value, dict):
                    return value
            except Exception:
                pass

        raise ValueError("Unable to parse filter JSON")

    def _normalize_filter(self, data: dict[str, Any]) -> dict[str, Any]:
        result = self._default_filter()
        if not isinstance(data, dict):
            return result

        severity = data.get("severity")
        normalized_severity = None
        if isinstance(severity, list):
            if severity:
                normalized_severity = self._normalize_severity(severity[0])
        elif isinstance(severity, str):
            normalized_severity = self._normalize_severity(severity)

        result["severity"] = normalized_severity
        result["tag"] = self._clean_str(data.get("tag"))
        result["geo_country"] = self._clean_str(data.get("geo_country"))
        result["ip_contains"] = self._clean_str(data.get("ip_contains"))
        result["keyword"] = self._clean_str(data.get("keyword"))

        window = data.get("time_window_minutes")
        try:
            minutes = int(window)
            result["time_window_minutes"] = max(1, minutes)
        except Exception:
            result["time_window_minutes"] = None

        return result

    @staticmethod
    def _normalize_severity(value: str) -> str | None:
        lowered = str(value or "").strip().lower()
        if lowered in {"critical", "high"}:
            return "high"
        if lowered in {"medium", "med"}:
            return "med"
        if lowered in {"low"}:
            return "low"
        if lowered in {"info", "informational"}:
            return "info"
        return None

    @staticmethod
    def _clean_str(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None

    @staticmethod
    def _within_window(event: dict[str, Any], now: datetime, window_seconds: int) -> bool:
        timestamp = str(event.get("timestamp", ""))
        if not timestamp:
            return False
        try:
            parsed = datetime.fromisoformat(timestamp)
        except ValueError:
            return False

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (now - parsed).total_seconds() <= window_seconds

    @staticmethod
    def _matches_severity(event: dict[str, Any], severity: str) -> bool:
        event_severity = str(event.get("severity", "LOW")).lower()
        if severity == "high":
            return event_severity in {"high", "critical"}
        if severity == "med":
            return event_severity == "medium"
        if severity == "low":
            return event_severity == "low"
        if severity == "info":
            return event_severity in {"low", "info"}
        return True

    @staticmethod
    def _matches_tag(event: dict[str, Any], tag: str) -> bool:
        attack_type = str(event.get("attack_type", "")).lower().replace("_", " ")
        attack_tag = str(event.get("attack_tag", "")).lower()
        tag_value = tag.replace("_", " ")
        return tag_value in attack_type or tag_value in attack_tag

    @staticmethod
    def _matches_geo(event: dict[str, Any], geo_country: str) -> bool:
        country = str(event.get("country", "")).upper()
        geo = geo_country.lower()
        country_aliases = {
            "russia": {"RU", "RUSSIA"},
            "china": {"CN", "CHINA"},
            "iran": {"IR", "IRAN"},
            "north korea": {"KP", "NORTH KOREA"},
            "korea": {"KP", "NORTH KOREA"},
            "brazil": {"BR", "BRAZIL"},
            "germany": {"DE", "GERMANY"},
            "netherlands": {"NL", "NETHERLANDS"},
        }

        aliases = country_aliases.get(geo, {geo.upper()})
        return country in aliases

    @staticmethod
    def _matches_keyword(event: dict[str, Any], keyword: str) -> bool:
        blob = " ".join(
            [
                str(event.get("attack_type", "")),
                str(event.get("event_type", "")),
                str(event.get("status", "")),
                str(event.get("reason", "")),
                str(event.get("analysis", "")),
                str(event.get("source_ip", "")),
                str(event.get("destination_ip", "")),
                str(event.get("country", "")),
            ]
        ).lower()

        token = keyword.lower().strip()
        if not token:
            return True

        # Treat fail/failure/failed as one concept to match common query wording.
        if token in {"failed", "failure", "fail"}:
            return any(variant in blob for variant in ("failed", "failure", "fail"))

        return token in blob


log_query_service = LogQueryService()
