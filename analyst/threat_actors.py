from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_ACTOR_DATA_PATH = Path(__file__).resolve().parents[1] / "threat_actors.json"

_ATTACK_TYPE_TO_TACTIC = {
    "BRUTE_FORCE": "Brute Force",
    "PHISHING": "Phishing",
    "C2_BEACON": "C2 Beacon",
    "PORT_SCAN": "Port Scan",
    "SQL_INJECTION": "SQL Injection",
}

_COUNTRY_TO_ORIGIN = {
    "RU": "Russia",
    "KP": "North Korea",
    "CN": "China",
    "IR": "Iran",
}


def _load_actor_profiles() -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(_ACTOR_DATA_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

    if not isinstance(raw, dict):
        return {}

    normalized: dict[str, dict[str, Any]] = {}
    for name, profile in raw.items():
        if isinstance(name, str) and isinstance(profile, dict):
            normalized[name] = profile
    return normalized


def _normalized_origin(source_country: str) -> str:
    country = str(source_country or "").strip()
    if not country:
        return ""
    if len(country) == 2:
        return _COUNTRY_TO_ORIGIN.get(country.upper(), "")
    return country


def match_threat_actor(attack_type: str, source_country: str, target_port: int | None = None) -> dict[str, Any] | None:
    profiles = _load_actor_profiles()
    if not profiles:
        return None

    tactic = _ATTACK_TYPE_TO_TACTIC.get(str(attack_type or "").strip().upper(), "")
    origin = _normalized_origin(source_country)
    try:
        port = int(target_port) if target_port is not None else None
    except (TypeError, ValueError):
        port = None

    best_name = ""
    best_profile: dict[str, Any] | None = None
    best_score = -1

    for actor_name, profile in profiles.items():
        score = 0
        tactics = [str(item) for item in profile.get("tactics", []) if isinstance(item, (str, int, float))]
        profile_origin = str(profile.get("origin", "")).strip()
        profile_ports = []
        for item in profile.get("ports", []):
            try:
                profile_ports.append(int(item))
            except (TypeError, ValueError):
                continue

        if tactic and tactic in tactics:
            score += 2
        if origin and profile_origin and origin.lower() == profile_origin.lower():
            score += 2
        if port is not None and port in profile_ports:
            score += 1

        if score > best_score:
            best_score = score
            best_name = actor_name
            best_profile = profile

    if best_score < 2 or not best_profile or not best_name:
        return None

    return {
        "name": best_name,
        "aka": str(best_profile.get("aka", "Unknown")),
        "origin": str(best_profile.get("origin", "Unknown")),
        "description": str(best_profile.get("description", "")),
        "confidence": "HIGH",
    }
