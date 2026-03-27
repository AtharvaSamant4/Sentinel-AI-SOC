from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DATA_PATH = Path(__file__).with_name("threat_actors.json")

_ATTACK_TO_TACTIC = {
    "BRUTE_FORCE": "Brute Force",
    "PHISHING": "Phishing",
    "PORT_SCAN": "Port Scan",
    "SQL_INJECTION": "SQL Injection",
    "C2_BEACON": "C2 Beacon",
}

_COUNTRY_TO_ORIGIN = {
    "RU": "Russia",
    "KP": "North Korea",
    "CN": "China",
    "IR": "Iran",
}

_ORIGIN_ADJECTIVE = {
    "Russia": "Russian",
    "North Korea": "North Korean",
    "China": "Chinese",
    "Iran": "Iranian",
}


def _load_profiles() -> dict[str, dict[str, Any]]:
    try:
        content = _DATA_PATH.read_text(encoding="utf-8")
        raw = json.loads(content)
    except Exception:
        return {}

    profiles: dict[str, dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return profiles

    for name, profile in raw.items():
        if not isinstance(profile, dict):
            continue
        profiles[str(name)] = profile
    return profiles


class ThreatActorMatcher:
    def __init__(self) -> None:
        self._profiles = _load_profiles()

    def match(self, threat: dict[str, Any]) -> dict[str, Any] | None:
        if not self._profiles:
            return None

        tactic = _ATTACK_TO_TACTIC.get(str(threat.get("attack_type", "")).upper())
        if not tactic:
            return None

        country_code = str(threat.get("country", "")).upper()
        origin = _COUNTRY_TO_ORIGIN.get(country_code)
        destination_port = int(threat.get("destination_port", 0) or 0)

        best: dict[str, Any] | None = None
        best_confidence = -1

        for actor_name, profile in self._profiles.items():
            confidence = 0

            profile_origin = str(profile.get("origin", ""))
            profile_tactics = [str(t) for t in profile.get("tactics", [])]
            profile_ports = [int(p) for p in profile.get("target_ports", [])]

            if origin and profile_origin == origin:
                confidence += 1
            if tactic in profile_tactics:
                confidence += 1
            if destination_port > 0 and destination_port in profile_ports:
                confidence += 1

            if confidence > best_confidence:
                best_confidence = confidence
                best = {
                    "name": actor_name,
                    "aka": str(profile.get("aka", "Unknown")),
                    "origin": profile_origin,
                    "description": str(profile.get("description", "")),
                    "confidence": confidence,
                }

        if not best or int(best.get("confidence", 0)) < 2:
            return None

        adjective = _ORIGIN_ADJECTIVE.get(str(best.get("origin", "")), str(best.get("origin", "")))
        best["label"] = f"{adjective} state-sponsored"
        return best


threat_actor_matcher = ThreatActorMatcher()
