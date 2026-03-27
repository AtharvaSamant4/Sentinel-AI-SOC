from __future__ import annotations

from pathlib import Path
import re
from typing import Any

import yaml

from response.actions import execute_action


class ResponseEngine:
    def __init__(self, playbook_path: Path | None = None) -> None:
        default_path = Path(__file__).with_name("playbooks.yaml")
        self._playbook_path = playbook_path or default_path
        self._rules = self._load_playbooks()

    def execute(self, threat: dict[str, Any]) -> list[dict[str, Any]]:
        context = self._build_context(threat)
        results: list[dict[str, Any]] = []

        for rule in self._rules:
            trigger = str(rule.get("trigger", "")).upper()
            if not self._trigger_matches(trigger, context):
                continue
            if not self._conditions_match(rule.get("conditions", {}), context):
                continue

            for action_name in rule.get("actions", []):
                result = execute_action(str(action_name), threat, trigger=f"{trigger} threat")
                results.append(result)

        return results

    def _load_playbooks(self) -> list[dict[str, Any]]:
        try:
            with open(self._playbook_path, "r", encoding="utf-8") as file:
                loaded = yaml.safe_load(file) or []
        except FileNotFoundError:
            print(f"[engine] playbooks.yaml not found at {self._playbook_path} — using empty ruleset")
            return []
        if not isinstance(loaded, list):
            raise ValueError("Playbook root must be a list")
        return loaded

    def _trigger_matches(self, trigger: str, context: dict[str, Any]) -> bool:
        if not trigger:
            return False
        return trigger in {str(context.get("severity", "")).upper(), str(context.get("attack_type", "")).upper()}

    def _conditions_match(self, conditions: dict[str, Any], context: dict[str, Any]) -> bool:
        for key, expected in conditions.items():
            actual = context.get(str(key))
            if not self._match_condition(actual, expected):
                return False
        return True

    def _match_condition(self, actual: Any, expected: Any) -> bool:
        if isinstance(expected, str):
            parsed = self._parse_operator(expected)
            if parsed is not None:
                operator, rhs = parsed
                actual_num = self._to_float(actual)
                if actual_num is None:
                    return False
                return self._compare_numeric(actual_num, operator, rhs)

        return str(actual) == str(expected)

    @staticmethod
    def _parse_operator(raw: str) -> tuple[str, float] | None:
        match = re.fullmatch(r"\s*(>=|<=|>|<|==|!=)\s*(-?\d+(?:\.\d+)?)\s*", raw)
        if not match:
            return None
        return match.group(1), float(match.group(2))

    @staticmethod
    def _to_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _compare_numeric(lhs: float, operator: str, rhs: float) -> bool:
        if operator == ">":
            return lhs > rhs
        if operator == "<":
            return lhs < rhs
        if operator == ">=":
            return lhs >= rhs
        if operator == "<=":
            return lhs <= rhs
        if operator == "==":
            return lhs == rhs
        if operator == "!=":
            return lhs != rhs
        return False

    @staticmethod
    def _build_context(threat: dict[str, Any]) -> dict[str, Any]:
        reason = str(threat.get("reason", ""))
        failed_attempts = _extract_first_int(reason) or 0

        return {
            **threat,
            "severity": str(threat.get("severity", "LOW")).upper(),
            "attack_type": str(threat.get("attack_type", "NORMAL")).upper(),
            "risk_score": float(threat.get("risk_score", 0)),
            "failed_attempts": failed_attempts,
        }


def _extract_first_int(text: str) -> int | None:
    match = re.search(r"\b(\d+)\b", text)
    if not match:
        return None
    return int(match.group(1))
