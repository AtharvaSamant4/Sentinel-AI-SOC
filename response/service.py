from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any

from response.actions import audit_log, execute_action, rollback_action
from response.engine import ResponseEngine
from response.operator import evaluate_threat


class ResponseService:
    def __init__(self, dedupe_window_seconds: int = 10) -> None:
        self._engine = ResponseEngine()
        self._dedupe_window_seconds = dedupe_window_seconds
        self._recent_actions: dict[str, float] = {}

    def handle_threat(self, threat: dict[str, Any]) -> dict[str, Any]:
        severity = str(threat.get("severity", "LOW")).upper()
        attack_type = str(threat.get("attack_type", "NORMAL")).upper()

        # ── operator decision gate ────────────────────────────────────────
        # Routes the threat through the human-in-the-loop layer first.
        #   CRITICAL  → auto_execute (falls through to existing engine logic)
        #   HIGH      → stored as PENDING, operator must approve
        #   MEDIUM/LOW → log only, no response fired
        decision = evaluate_threat(threat)

        # SMS alert for HIGH and CRITICAL threats — fires regardless of operator decision.
        if severity in {"HIGH", "CRITICAL"}:
            try:
                from notifications.sms import send_sms_alert
                sms_result = send_sms_alert(threat)
                print(f"[response] sms alert: {sms_result.get('status')} ({sms_result.get('detail')})")
            except Exception as sms_exc:
                print(f"[response] sms alert failed (non-critical): {sms_exc}")

        if decision["decision"] == "pending_approval":
            return {
                "actions_executed": [],
                "operator_decision": decision,
            }

        if decision["decision"] == "log_only":
            return {
                "actions_executed": [],
                "operator_decision": decision,
            }

        # decision == "auto_execute" — proceed with existing engine for CRITICAL
        # (and keep backward-compat for any attack_type-based routing below).
        if severity not in {"HIGH", "CRITICAL"} and attack_type not in {
            "BRUTE_FORCE",
            "PORT_SCAN",
            "PHISHING",
            "SQL_INJECTION",
            "C2_BEACON",
        }:
            return {"actions_executed": [], "operator_decision": decision}

        try:
            actions = self._engine.execute(threat)
            actions = self._ensure_autonomous_block(actions, threat)
            filtered_actions = self._filter_duplicate_actions(actions, threat)
            if filtered_actions:
                attack_type = str(threat.get("attack_type", "UNKNOWN"))
                source_ip = str(threat.get("source_ip", "unknown"))
                print(f"[response] response triggered: {attack_type} source={source_ip}")

            return {"actions_executed": filtered_actions, "operator_decision": decision}
        except Exception:
            pending_action = {
                "action_id": f"pending-{int(datetime.now(timezone.utc).timestamp())}",
                "action": "response_engine",
                "status": "PENDING",
                "target": str(threat.get("source_ip", "unknown")),
                "message": "Response engine temporarily unavailable",
            }
            return {"actions_executed": [pending_action], "operator_decision": decision}

    def rollback(self, action_id: str) -> dict[str, Any]:
        return rollback_action(action_id)

    def get_audit_log(self) -> list[dict[str, Any]]:
        return list(audit_log)

    def _filter_duplicate_actions(
        self, actions: list[dict[str, Any]], threat: dict[str, Any]
    ) -> list[dict[str, Any]]:
        now = time.time()
        source_ip = str(threat.get("source_ip", "unknown"))

        # Opportunistically prune stale dedupe entries.
        cutoff = now - self._dedupe_window_seconds
        stale_keys = [key for key, ts in self._recent_actions.items() if ts < cutoff]
        for key in stale_keys:
            self._recent_actions.pop(key, None)

        filtered: list[dict[str, Any]] = []
        for action in actions:
            action_name = str(action.get("action", "unknown"))
            dedupe_key = f"{source_ip}:{action_name}"
            last_seen = self._recent_actions.get(dedupe_key, 0.0)
            if now - last_seen < self._dedupe_window_seconds:
                continue
            self._recent_actions[dedupe_key] = now
            filtered.append(action)

        return filtered

    def _ensure_autonomous_block(
        self, actions: list[dict[str, Any]], threat: dict[str, Any]
    ) -> list[dict[str, Any]]:
        attack_type = str(threat.get("attack_type", "NORMAL")).upper()
        source_ip = str(threat.get("source_ip", "")).strip()

        if attack_type not in {"BRUTE_FORCE", "PORT_SCAN", "PHISHING", "SQL_INJECTION", "C2_BEACON"}:
            return actions
        if not source_ip:
            return actions
        if any(str(action.get("action", "")) == "block_ip" for action in actions):
            return actions

        forced_block = execute_action("block_ip", threat, trigger=f"AUTONOMOUS {attack_type} threat")
        return [forced_block, *actions]


response_service = ResponseService()
