from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import time

from analyst.threat_actors import match_threat_actor
from db.store import save_threat
from intelligence.classifier import EventClassifier
from intelligence.ip_reputation import ip_reputation_service
from intelligence.mitre_mapper import map_attack_type
from intelligence.risk_engine import compute_risk_score


class IntelligenceService:
    _KILL_CHAIN_STAGE_ORDER = [
        "Reconnaissance",
        "Initial Access",
        "Persistence",
        "Privilege Escalation",
        "Credential Access",
        "Lateral Movement",
        "Command & Control",
        "Exfiltration",
    ]

    _KILL_CHAIN_ACTIVE_WINDOW_SECONDS = 300

    def __init__(self, asset_criticality: float = 0.5) -> None:
        self._classifier = EventClassifier(window_seconds=60)
        self._asset_criticality = asset_criticality
        self._last_detection_log: dict[str, float] = {}
        self._kill_chain_state: OrderedDict[str, dict] = OrderedDict()

    def build_threat_object(self, event: dict) -> dict:
        classified = self._classifier.classify_event(event)
        attack_type = classified["type"]
        severity_weight = float(classified["severity_weight"])
        signals = classified.get("signals", {})

        anomaly_score = float(event.get("anomaly_score", 0.0))
        time_flag = 1 if self._is_off_hours(str(event.get("timestamp", ""))) else 0
        ip_reputation = self._lookup_ip_reputation(event)
        ip_reputation_bonus = self._ip_reputation_bonus(ip_reputation)

        risk = compute_risk_score(
            anomaly_score=anomaly_score,
            severity_weight=severity_weight,
            asset_criticality=self._asset_criticality,
            time_flag=time_flag,
            ip_reputation_bonus=ip_reputation_bonus,
        )
        risk = self._demo_override(attack_type, risk)

        mitre = map_attack_type(attack_type)
        reason = self._build_reason(attack_type, event, signals)
        self._log_attack_detection(attack_type, event, risk)
        threat_actor = self._match_actor_if_high(event, attack_type, risk)
        ip_reputation = self._filter_ip_reputation_by_severity(ip_reputation, risk)
        kill_chain = self._update_kill_chain_snapshot(attack_type, event)

        threat_obj = {
            "timestamp": str(event.get("timestamp", datetime.now(timezone.utc).isoformat())),
            "source_ip": str(event.get("source_ip", "unknown")),
            "destination_ip": str(event.get("destination_ip", "unknown")),
            "destination_port": int(event.get("destination_port", 0) or 0),
            "protocol": str(event.get("protocol", "TCP")),
            "event_type": str(event.get("event_type", "connection")),
            "status": str(event.get("status", "failure")),
            "username": event.get("username") or "unknown",
            "country": str(event.get("country", "XX")),
            "is_attack": event.get("is_attack", False),
            "attack_type": attack_type,
            "anomaly_score": round(anomaly_score, 4),
            "risk_score": risk["risk_score"],
            "severity": risk["risk_band"],
            "score_breakdown": list(risk.get("score_breakdown", [])),
            "mitre": mitre,
            "reason": reason,
            "threat_actor": threat_actor,
            "ip_reputation": ip_reputation,
            "kill_chain": kill_chain,
            "is_ingested": bool(event.get("is_ingested", False)),
        }

        # Persist to SQLite — fire-and-forget, never blocks the pipeline.
        if attack_type != "NORMAL":
            save_threat(threat_obj)

        return threat_obj

    def build_threat_objects(self, events: list[dict]) -> list[dict]:
        return [self.build_threat_object(event) for event in events]

    def _build_reason(self, attack_type: str, event: dict, signals: dict) -> str:
        if attack_type == "BRUTE_FORCE":
            failed_count = int(signals.get("failed_login_count", 0))
            if failed_count > 0:
                noun = "attempt" if failed_count == 1 else "attempts"
                return f"{failed_count} failed login {noun} detected in short time window"
            return "Multiple failed login attempts detected"
        if attack_type == "PORT_SCAN":
            unique_ports = int(signals.get("unique_ports", 0))
            if unique_ports > 0:
                return f"{unique_ports} unique ports accessed from single source in short window"
            return "Multiple ports accessed from single source"
        if attack_type == "ANOMALOUS_LOGIN":
            return "Off-hours login detected from new source IP"
        if attack_type == "PHISHING":
            return "Suspicious phishing delivery pattern detected"
        if attack_type == "DATA_EXFILTRATION":
            transferred = int(signals.get("bytes_transferred", event.get("bytes_transferred", 0)))
            if transferred > 0:
                return f"Unusual spike in outbound data ({transferred} bytes transferred)"
            return "Unusual spike in outbound data"
        if attack_type == "SQL_INJECTION":
            return "Suspicious SQL injection payload patterns detected"
        if attack_type == "C2_BEACON":
            interval = int(signals.get("beacon_interval_seconds", 0))
            if interval > 0:
                return f"Periodic command-and-control beacon detected every ~{interval}s"
            return "Periodic command-and-control beacon behavior detected"
        if attack_type == "PRIVILEGE_ESCALATION":
            return "Privilege escalation behavior detected on monitored endpoint"
        if attack_type == "LATERAL_MOVEMENT":
            return "Lateral movement behavior detected between internal hosts"
        return "No suspicious behavior detected"

    @staticmethod
    def _is_off_hours(timestamp: str) -> bool:
        if not timestamp:
            return False
        try:
            hour = datetime.fromisoformat(timestamp).hour
        except ValueError:
            return False
        return hour < 6 or hour >= 22

    @staticmethod
    def _demo_override(attack_type: str, risk: dict) -> dict:
        overridden = dict(risk)
        if attack_type == "BRUTE_FORCE" and overridden.get("risk_score", 0) < 82:
            overridden["risk_score"] = 82
            overridden["risk_band"] = "HIGH"
        if attack_type == "PORT_SCAN" and overridden.get("risk_score", 0) < 84:
            overridden["risk_score"] = 84
            overridden["risk_band"] = "HIGH"
        if attack_type == "PHISHING":
            overridden["risk_score"] = max(int(overridden.get("risk_score", 0)), 95)
            overridden["risk_band"] = "CRITICAL"
        if attack_type == "C2_BEACON" and overridden.get("risk_score", 0) < 86:
            overridden["risk_score"] = 86
            overridden["risk_band"] = "HIGH"
        if attack_type == "PRIVILEGE_ESCALATION" and overridden.get("risk_score", 0) < 91:
            overridden["risk_score"] = 91
            overridden["risk_band"] = "CRITICAL"
        if attack_type == "LATERAL_MOVEMENT" and overridden.get("risk_score", 0) < 88:
            overridden["risk_score"] = 88
            overridden["risk_band"] = "HIGH"
        if attack_type == "DATA_EXFILTRATION" and overridden.get("risk_score", 0) < 94:
            overridden["risk_score"] = 94
            overridden["risk_band"] = "CRITICAL"
        return overridden

    def _log_attack_detection(self, attack_type: str, event: dict, risk: dict) -> None:
        if attack_type not in {"BRUTE_FORCE", "PORT_SCAN", "PHISHING", "SQL_INJECTION", "C2_BEACON"}:
            return

        source_ip = str(event.get("source_ip", "unknown"))
        key = f"{attack_type}:{source_ip}"
        now = time.time()
        last = self._last_detection_log.get(key, 0.0)
        if now - last < 5.0:
            return

        self._last_detection_log[key] = now
        print(
            "[detection] attack detected: "
            f"type={attack_type} source={source_ip} severity={risk.get('risk_band', 'LOW')}"
        )

    @staticmethod
    def _match_actor_if_high(event: dict, attack_type: str, risk: dict) -> dict | None:
        severity = str(risk.get("risk_band", "LOW")).upper()
        if severity not in {"HIGH", "CRITICAL"}:
            return None

        return match_threat_actor(
            attack_type=attack_type,
            source_country=str(event.get("country", "")),
            target_port=int(event.get("destination_port", 0) or 0),
        )

    @staticmethod
    def _lookup_ip_reputation(event: dict) -> dict:
        source_ip = str(event.get("source_ip", "unknown"))
        reputation = ip_reputation_service.lookup(source_ip)
        if str(reputation.get("countryCode", "XX")) == "XX":
            reputation["countryCode"] = str(event.get("country", "XX") or "XX")
        return reputation

    @staticmethod
    def _filter_ip_reputation_by_severity(reputation: dict, risk: dict) -> dict | None:
        severity = str(risk.get("risk_band", "LOW")).upper()
        if severity not in {"HIGH", "CRITICAL"}:
            return None

        return reputation

    @staticmethod
    def _ip_reputation_bonus(reputation: dict) -> float:
        confidence = int(reputation.get("abuseConfidenceScore", 0) or 0)
        reports = int(reputation.get("totalReports", 0) or 0)

        if confidence >= 85 or reports >= 100:
            return 1.0
        if confidence >= 60 or reports >= 20:
            return 0.6
        return 0.0

    def _update_kill_chain_snapshot(self, attack_type: str, event: dict) -> dict:
        stage = self._attack_type_to_stage(attack_type, event)
        now_ts = time.time()

        # Prune stale stages first to keep the campaign window bounded.
        cutoff = now_ts - self._KILL_CHAIN_ACTIVE_WINDOW_SECONDS
        stale_stages = [
            key
            for key, value in self._kill_chain_state.items()
            if float(value.get("last_seen_ts", 0.0)) < cutoff
        ]
        for stale in stale_stages:
            self._kill_chain_state.pop(stale, None)

        just_activated = False
        if stage:
            just_activated = stage not in self._kill_chain_state
            trigger_event = self._stage_trigger_label(attack_type, event)
            activated_at = str(event.get("timestamp", datetime.now(timezone.utc).isoformat()))
            self._kill_chain_state[stage] = {
                "stage": stage,
                "trigger_event": trigger_event,
                "activated_at": activated_at,
                "last_seen_ts": now_ts,
                "just_activated": just_activated,
            }

        ordered_active = []
        for stage_name in self._KILL_CHAIN_STAGE_ORDER:
            data = self._kill_chain_state.get(stage_name)
            if data:
                ordered_active.append(
                    {
                        "stage": stage_name,
                        "trigger_event": str(data.get("trigger_event", "Threat activity")),
                        "activated_at": str(data.get("activated_at", datetime.now(timezone.utc).isoformat())),
                        "just_activated": bool(data.get("just_activated", False)),
                    }
                )

        active_stage_names = [item["stage"] for item in ordered_active]
        campaign_active = len(active_stage_names) >= 3

        return {
            "stage_order": list(self._KILL_CHAIN_STAGE_ORDER),
            "active_stages": ordered_active,
            "active_stage_names": active_stage_names,
            "active_count": len(active_stage_names),
            "campaign_active": campaign_active,
        }

    @staticmethod
    def _attack_type_to_stage(attack_type: str, event: dict) -> str | None:
        # Breach scenario events carry an explicit breach_stage — honour it directly.
        breach_stage = str(event.get("breach_stage", "")).upper().strip()
        breach_map = {
            "RECONNAISSANCE":       "Reconnaissance",
            "INITIAL_ACCESS":       "Initial Access",
            "PERSISTENCE":          "Persistence",
            "PRIVILEGE_ESCALATION": "Privilege Escalation",
            "LATERAL_MOVEMENT":     "Lateral Movement",
            "EXFILTRATION":         "Exfiltration",
            "IMPACT":               "Exfiltration",
        }
        if breach_stage in breach_map:
            return breach_map[breach_stage]

        mapping = {
            "PORT_SCAN": "Reconnaissance",
            "PHISHING": "Initial Access",
            "SQL_INJECTION": "Initial Access",
            "ANOMALOUS_LOGIN": "Persistence",
            "PRIVILEGE_ESCALATION": "Privilege Escalation",
            "BRUTE_FORCE": "Credential Access",
            "LATERAL_MOVEMENT": "Lateral Movement",
            "C2_BEACON": "Command & Control",
            "DATA_EXFILTRATION": "Exfiltration",
        }

        mapped = mapping.get(attack_type)
        if mapped:
            return mapped

        event_type = str(event.get("event_type", "")).lower().strip()
        if event_type in {"privilege_escalation", "token_elevation", "sudo_abuse"}:
            return "Privilege Escalation"
        if event_type in {"lateral_movement", "remote_exec"}:
            return "Lateral Movement"

        return None

    @staticmethod
    def _stage_trigger_label(attack_type: str, event: dict) -> str:
        if attack_type == "PORT_SCAN":
            return "Port Scan"
        if attack_type == "PHISHING":
            return "Phishing"
        if attack_type == "SQL_INJECTION":
            return "SQL Injection"
        if attack_type == "ANOMALOUS_LOGIN":
            return "Anomalous Login"
        if attack_type == "PRIVILEGE_ESCALATION":
            return "Privilege Escalation"
        if attack_type == "BRUTE_FORCE":
            if int(event.get("destination_port", 0) or 0) == 22:
                return "SSH Brute Force"
            return "Brute Force"
        if attack_type == "LATERAL_MOVEMENT":
            return "Lateral Movement"
        if attack_type == "C2_BEACON":
            return "C2 Beacon"
        if attack_type == "DATA_EXFILTRATION":
            return "High Outbound Bytes"
        return str(attack_type).replace("_", " ").title()


intelligence_service = IntelligenceService(asset_criticality=0.5)
