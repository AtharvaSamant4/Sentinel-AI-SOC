from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
import threading
import time
from typing import Deque


class EventClassifier:
    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._failed_logins: dict[str, Deque[float]] = defaultdict(deque)
        self._port_touches: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        self._seen_ips: set[str] = set()
        self._lock = threading.Lock()

        self._failed_login_spike_threshold = 8
        self._port_scan_threshold = 16
        self._high_bytes_threshold = 120000

    def classify_event(self, event: dict) -> dict:
        source_ip = str(event.get("source_ip", "0.0.0.0"))
        event_type = str(event.get("event_type", "connection"))
        status = str(event.get("status", "success"))
        destination_port = int(event.get("destination_port", 0))
        bytes_transferred = int(event.get("bytes_transferred", 0))
        payload = str(event.get("payload", ""))
        timestamp = str(event.get("timestamp", ""))
        phishing_signal = bool(event.get("phishing_signal", False))
        c2_signal = bool(event.get("c2_signal", False))

        now = time.time()
        off_hours = self._is_off_hours(timestamp)

        with self._lock:
            new_ip = source_ip not in self._seen_ips
            if new_ip:
                self._seen_ips.add(source_ip)

            failed_login_count = self._update_failed_login_count(source_ip, event_type, status, now)
            unique_ports = self._update_unique_ports(source_ip, destination_port, now)

        # Honour explicit attack_type tags injected by breach/demo scenarios.
        # This must run before any heuristic checks so the tag is never overridden.
        explicit_type = str(event.get("attack_type", "")).upper().strip()
        _EXPLICIT_MAP: dict[str, tuple[str, float]] = {
            "PRIVILEGE_ESCALATION": ("PRIVILEGE_ESCALATION", 0.96),
            "LATERAL_MOVEMENT":     ("LATERAL_MOVEMENT",     0.90),
            "DATA_EXFILTRATION":    ("DATA_EXFILTRATION",    0.95),
            "BRUTE_FORCE":          ("BRUTE_FORCE",          1.00),
            "PORT_SCAN":            ("PORT_SCAN",            0.95),
            "C2_BEACON":            ("C2_BEACON",            0.93),
            "SQL_INJECTION":        ("SQL_INJECTION",        1.00),
            "PHISHING":             ("PHISHING",             0.92),
        }
        if explicit_type in _EXPLICIT_MAP and bool(event.get("is_attack")):
            mapped_type, weight = _EXPLICIT_MAP[explicit_type]
            return {
                "type": mapped_type,
                "severity_weight": weight,
                "signals": {"explicit_tag": True},
            }

        if payload and self._looks_like_sql_injection(payload):
            return {
                "type": "SQL_INJECTION",
                "severity_weight": 1.00,
                "signals": {"payload_indicator": True},
            }

        if self._looks_like_privilege_escalation(event_type, payload):
            return {
                "type": "PRIVILEGE_ESCALATION",
                "severity_weight": 0.96,
                "signals": {"privilege_signal": True},
            }

        if self._looks_like_lateral_movement(event_type, payload):
            return {
                "type": "LATERAL_MOVEMENT",
                "severity_weight": 0.9,
                "signals": {"lateral_signal": True},
            }

        if phishing_signal:
            # Use NLP confidence when available (set by demo scenario or API),
            # otherwise fall back to the raw boolean flag.
            nlp_confidence: float = float(event.get("phishing_confidence") or 0.85)
            nlp_method: str = str(event.get("phishing_nlp_method") or "flag")
            return {
                "type": "PHISHING",
                "severity_weight": 0.92,
                "signals": {
                    "phishing_signal": True,
                    "nlp_confidence": nlp_confidence,
                    "nlp_method": nlp_method,
                },
            }

        if c2_signal:
            return {
                "type": "C2_BEACON",
                "severity_weight": 0.93,
                "signals": {
                    "c2_signal": True,
                    "beacon_interval_seconds": int(event.get("beacon_interval_seconds", 0) or 0),
                },
            }

        if failed_login_count >= self._failed_login_spike_threshold:
            return {
                "type": "BRUTE_FORCE",
                "severity_weight": 1.00,
                "signals": {"failed_login_count": failed_login_count},
            }

        if unique_ports >= self._port_scan_threshold:
            return {
                "type": "PORT_SCAN",
                "severity_weight": 0.95,
                "signals": {"unique_ports": unique_ports},
            }

        if (
            not bool(event.get("is_attack"))
            and event_type == "login"
            and status == "success"
            and off_hours
            and new_ip
        ):
            return {
                "type": "ANOMALOUS_LOGIN",
                "severity_weight": 0.55,
                "signals": {"off_hours": off_hours, "new_ip": new_ip},
            }

        if event.get("is_attack") and event_type == "login" and status == "failure":
            return {
                "type": "BRUTE_FORCE",
                "severity_weight": 0.95,
                "signals": {"failed_login_count": failed_login_count},
            }

        if event.get("is_attack") and event_type == "connection":
            return {
                "type": "PORT_SCAN",
                "severity_weight": 0.90,
                "signals": {"unique_ports": unique_ports},
            }

        if bytes_transferred >= self._high_bytes_threshold:
            return {
                "type": "DATA_EXFILTRATION",
                "severity_weight": 0.95,
                "signals": {"bytes_transferred": bytes_transferred},
            }

        return {"type": "NORMAL", "severity_weight": 0.15, "signals": {}}

    def _update_failed_login_count(self, source_ip: str, event_type: str, status: str, now: float) -> int:
        login_deque = self._failed_logins[source_ip]
        if event_type == "login" and status == "failure":
            login_deque.append(now)

        cutoff = now - self.window_seconds
        while login_deque and login_deque[0] < cutoff:
            login_deque.popleft()

        return len(login_deque)

    def _update_unique_ports(self, source_ip: str, destination_port: int, now: float) -> int:
        port_deque = self._port_touches[source_ip]
        port_deque.append((now, destination_port))

        cutoff = now - self.window_seconds
        while port_deque and port_deque[0][0] < cutoff:
            port_deque.popleft()

        return len({port for _, port in port_deque})

    @staticmethod
    def _looks_like_sql_injection(payload: str) -> bool:
        lowered = payload.lower()
        indicators = [
            "' or 1=1",
            "union select",
            "drop table",
            "--",
            ";--",
            " or ",
        ]
        return any(indicator in lowered for indicator in indicators)

    @staticmethod
    def _looks_like_privilege_escalation(event_type: str, payload: str) -> bool:
        normalized = event_type.lower().strip()
        if normalized in {"privilege_escalation", "token_elevation", "sudo_abuse"}:
            return True

        lowered = payload.lower()
        indicators = ["sudo su", "token::elevate", "setuid", "runas /user:administrator"]
        return any(indicator in lowered for indicator in indicators)

    @staticmethod
    def _looks_like_lateral_movement(event_type: str, payload: str) -> bool:
        normalized = event_type.lower().strip()
        if normalized in {"lateral_movement", "remote_exec"}:
            return True

        lowered = payload.lower()
        indicators = ["psexec", "wmic /node", "smb lateral", "remote service creation"]
        return any(indicator in lowered for indicator in indicators)

    @staticmethod
    def _is_off_hours(timestamp: str) -> bool:
        if not timestamp:
            return False
        try:
            hour = datetime.fromisoformat(timestamp).hour
        except ValueError:
            return False
        return hour < 6 or hour >= 22
