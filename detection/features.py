from __future__ import annotations

import hashlib
import logging
import math
from collections import defaultdict, deque
from datetime import datetime
import time
from typing import Deque

logger = logging.getLogger(__name__)

# Feature vector length — asserted on every extraction so shape mismatches
# are caught immediately rather than silently corrupting the model.
FEATURE_COUNT = 15


class StreamingFeatureExtractor:
    """
    Extracts a 15-dimensional numeric feature vector from a raw security event
    dict in real time.  All per-IP / per-user state is maintained in-memory
    using sliding deques bounded by ``window_seconds``.

    Feature index map
    -----------------
     0  failed_login_flag          – 1.0 if this event is a failed login
     1  login_frequency_per_ip     – logins from this IP in the window
     2  unique_ports_per_ip        – distinct dest. ports from this IP in window
     3  bytes_transferred          – raw bytes (float)
     4  off_hours_flag             – 1.0 if outside 06:00–22:00
     5  new_ip_flag                – 1.0 on first-ever appearance of the IP
     6  event_type_encoded         – connection=0, request=1, login=2
     7  protocol_encoded           – TCP=0, UDP=1, HTTP=2, SSH=3
     8  request_entropy            – Shannon entropy of the payload string
     9  login_time_deviation       – |current_hour – user's mean login hour|
    10  ip_request_frequency       – all event types from this IP in window
    11  session_duration           – event field "session_duration" (0 if absent)
    12  user_agent_hash            – numeric hash of user-agent string (0–1)
    13  geo_distance_flag          – 1.0 if login from a previously unseen country
    14  failed_login_ratio         – failed / total login attempts per IP
    """

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds

        # ── existing state ────────────────────────────────────────────────
        # Timestamps of login events per source IP (for login_frequency).
        self._login_times: dict[str, Deque[float]] = defaultdict(deque)
        # (timestamp, port) per source IP (for unique_ports).
        self._port_times: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        # IPs seen at least once (for new_ip_flag).
        self._seen_ips: set[str] = set()

        # ── new state ─────────────────────────────────────────────────────
        # All event timestamps per IP (for ip_request_frequency).
        self._ip_event_times: dict[str, Deque[float]] = defaultdict(deque)
        # Login hour history per username (for login_time_deviation).
        self._user_login_hours: dict[str, Deque[float]] = defaultdict(deque)
        # (timestamp, status) per IP to compute failed_login_ratio.
        self._ip_login_attempts: dict[str, Deque[tuple[float, str]]] = defaultdict(deque)
        # Countries seen per source IP (for geo_distance_flag).
        self._ip_countries: dict[str, set[str]] = defaultdict(set)

        # ── encoding maps ─────────────────────────────────────────────────
        self._event_type_map = {"connection": 0.0, "request": 1.0, "login": 2.0}
        self._protocol_map = {"TCP": 0.0, "UDP": 1.0, "HTTP": 2.0, "SSH": 3.0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, event: dict) -> list[float]:
        now = time.time()

        # ── parse event fields (safe defaults) ────────────────────────────
        source_ip    = str(event.get("source_ip") or "0.0.0.0")
        dest_port    = int(event.get("destination_port") or 0)
        event_type   = str(event.get("event_type") or "connection")
        protocol     = str(event.get("protocol") or "TCP")
        status       = str(event.get("status") or "success")
        bytes_xfer   = float(event.get("bytes_transferred") or 0.0)
        timestamp    = str(event.get("timestamp") or "")
        payload      = str(event.get("payload") or "")
        username     = str(event.get("username") or "")
        user_agent   = str(event.get("user_agent") or "")
        country      = str(event.get("country") or "")
        session_dur  = float(event.get("session_duration") or 0.0)

        # ── f0  failed_login_flag ─────────────────────────────────────────
        failed_login_flag = 1.0 if event_type == "login" and status == "failure" else 0.0

        # ── f1  login_frequency_per_ip ────────────────────────────────────
        login_frequency_per_ip = self._update_login_frequency(source_ip, event_type, now)

        # ── f2  unique_ports_per_ip ───────────────────────────────────────
        unique_ports_per_ip = self._update_unique_ports(source_ip, dest_port, now)

        # ── f3  bytes_transferred ─────────────────────────────────────────
        # Normalise to kilobytes to keep the value in a reasonable range.
        bytes_norm = bytes_xfer / 1024.0

        # ── f4  off_hours_flag ────────────────────────────────────────────
        off_hours_flag = self._off_hours_flag(timestamp)

        # ── f5  new_ip_flag ───────────────────────────────────────────────
        new_ip_flag = 0.0
        if source_ip not in self._seen_ips:
            new_ip_flag = 1.0
            self._seen_ips.add(source_ip)

        # ── f6  event_type_encoded ────────────────────────────────────────
        event_type_encoded = self._event_type_map.get(event_type, 0.0)

        # ── f7  protocol_encoded ──────────────────────────────────────────
        protocol_encoded = self._protocol_map.get(protocol, 0.0)

        # ── f8  request_entropy ───────────────────────────────────────────
        # Shannon entropy of the payload string (0.0 when payload is empty).
        request_entropy = _shannon_entropy(payload)

        # ── f9  login_time_deviation ──────────────────────────────────────
        login_time_deviation = self._login_time_deviation(username, timestamp, event_type)

        # ── f10  ip_request_frequency ─────────────────────────────────────
        # All event types (not just logins) from this IP in the window.
        ip_request_frequency = self._update_ip_request_frequency(source_ip, now)

        # ── f11  session_duration ─────────────────────────────────────────
        # Normalise to minutes.
        session_duration = session_dur / 60.0

        # ── f12  user_agent_hash ──────────────────────────────────────────
        user_agent_hash = _ua_hash(user_agent)

        # ── f13  geo_distance_flag ────────────────────────────────────────
        geo_distance_flag = self._geo_distance_flag(source_ip, country, event_type)

        # ── f14  failed_login_ratio ───────────────────────────────────────
        failed_login_ratio = self._update_failed_login_ratio(source_ip, event_type, status, now)

        vector = [
            failed_login_flag,       # 0
            login_frequency_per_ip,  # 1
            unique_ports_per_ip,     # 2
            bytes_norm,              # 3
            off_hours_flag,          # 4
            new_ip_flag,             # 5
            event_type_encoded,      # 6
            protocol_encoded,        # 7
            request_entropy,         # 8
            login_time_deviation,    # 9
            ip_request_frequency,    # 10
            session_duration,        # 11
            user_agent_hash,         # 12
            geo_distance_flag,       # 13
            failed_login_ratio,      # 14
        ]

        assert len(vector) == FEATURE_COUNT, (
            f"Feature vector length mismatch: expected {FEATURE_COUNT}, got {len(vector)}"
        )
        logger.debug("Feature vector length: %d", len(vector))

        return vector

    # ------------------------------------------------------------------
    # State-update helpers
    # ------------------------------------------------------------------

    def _update_login_frequency(self, source_ip: str, event_type: str, now: float) -> float:
        dq = self._login_times[source_ip]
        if event_type == "login":
            dq.append(now)
        self._prune(dq, now)
        return float(len(dq))

    def _update_unique_ports(self, source_ip: str, dest_port: int, now: float) -> float:
        dq = self._port_times[source_ip]
        dq.append((now, dest_port))
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return float(len({p for _, p in dq}))

    def _update_ip_request_frequency(self, source_ip: str, now: float) -> float:
        dq = self._ip_event_times[source_ip]
        dq.append(now)
        self._prune(dq, now)
        return float(len(dq))

    def _login_time_deviation(self, username: str, timestamp: str, event_type: str) -> float:
        if event_type != "login" or not timestamp or not username:
            return 0.0
        try:
            hour = float(datetime.fromisoformat(timestamp).hour)
        except ValueError:
            return 0.0

        dq = self._user_login_hours[username]
        dq.append(hour)
        # Keep at most 50 historical hours to bound memory.
        while len(dq) > 50:
            dq.popleft()

        if len(dq) < 2:
            return 0.0

        mean_hour = sum(dq) / len(dq)
        # Normalise deviation to [0, 1] — max possible circular distance is 12 h.
        deviation = abs(hour - mean_hour)
        # Handle wrap-around (e.g. 23 vs 1).
        if deviation > 12.0:
            deviation = 24.0 - deviation
        return round(deviation / 12.0, 4)

    def _update_failed_login_ratio(
        self, source_ip: str, event_type: str, status: str, now: float
    ) -> float:
        if event_type != "login":
            return 0.0

        dq = self._ip_login_attempts[source_ip]
        dq.append((now, status))
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        total = len(dq)
        if total == 0:
            return 0.0
        failed = sum(1 for _, s in dq if s == "failure")
        return round(failed / total, 4)

    def _geo_distance_flag(self, source_ip: str, country: str, event_type: str) -> float:
        if event_type != "login" or not country:
            return 0.0
        seen = self._ip_countries[source_ip]
        if country not in seen:
            seen.add(country)
            # Only flag as anomalous if the IP has been seen before
            # (first-ever login from an IP is already captured by new_ip_flag).
            if len(seen) > 1:
                return 1.0
        return 0.0

    # ------------------------------------------------------------------
    # Pure helpers (no state)
    # ------------------------------------------------------------------

    def _off_hours_flag(self, timestamp: str) -> float:
        if not timestamp:
            return 0.0
        try:
            hour = datetime.fromisoformat(timestamp).hour
        except ValueError:
            return 0.0
        return 1.0 if hour < 6 or hour >= 22 else 0.0

    def _prune(self, dq: Deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()


# ------------------------------------------------------------------
# Module-level pure helpers
# ------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Normalised Shannon entropy of *text* in [0.0, 1.0]."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    # Max entropy for a string of length n over printable ASCII (~95 chars) is
    # log2(95) ≈ 6.57 bits.  We cap at log2(256) = 8.0 for safety.
    return round(min(entropy / 8.0, 1.0), 4)


def _ua_hash(user_agent: str) -> float:
    """Map a user-agent string to a stable float in [0.0, 1.0]."""
    if not user_agent:
        return 0.0
    digest = int(hashlib.md5(user_agent.encode(), usedforsecurity=False).hexdigest(), 16)
    return round((digest % 10_000) / 10_000.0, 4)
