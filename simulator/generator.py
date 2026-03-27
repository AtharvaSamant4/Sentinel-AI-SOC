from __future__ import annotations

import asyncio
from collections import Counter, deque
from datetime import datetime, timezone
import os
import random
import time
from typing import Optional

from analyst.service import analyst_service
from detection.service import detection_service
from detection.correlator import check_correlation
from intelligence.service import intelligence_service
from response.actions import is_ip_blocked, normalize_ip
from response.service import response_service
from simulator.attack_patterns import (
    EventContext,
    generate_brute_force_attack,
    generate_c2_beacon_attack,
    generate_normal_event,
    generate_port_scan,
    generate_sql_injection_attack,
)


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


class EventSimulator:
    _CATEGORY_RECENCY_SECONDS = 90

    def __init__(self, attack_ratio: float = 0.2) -> None:
        self.attack_ratio = attack_ratio
        self.context = EventContext()
        self._category_generators = {
            "Brute Force": generate_brute_force_attack,
            "Phishing": self._generate_phishing,
            "Port Scan": generate_port_scan,
            "SQL Injection": generate_sql_injection_attack,
            "C2 Beacon": generate_c2_beacon_attack,
        }
        self._category_weights = {
            "Brute Force": 0.24,
            "Phishing": 0.2,
            "Port Scan": 0.24,
            "SQL Injection": 0.16,
            "C2 Beacon": 0.16,
        }
        self.category_last_fired: dict[str, float] = {
            "Brute Force": 0.0,
            "Phishing": 0.0,
            "Port Scan": 0.0,
            "SQL Injection": 0.0,
            "C2 Beacon": 0.0,
        }

    def generate_event(self, attack_mode: Optional[str] = None) -> dict:
        mode = (attack_mode or "mixed").lower()

        if mode == "bruteforce":
            return generate_brute_force_attack(self.context)
        if mode == "portscan":
            return generate_port_scan(self.context)
        if mode == "sqlinjection":
            return generate_sql_injection_attack(self.context)
        if mode == "c2beacon":
            return generate_c2_beacon_attack(self.context)
        if mode == "phishing":
            return self._generate_phishing(self.context)

        if random.random() < self.attack_ratio:
            return self._generate_weighted_attack()
        return generate_normal_event(self.context)

    def _generate_weighted_attack(self) -> dict:
        now = time.time()

        categories = list(self._category_weights.keys())
        stale_categories = [
            category
            for category in categories
            if now - float(self.category_last_fired.get(category, 0.0)) > self._CATEGORY_RECENCY_SECONDS
        ]

        # 70% chance to fire a stale category (split equally), 30% weighted baseline random.
        use_stale_path = bool(stale_categories) and random.random() < 0.7
        if use_stale_path:
            category = random.choice(stale_categories)
        else:
            weights = [self._category_weights[category] for category in categories]
            category = random.choices(categories, weights=weights, k=1)[0]

        generated = self._category_generators[category](self.context)
        self.category_last_fired[category] = now
        generated["attack_tag"] = category
        return generated

    @staticmethod
    def _generate_phishing(context: EventContext) -> dict:
        country = context.next_hostile_country()
        source_ip = context.source_ip_for_country(country)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "destination_ip": random.choice(context.normal_destination_ips),
            "destination_port": 443,
            "protocol": "HTTP",
            "event_type": "request",
            "username": random.choice(context.usernames),
            "status": "failure",
            "bytes_transferred": random.randint(30000, 110000),
            "country": country,
            "is_attack": True,
            "phishing_signal": True,
            "payload": "Urgent invoice verification needed. Click secure link now.",
            "attack_tag": "Phishing",
        }
        return event


class EventStreamService:

    def __init__(
        self,
        target_eps: float = 0.4,
        subscriber_queue_size: int = 5000,
        ingest_queue_size: int = 15000,
        scoring_batch_size: int = 10,
    ) -> None:
        self.target_eps = target_eps
        self.subscriber_queue_size = subscriber_queue_size
        self.ingest_queue_size = ingest_queue_size
        self.scoring_batch_size = scoring_batch_size
        auto_attacks_enabled = os.getenv("SENTINEL_AUTO_ATTACKS", "false").strip().lower() == "true"
        self._simulator = EventSimulator(attack_ratio=0.08 if auto_attacks_enabled else 0.0)
        self._subscribers: set[asyncio.Queue] = set()
        self._ingest_queue: asyncio.Queue = asyncio.Queue(maxsize=self.ingest_queue_size)
        self._producer_task: Optional[asyncio.Task] = None
        self._scorer_task: Optional[asyncio.Task] = None
        self._correlator_task: Optional[asyncio.Task] = None
        self._running = False
        self._suspend_normal_until = 0.0
        self._blocked_attempt_log_cache: dict[str, float] = {}
        self._event_count = 0
        self._recent_high_threat_times: deque[float] = deque()
        self._recent_geo_samples: deque[tuple[float, str]] = deque()
        self._event_history: deque[dict] = deque(maxlen=4000)
        self._last_correlation_alert_ts = 0.0
        self.dwell_tracker: dict[str, dict] = {}

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._producer_task = asyncio.create_task(self._producer_loop(), name="event-producer")
        self._scorer_task = asyncio.create_task(self._scorer_loop(), name="event-scorer")
        self._correlator_task = asyncio.create_task(self._correlator_loop(), name="event-correlator")
        print(f"[simulator] started with target rate={self.target_eps} events/sec")

    async def stop(self) -> None:
        self._running = False
        if self._producer_task:
            self._producer_task.cancel()
            try:
                await self._producer_task
            except asyncio.CancelledError:
                pass
            self._producer_task = None
        if self._scorer_task:
            self._scorer_task.cancel()
            try:
                await self._scorer_task
            except asyncio.CancelledError:
                pass
            self._scorer_task = None
        if self._correlator_task:
            self._correlator_task.cancel()
            try:
                await self._correlator_task
            except asyncio.CancelledError:
                pass
            self._correlator_task = None
        print("[simulator] stopped")

    async def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.subscriber_queue_size)
        self._subscribers.add(queue)
        print(f"[websocket] subscriber connected. active={len(self._subscribers)}")
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)
        print(f"[websocket] subscriber disconnected. active={len(self._subscribers)}")

    async def inject_event(self, event: dict) -> bool:
        try:
            self._ingest_queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            return False

    def suspend_background(self, duration_seconds: float) -> None:
        until = time.perf_counter() + max(duration_seconds, 0.0)
        if until > self._suspend_normal_until:
            self._suspend_normal_until = until

    async def _publish(self, event: dict) -> None:
        if str(event.get("type", "")) != "response_fired":
            self._event_history.append(dict(event))

        if not self._subscribers:
            return

        for queue in tuple(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop when a client cannot keep up to preserve pipeline throughput.
                continue

    def update_dwell_tracker(self, event: dict) -> None:
        source_ip = normalize_ip(str(event.get("source_ip", "")))
        if not source_ip:
            return

        now = datetime.now(timezone.utc)
        attack_type = str(
            event.get("attack_type")
            or event.get("attempted_attack_type")
            or event.get("attack_tag")
            or "UNKNOWN"
        ).strip().upper().replace(" ", "_")

        entry = self.dwell_tracker.get(source_ip)
        if not entry:
            self.dwell_tracker[source_ip] = {
                "first_seen": now,
                "last_seen": now,
                "event_count": 1,
                "attack_types": {attack_type},
            }
            return

        entry["last_seen"] = now
        entry["event_count"] = int(entry.get("event_count", 0)) + 1
        attack_types = entry.get("attack_types")
        if not isinstance(attack_types, set):
            attack_types = set()
        attack_types.add(attack_type)
        entry["attack_types"] = attack_types

    def attach_dwell_fields(self, threat: dict) -> dict:
        source_ip = normalize_ip(str(threat.get("source_ip", "")))
        if not source_ip:
            threat["dwell_seconds"] = 0
            threat["event_count"] = int(threat.get("event_count", 0) or 0)
            threat["is_persistent"] = False
            return threat

        threat["source_ip"] = source_ip
        entry = self.dwell_tracker.get(source_ip)
        if not entry:
            threat["dwell_seconds"] = 0
            threat["event_count"] = int(threat.get("event_count", 0) or 0)
            threat["is_persistent"] = False
            return threat

        first_seen = entry.get("first_seen")
        last_seen = entry.get("last_seen")
        if not isinstance(first_seen, datetime) or not isinstance(last_seen, datetime):
            threat["dwell_seconds"] = 0
            threat["event_count"] = int(entry.get("event_count", 0) or 0)
            threat["is_persistent"] = False
            return threat

        dwell_seconds = max(0, int((last_seen - first_seen).total_seconds()))
        event_count = int(entry.get("event_count", 0) or 0)
        threat["dwell_seconds"] = dwell_seconds
        threat["event_count"] = event_count
        threat["is_persistent"] = dwell_seconds > 1800
        return threat

    def record_live_context(self, threat: dict) -> None:
        self._record_live_context(threat)

    def snapshot_live_context(self) -> dict:
        return self._snapshot_live_context()

    def query_event_history(self, filter_obj: dict) -> list[dict]:
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
        matched: list[dict] = []

        for event in reversed(self._event_history):
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
            if len(matched) >= 300:
                break

        return matched

    def get_recent_events(self, limit: int = 400) -> list[dict]:
        bounded = max(1, min(int(limit), len(self._event_history) or 1))
        return [dict(event) for event in list(self._event_history)[-bounded:]]

    def _events_in_last_minutes(self, now: datetime, minutes: int) -> list[dict]:
        window_seconds = max(1, minutes) * 60
        return [
            dict(event)
            for event in self._event_history
            if self._within_window(event, now, window_seconds)
        ]

    @staticmethod
    def _within_window(event: dict, now: datetime, window_seconds: int) -> bool:
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
    def _matches_severity(event: dict, severity: str) -> bool:
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
    def _matches_tag(event: dict, tag: str) -> bool:
        attack_type = str(event.get("attack_type", "")).lower().replace("_", " ")
        attack_tag = str(event.get("attack_tag", "")).lower()
        tag_value = tag.replace("_", " ")
        return tag_value in attack_type or tag_value in attack_tag

    @staticmethod
    def _matches_geo(event: dict, geo_country: str) -> bool:
        country = str(event.get("country", "")).upper()
        geo = geo_country.lower()
        country_aliases = {
            "russia": {"RU", "RUSSIA"},
            "china": {"CN", "CHINA"},
            "iran": {"IR", "IRAN"},
            "north korea": {"KP", "NORTH KOREA"},
            "united states": {"US", "USA", "UNITED STATES"},
            "brazil": {"BR", "BRAZIL"},
        }
        allowed = country_aliases.get(geo, {geo_country.upper()})
        return country in allowed

    @staticmethod
    def _matches_keyword(event: dict, keyword: str) -> bool:
        haystack = " ".join(
            [
                str(event.get("event_type", "")),
                str(event.get("status", "")),
                str(event.get("attack_type", "")),
                str(event.get("source_ip", "")),
                str(event.get("username", "")),
                str(event.get("reason", "")),
                str(event.get("analysis", "")),
            ]
        ).lower()

        token = str(keyword or "").lower().strip()
        if not token:
            return True

        if token in {"failed", "failure", "fail"}:
            return any(variant in haystack for variant in ("failed", "failure", "fail"))

        return token in haystack

    async def _producer_loop(self) -> None:
        interval = max(1.0 / max(float(self.target_eps), 0.001), 0.02)
        next_tick = time.perf_counter()

        try:
            while self._running:
                if time.perf_counter() < self._suspend_normal_until:
                    await asyncio.sleep(0.1)
                    continue

                event = self._simulator.generate_event()
                try:
                    self._ingest_queue.put_nowait(event)
                except asyncio.QueueFull:
                    # Prefer dropping under overload over blocking the event loop.
                    pass
                next_tick += interval
                delay = next_tick - time.perf_counter()

                if delay > 0:
                    await asyncio.sleep(delay)
                else:
                    if delay < -1.0:
                        next_tick = time.perf_counter()
        except asyncio.CancelledError:
            raise

    async def _scorer_loop(self) -> None:
        try:
            while self._running:
                first_event = await self._ingest_queue.get()
                batch = [first_event]

                while len(batch) < self.scoring_batch_size:
                    try:
                        batch.append(self._ingest_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                try:
                    eligible_batch: list[dict] = []
                    for event in batch:
                        source_ip = normalize_ip(str(event.get("source_ip", "")))
                        event["source_ip"] = source_ip or str(event.get("source_ip", ""))
                        self.update_dwell_tracker(event)
                        is_attack = bool(event.get("is_attack", False))
                        if is_attack and is_ip_blocked(source_ip):
                            blocked_event = self._blocked_attempt_event(event)
                            blocked_event = self.attach_dwell_fields(blocked_event)
                            self.record_live_context(blocked_event)
                            blocked_event["live_context"] = self.snapshot_live_context()
                            blocked_event = await analyst_service.enrich_threat(blocked_event)
                            await self._publish(blocked_event)
                            self._log_blocked_attempt(source_ip)
                            continue
                        eligible_batch.append(event)

                    if not eligible_batch:
                        continue

                    enriched_batch = detection_service.enrich_events(eligible_batch)
                    threats = intelligence_service.build_threat_objects(enriched_batch)
                    for threat in threats:
                        threat = self.attach_dwell_fields(threat)
                        self.record_live_context(threat)
                        threat["live_context"] = self.snapshot_live_context()
                        threat = await analyst_service.enrich_threat(threat)
                        response = response_service.handle_threat(threat)
                        threat["actions"] = response["actions_executed"]
                        counterfactual_trigger = next(
                            (
                                action.get("counterfactual_trigger")
                                for action in threat["actions"]
                                if isinstance(action, dict)
                                and isinstance(action.get("counterfactual_trigger"), dict)
                            ),
                            None,
                        )
                        if counterfactual_trigger:
                            counterfactual_threat = {
                                **threat,
                                "attack_type": str(counterfactual_trigger.get("attack_type", threat.get("attack_type", "UNKNOWN"))),
                                "risk_score": int(counterfactual_trigger.get("risk_score", threat.get("risk_score", 0)) or 0),
                                "destination_ip": str(counterfactual_trigger.get("target_asset", threat.get("destination_ip", "unknown"))).split(":")[0],
                            }
                            threat["counterfactual"] = {
                                "title": "⚡ If SENTINEL hadn't responded...",
                                "text": await analyst_service.generate_counterfactual(
                                    counterfactual_threat,
                                    str(counterfactual_trigger.get("ip", threat.get("source_ip", "unknown"))),
                                ),
                                "badge": "simulated",
                            }
                        await self._publish(threat)
                        response_event = await self._response_fired_event(threat, threat["actions"])
                        if response_event:
                            await self._publish(response_event)
                except Exception as exc:
                    for event in batch:
                        await self._publish(
                            {
                                "timestamp": str(event.get("timestamp", datetime.now(timezone.utc).isoformat())),
                                "source_ip": str(event.get("source_ip", "unknown")),
                                "event_type": str(event.get("event_type", "connection")),
                                "status": str(event.get("status", "failure")),
                                "attack_type": "SYSTEM",
                                "anomaly_score": 0.0,
                                "risk_score": 0,
                                "severity": "LOW",
                                "mitre": {"technique": "N/A", "tactic": "None"},
                                "reason": "Data temporarily unavailable",
                                "analysis": f"pipeline_error: {exc}",
                                "actions": [],
                            }
                        )
        except asyncio.CancelledError:
            raise

    async def _correlator_loop(self) -> None:
        try:
            while self._running:
                await asyncio.sleep(60)
                if not self._running:
                    break

                now = datetime.now(timezone.utc)
                recent_events = self._events_in_last_minutes(now, 10)
                correlation = check_correlation(recent_events, window_minutes=10)
                if not correlation.get("triggered"):
                    continue

                now_ts = time.time()
                if now_ts - self._last_correlation_alert_ts < 300:
                    continue

                vector_count = int(correlation.get("vector_count", 0) or 0)
                attack_types = [str(item) for item in correlation.get("attack_types", [])]
                source_countries = [str(item) for item in correlation.get("source_countries", [])]
                confidence = str(correlation.get("confidence", "MEDIUM"))

                attack_type_text = ", ".join(attack_types) if attack_types else "Unknown"
                country_text = ", ".join(source_countries) if source_countries else "Unknown"
                analyst_message = (
                    "ALERT: SENTINEL has correlated "
                    f"{vector_count} simultaneous attack vectors in the last 10 minutes: {attack_type_text}. "
                    f"Source countries: {country_text}.\n"
                    "Is this a coordinated campaign? What is the likely objective and \n"
                    "primary target? What immediate action should we take? \n"
                    "Answer in 4 sentences - be direct and specific."
                )

                reference = recent_events[-1] if recent_events else {}
                assessment = await analyst_service.generate_manual_analysis(reference, analyst_message)

                coordinated_event = {
                    "type": "campaign_detected",
                    "timestamp": now.isoformat(),
                    "source_ip": "campaign-monitor",
                    "event_type": "campaign",
                    "status": "detected",
                    "attack_type": "CAMPAIGN_DETECTED",
                    "anomaly_score": 1.0,
                    "risk_score": 100,
                    "severity": "CRITICAL",
                    "reason": "COORDINATED ATTACK CAMPAIGN DETECTED",
                    "analysis": assessment,
                    "actions": [],
                    "attack_types": attack_types,
                    "vector_count": vector_count,
                    "source_countries": source_countries,
                    "confidence": confidence,
                }

                await self._publish(coordinated_event)
                self._last_correlation_alert_ts = now_ts
                print(
                    "[correlation] coordinated campaign detected: "
                    f"vectors={vector_count} set={','.join(attack_types)}"
                )
        except asyncio.CancelledError:
            raise

    @staticmethod
    def _blocked_attempt_event(event: dict) -> dict:
        attempted_attack_type = str(
            event.get("attack_type")
            or event.get("attack_tag")
            or ""
        ).strip().upper().replace(" ", "_")

        if attempted_attack_type == "BRUTEFORCE":
            attempted_attack_type = "BRUTE_FORCE"
        elif attempted_attack_type == "PORTSCAN":
            attempted_attack_type = "PORT_SCAN"

        if not attempted_attack_type:
            event_type = str(event.get("event_type", "")).strip().lower()
            if event_type == "login":
                attempted_attack_type = "BRUTE_FORCE"
            elif bool(event.get("phishing_signal")):
                attempted_attack_type = "PHISHING"
            elif event_type == "connection":
                attempted_attack_type = "PORT_SCAN"
            else:
                attempted_attack_type = "UNKNOWN"

        return {
            "timestamp": str(event.get("timestamp", datetime.now(timezone.utc).isoformat())),
            "source_ip": str(event.get("source_ip", "unknown")),
            "destination_ip": str(event.get("destination_ip", "unknown")),
            "destination_port": int(event.get("destination_port", 0) or 0),
            "protocol": str(event.get("protocol", "TCP")),
            "event_type": str(event.get("event_type", "connection")),
            "status": "blocked",
            "username": event.get("username") or "unknown",
            "country": str(event.get("country", "XX")),
            "is_attack": True,
            "attack_type": "BLOCKED_SOURCE",
            "attempted_attack_type": attempted_attack_type,
            "anomaly_score": 1.0,
            "risk_score": 99,
            "severity": "CRITICAL",
            "mitre": {"technique": "T1562", "tactic": "Defense Evasion"},
            "reason": (
                "Attack attempt blocked: source IP already blocked by SOC response "
                f"(attempted {attempted_attack_type})"
            ),
            "analysis": "Source IP is blocked. Further attack traffic denied.",
            "actions": [],
        }

    @staticmethod
    def _format_response_action_line(action: dict) -> str | None:
        status = str(action.get("status", "")).lower()
        if status != "success":
            return None

        action_name = str(action.get("action", "")).strip().lower()
        target = str(action.get("target", "unknown")).strip() or "unknown"

        if action_name == "block_ip":
            return f"IP {target} blocked"
        if action_name == "lock_account":
            return f"Account {target} locked 30min"
        if action_name in {"create_ticket", "create_alert"}:
            ticket_id = target.replace("act-", "")
            return f"Ticket #{ticket_id} created"
        return None

    async def _response_fired_event(self, threat: dict, actions: list[dict]) -> dict | None:
        # Group actions from the same playbook execution into one toast payload.
        await asyncio.sleep(0.5)
        action_lines = [line for line in (self._format_response_action_line(action) for action in actions) if line]
        if not action_lines:
            return None

        return {
            "type": "response_fired",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": str(threat.get("source_ip", "unknown")),
            "attack_type": str(threat.get("attack_type", "UNKNOWN")),
            "severity": str(threat.get("severity", "LOW")),
            "actions": action_lines,
            "counterfactual": threat.get("counterfactual"),
        }

    def _log_blocked_attempt(self, source_ip: str) -> None:
        now = time.time()
        last = self._blocked_attempt_log_cache.get(source_ip, 0.0)
        if now - last < 3.0:
            return
        self._blocked_attempt_log_cache[source_ip] = now
        print(f"[response] blocked attempt denied from {source_ip}")

    def _record_live_context(self, threat: dict) -> None:
        now = time.time()
        self._event_count += 1

        risk_score = float(threat.get("risk_score", 0) or 0)
        if risk_score >= 75:
            self._recent_high_threat_times.append(now)

        country = str(threat.get("country", "XX")).upper()
        self._recent_geo_samples.append((now, country))

        cutoff_threats = now - 60
        while self._recent_high_threat_times and self._recent_high_threat_times[0] < cutoff_threats:
            self._recent_high_threat_times.popleft()

        cutoff_geo = now - 120
        while self._recent_geo_samples and self._recent_geo_samples[0][0] < cutoff_geo:
            self._recent_geo_samples.popleft()

    def _snapshot_live_context(self) -> dict:
        geo_counts = Counter(country for _, country in self._recent_geo_samples)
        top_geo = dict(geo_counts.most_common(5))
        persistent_threats: list[dict] = []
        for source_ip, entry in self.dwell_tracker.items():
            first_seen = entry.get("first_seen")
            last_seen = entry.get("last_seen")
            if not isinstance(first_seen, datetime) or not isinstance(last_seen, datetime):
                continue
            dwell_seconds = max(0, int((last_seen - first_seen).total_seconds()))
            if dwell_seconds <= 1800:
                continue
            persistent_threats.append(
                {
                    "source_ip": source_ip,
                    "duration": self._format_dwell_duration(dwell_seconds),
                    "dwell_seconds": dwell_seconds,
                    "event_count": int(entry.get("event_count", 0) or 0),
                }
            )

        persistent_threats.sort(key=lambda item: int(item.get("dwell_seconds", 0)), reverse=True)
        return {
            "event_count": self._event_count,
            "active_threats": len(self._recent_high_threat_times),
            "geo_data": top_geo,
            "persistent_threats": persistent_threats[:12],
        }

    @staticmethod
    def _format_dwell_duration(dwell_seconds: int) -> str:
        total_minutes = max(0, dwell_seconds // 60)
        if total_minutes < 1:
            return "< 1 min"
        if total_minutes < 60:
            return f"{total_minutes} min"
        hours = total_minutes // 60
        minutes = total_minutes % 60
        return f"{hours}h {minutes:02d}m"


event_stream_service = EventStreamService(
    target_eps=_env_float("SENTINEL_TARGET_EPS", 0.4)
)
