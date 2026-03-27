from __future__ import annotations

from collections import defaultdict
from collections import deque
import threading
import time

from detection.features import StreamingFeatureExtractor
from detection.model import IsolationForestEngine
from simulator.attack_patterns import EventContext, generate_normal_event


class DetectionService:
    def __init__(self) -> None:
        self._runtime_extractor = StreamingFeatureExtractor(window_seconds=60)
        self._model = IsolationForestEngine(n_estimators=100, contamination=0.05)
        self._state_lock = threading.Lock()
        self._ready = False
        self._failed_login_times: dict[str, deque[float]] = defaultdict(deque)
        self._port_times: dict[str, deque[tuple[float, int]]] = defaultdict(deque)

    def initialize(self, baseline_size: int = 5000) -> None:
        baseline_context = EventContext()
        baseline_extractor = StreamingFeatureExtractor(window_seconds=60)

        baseline_features: list[list[float]] = []
        for _ in range(baseline_size):
            event = generate_normal_event(baseline_context)
            baseline_features.append(baseline_extractor.extract(event))

        self._model.train_model(baseline_features)
        self._ready = True
        print(f"[detection] model trained on {baseline_size} normal events")

    def analyze_event(self, event: dict) -> dict:
        if not self._ready:
            return self._heuristic_fallback(event)

        try:
            with self._state_lock:
                feature_vector = self._runtime_extractor.extract(event)
            score = self._model.predict_score(feature_vector)
        except Exception:
            return self._heuristic_fallback(event)

        is_anomaly = score > 0.65
        severity = "HIGH" if score > 0.80 else "LOW"

        return {"score": score, "is_anomaly": is_anomaly, "severity": severity}

    def enrich_event(self, event: dict) -> dict:
        analysis = self.analyze_event(event)
        event["anomaly_score"] = round(float(analysis["score"]), 4)
        event["is_anomaly"] = bool(analysis["is_anomaly"])
        event["severity"] = str(analysis["severity"])
        return event

    def enrich_events(self, events: list[dict]) -> list[dict]:
        if not events:
            return []
        if not self._ready:
            for event in events:
                fallback = self._heuristic_fallback(event)
                event["anomaly_score"] = round(float(fallback["score"]), 4)
                event["is_anomaly"] = bool(fallback["is_anomaly"])
                event["severity"] = str(fallback["severity"])
            return events

        try:
            with self._state_lock:
                feature_vectors = [self._runtime_extractor.extract(event) for event in events]

            scores = self._model.predict_scores(feature_vectors)
            for event, score in zip(events, scores):
                is_anomaly = score > 0.65
                severity = "HIGH" if score > 0.80 else "LOW"
                event["anomaly_score"] = round(float(score), 4)
                event["is_anomaly"] = is_anomaly
                event["severity"] = severity
        except Exception:
            for event in events:
                fallback = self._heuristic_fallback(event)
                event["anomaly_score"] = round(float(fallback["score"]), 4)
                event["is_anomaly"] = bool(fallback["is_anomaly"])
                event["severity"] = str(fallback["severity"])

        return events

    def _heuristic_fallback(self, event: dict) -> dict:
        now = time.time()
        source_ip = str(event.get("source_ip", "unknown"))
        destination_port = int(event.get("destination_port", 0) or 0)
        event_type = str(event.get("event_type", ""))
        status = str(event.get("status", ""))

        with self._state_lock:
            if event_type == "login" and status == "failure":
                self._failed_login_times[source_ip].append(now)
            self._port_times[source_ip].append((now, destination_port))

            cutoff = now - 60
            while self._failed_login_times[source_ip] and self._failed_login_times[source_ip][0] < cutoff:
                self._failed_login_times[source_ip].popleft()
            while self._port_times[source_ip] and self._port_times[source_ip][0][0] < cutoff:
                self._port_times[source_ip].popleft()

            failed_login_count = len(self._failed_login_times[source_ip])
            unique_ports = len({port for _, port in self._port_times[source_ip]})

        # Fallback rules required for demo stability.
        if failed_login_count > 20:
            return {"score": 0.88, "is_anomaly": True, "severity": "HIGH"}
        if unique_ports > 50:
            return {"score": 0.9, "is_anomaly": True, "severity": "HIGH"}
        return {"score": 0.25, "is_anomaly": False, "severity": "LOW"}


detection_service = DetectionService()
