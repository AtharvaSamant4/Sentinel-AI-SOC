from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestEngine:
    def __init__(self, n_estimators: int = 100, contamination: float = 0.05) -> None:
        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=1,
        )
        self._trained = False
        self._score_min = 0.0
        self._score_max = 1.0

    def train_model(self, baseline_features: list[list[float]]) -> None:
        if not baseline_features:
            raise ValueError("baseline_features cannot be empty")

        x_train = np.asarray(baseline_features, dtype=np.float64)
        self._model.fit(x_train)

        baseline_scores = self._model.decision_function(x_train)
        self._score_min = float(np.min(baseline_scores))
        self._score_max = float(np.max(baseline_scores))
        if self._score_max - self._score_min < 1e-9:
            self._score_max = self._score_min + 1e-9

        self._trained = True

    def predict_score(self, feature_vector: list[float]) -> float:
        if not self._trained:
            raise RuntimeError("Model has not been trained")

        x = np.asarray([feature_vector], dtype=np.float64)
        raw_score = float(self._model.decision_function(x)[0])
        return self._normalize_raw_score(raw_score)

    def predict_scores(self, feature_vectors: list[list[float]]) -> list[float]:
        if not self._trained:
            raise RuntimeError("Model has not been trained")
        if not feature_vectors:
            return []

        x = np.asarray(feature_vectors, dtype=np.float64)
        raw_scores = self._model.decision_function(x)
        return [self._normalize_raw_score(float(score)) for score in raw_scores]

    def _normalize_raw_score(self, raw_score: float) -> float:
        normalized = (raw_score - self._score_min) / (self._score_max - self._score_min)
        normalized = min(1.0, max(0.0, normalized))
        return float(1.0 - normalized)
