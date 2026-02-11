from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List

import numpy as np
from sklearn.ensemble import IsolationForest


FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "packets",
    "failed_logins",
    "dst_port",
]


@dataclass
class DetectionResult:
    label: str
    score: float
    threshold: float


@dataclass
class IntrusionDetector:
    contamination: float = 0.08
    random_state: int = 42
    _model: IsolationForest = field(init=False)
    _threshold: float = field(init=False, default=0.0)
    _lock: Lock = field(init=False, default_factory=Lock)

    def __post_init__(self) -> None:
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=200,
        )
        baseline = self._generate_synthetic_baseline()
        self._model.fit(baseline)
        baseline_scores = self._model.decision_function(baseline)
        self._threshold = float(np.percentile(baseline_scores, 8))

    def _generate_synthetic_baseline(self, rows: int = 4000) -> np.ndarray:
        rng = np.random.default_rng(self.random_state)
        duration = rng.gamma(shape=2.4, scale=7.0, size=rows)
        src_bytes = rng.lognormal(mean=8.8, sigma=0.5, size=rows)
        dst_bytes = rng.lognormal(mean=8.6, sigma=0.6, size=rows)
        packets = rng.poisson(lam=28, size=rows)
        failed_logins = rng.binomial(n=3, p=0.02, size=rows)
        dst_port = rng.choice([22, 53, 80, 443, 3306], size=rows, p=[0.08, 0.22, 0.28, 0.34, 0.08])

        return np.column_stack([duration, src_bytes, dst_bytes, packets, failed_logins, dst_port])

    def predict(self, sample: Dict[str, float]) -> DetectionResult:
        row = np.array([[sample.get(feature, 0.0) for feature in FEATURES]], dtype=float)
        with self._lock:
            score = float(self._model.decision_function(row)[0])
        label = "anomaly" if score < self._threshold else "normal"
        return DetectionResult(label=label, score=score, threshold=self._threshold)

    def batch_predict(self, samples: List[Dict[str, float]]) -> List[DetectionResult]:
        return [self.predict(sample) for sample in samples]
