"""Persist / load the trained detector (joblib). Trains on first use if no artifact exists."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import joblib

from app.api.settings import settings
from app.features.schemas import VECTOR_VERSION
from app.models.isolation_forest import AnomalyDetector, load_training_frame

log = logging.getLogger("potus.models")

_detector: Optional[AnomalyDetector] = None


def train_and_save(path: Optional[str] = None) -> AnomalyDetector:
    df, source = load_training_frame()
    det = AnomalyDetector().fit(df, source)
    p = Path(path or settings.model_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(det, p)
    log.info("trained IsolationForest on %s rows (%s) -> %s", len(df), source, p)
    return det


def load_detector(path: Optional[str] = None, retrain: bool = False) -> AnomalyDetector:
    global _detector
    if _detector is not None and not retrain:
        return _detector
    p = Path(path or settings.model_path)
    det: Optional[AnomalyDetector] = None
    if p.exists() and not retrain:
        try:
            det = joblib.load(p)
            if getattr(det, "vector_version", None) != VECTOR_VERSION:
                log.info("model artifact has old vector version; retraining")
                det = None
        except Exception as exc:
            log.warning("could not load model artifact (%s); retraining", exc)
            det = None
    _detector = det or train_and_save(str(p))
    return _detector


if __name__ == "__main__":  # python -m app.models.model_store
    logging.basicConfig(level=logging.INFO)
    d = load_detector(retrain=True)
    print(d.info())
