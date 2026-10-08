"""Persist/load the trained anomaly detector and keep artifacts fresh."""
from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import sklearn
from pathlib import Path
from typing import Optional

import joblib

from app.api.settings import REPO_DIR, settings
from app.features.schemas import VECTOR_VERSION
from app.models.isolation_forest import AnomalyDetector, load_training_frame, MODEL_SCHEMA_VERSION

log = logging.getLogger("potus.models")

_detector: Optional[AnomalyDetector] = None
_detector_path: Optional[Path] = None


def _training_source_path() -> Path:
    return REPO_DIR / "normal_wallets.csv"


def training_fingerprint(path: Optional[Path] = None) -> str:
    """Return a stable content hash for the normal-only CSV, or a fallback marker."""
    p = path or _training_source_path()
    if not p.exists():
        return "synthetic:seed-42"
    digest = hashlib.sha256()
    with p.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def train_and_save(path: Optional[str] = None) -> AnomalyDetector:
    df, source = load_training_frame()
    det = AnomalyDetector().fit(df, source, training_fingerprint())
    p = Path(path or settings.model_path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    os.close(fd)
    try:
        joblib.dump(det, temporary)
        os.replace(temporary, p)
    finally:
        Path(temporary).unlink(missing_ok=True)
    log.info("trained %s on %s rows (%s) -> %s", det.info()["model"], len(df), source, p)
    return det


def _artifact_compatible(det: object) -> bool:
    return (
        isinstance(det, AnomalyDetector)
        and det.model is not None
        and getattr(det, "sklearn_version", None) == sklearn.__version__
        and getattr(det, "vector_version", None) == VECTOR_VERSION
        and getattr(det, "model_schema_version", None) == MODEL_SCHEMA_VERSION
        and getattr(det, "training_fingerprint", None) == training_fingerprint()
    )


def load_detector(path: Optional[str] = None, retrain: bool = False) -> AnomalyDetector:
    global _detector, _detector_path
    p = Path(path or settings.model_path).expanduser().resolve()
    if _detector is not None and _detector_path == p and not retrain and _artifact_compatible(_detector):
        return _detector

    det: Optional[AnomalyDetector] = None
    if p.exists() and not retrain:
        try:
            candidate = joblib.load(p)
            if _artifact_compatible(candidate):
                det = candidate
            else:
                log.info("model artifact is stale/incompatible; retraining")
        except Exception as exc:
            log.warning("could not load model artifact (%s); retraining", exc)

    _detector = det or train_and_save(str(p))
    _detector_path = p
    return _detector


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    d = load_detector(retrain=True)
    print(d.info())
