"""Statistical anomaly detector (spec §5): scikit-learn IsolationForest.

Training data = normal behavior only. The detector owns the model contract,
calibration, population baselines, and deterministic scoring used by the POTUS
risk engine. It does not make policy decisions.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Sequence

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest

from app.api.settings import REPO_DIR
from app.features.baselines import PopulationStats
from app.features.schemas import MAX_FEATURE_COUNT, MODEL_FEATURES, VECTOR_VERSION

log = logging.getLogger("potus.models")

RANDOM_STATE = 42
N_ESTIMATORS = 300
MODEL_NAME = "IsolationForest"
MODEL_SCHEMA_VERSION = "iforest-v2"

# Column mapping from generate_data.py output -> model feature names.
CSV_MAP = {
    "tx_10m": "tx_count_10m",
    "tx_1h": "tx_count_1h",
    "unique_contracts_24h": "unique_contracts_24h",
    "new_contract_ratio": "new_contract_ratio",
    "access_requests_10m": "access_requests_10m",
    "failed_requests_1h": "failed_access_count",
    "flagged_counterparties": "flagged_counterparty_count",
}


def normalize_anomaly(raw_score: float, low: float, high: float) -> float:
    """Map higher-is-more-anomalous raw output into the risk engine's 0..1 range."""
    x = (raw_score - low) / (high - low) if high > low else 0.0
    return float(max(0.0, min(1.0, x)))


def synthetic_normal(n: int = 1000, seed: int = RANDOM_STATE) -> pd.DataFrame:
    """Create deterministic fallback normal behavior when no CSV is available."""
    if n < 2:
        raise ValueError("synthetic training population must contain at least two rows")
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "tx_count_10m": rng.poisson(2, n),
        "tx_count_1h": rng.poisson(8, n),
        "unique_contracts_24h": rng.poisson(4, n),
        "new_contract_ratio": rng.beta(2, 8, n),
        "transfer_value_zscore": np.clip(rng.normal(0, 1, n), -4, 4),
        "access_requests_10m": rng.poisson(1, n),
        "failed_access_count": rng.poisson(0.2, n),
        "flagged_counterparty_count": rng.binomial(1, 0.02, n),
    })[MODEL_FEATURES]


def load_training_frame(csv_path: Optional[Path] = None) -> tuple[pd.DataFrame, str]:
    """Load normal-only training data, falling back deterministically if needed."""
    csv_path = Path(csv_path) if csv_path is not None else REPO_DIR / "normal_wallets.csv"
    if csv_path.exists():
        try:
            raw = pd.read_csv(csv_path)
            if set(MODEL_FEATURES).issubset(raw.columns):
                df = raw[MODEL_FEATURES].copy()
            elif set(CSV_MAP).issubset(raw.columns):
                df = raw.rename(columns=CSV_MAP).copy()
            else:
                raise ValueError("missing required feature columns")

            # avg_transfer_value is a level, not a z-score. Convert in log-space.
            if "transfer_value_zscore" not in df and "avg_transfer_value" in raw.columns:
                values = pd.to_numeric(raw["avg_transfer_value"], errors="raise")
                if not np.isfinite(values).all() or (values < 0).any():
                    raise ValueError("invalid transfer values")
                lv = np.log10(values.clip(lower=1e-9))
                sd = float(lv.std())
                df["transfer_value_zscore"] = (
                    (lv - lv.mean()) / (sd if np.isfinite(sd) and sd > 0 else 1.0)
                ).clip(-4, 4)
            elif "transfer_value_zscore" not in df:
                df["transfer_value_zscore"] = synthetic_normal(len(df))["transfer_value_zscore"].values

            df = df[MODEL_FEATURES].astype(float)
            _validate_training_frame(df)
            return df, f"csv:{csv_path.name}"
        except (OSError, ValueError, TypeError, pd.errors.ParserError) as exc:
            log.warning("training CSV %s is unusable (%s); using synthetic normal data", csv_path.name, exc)
    return synthetic_normal().astype(float), "synthetic"


def _validate_training_frame(df: pd.DataFrame) -> None:
    missing = [f for f in MODEL_FEATURES if f not in df.columns]
    if missing:
        raise ValueError(f"training data missing model features: {missing}")
    values = df[MODEL_FEATURES].to_numpy(dtype=float)
    if len(values) < 2 or not np.isfinite(values).all():
        raise ValueError("training data must contain at least two finite feature rows")
    nonnegative = [f for f in MODEL_FEATURES if f != "transfer_value_zscore"]
    if (df[nonnegative] < 0).any().any() or (df["new_contract_ratio"] > 1).any():
        raise ValueError("training counts and ratios are outside their valid ranges")
    counts = [f for f in nonnegative if f != "new_contract_ratio"]
    if (df[counts] > MAX_FEATURE_COUNT).any().any() or (df["transfer_value_zscore"].abs() > 10).any():
        raise ValueError("training features exceed the supported model range")


def _validate_vector(vector: Sequence[float]) -> np.ndarray:
    """Validate one model vector before it reaches scikit-learn."""
    if len(vector) != len(MODEL_FEATURES):
        raise ValueError(
            f"model vector has {len(vector)} features; expected {len(MODEL_FEATURES)} ({MODEL_FEATURES})"
        )
    arr = np.asarray(vector, dtype=float)
    if not np.isfinite(arr).all():
        raise ValueError("model vector must contain only finite values")
    for i, name in enumerate(MODEL_FEATURES):
        if name != "transfer_value_zscore" and arr[i] < 0:
            raise ValueError(f"{name} must be non-negative")
        if name == "new_contract_ratio" and not 0 <= arr[i] <= 1:
            raise ValueError("new_contract_ratio must be between 0 and 1")
        if name == "transfer_value_zscore" and abs(arr[i]) > 10:
            raise ValueError("transfer_value_zscore must be between -10 and 10")
        if name not in {"new_contract_ratio", "transfer_value_zscore"} and arr[i] > MAX_FEATURE_COUNT:
            raise ValueError(f"{name} exceeds the supported range")
    return arr


class AnomalyDetector:
    """Normal-behavior IsolationForest plus deterministic 0..1 calibration."""

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.low = 0.0
        self.high = 1.0
        self.population = PopulationStats()
        self.trained_on = ""
        self.training_fingerprint = ""
        self.vector_version = VECTOR_VERSION
        self.model_schema_version = MODEL_SCHEMA_VERSION
        self.sklearn_version = sklearn.__version__

    def fit(self, df: pd.DataFrame, source: str = "", training_fingerprint: str = "") -> "AnomalyDetector":
        _validate_training_frame(df)
        X = df[MODEL_FEATURES].to_numpy(dtype=float)
        self.model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination="auto",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        self.model.fit(X)

        raw = self._raw(X)
        p50, p99 = float(np.percentile(raw, 50)), float(np.percentile(raw, 99))
        self.low = p50
        self.high = p50 + 2.5 * max(p99 - p50, 1e-6)
        self.population = PopulationStats(
            median={k: float(df[k].median()) for k in MODEL_FEATURES},
            mean={k: float(df[k].mean()) for k in MODEL_FEATURES},
            std={k: float(df[k].std() or 1.0) for k in MODEL_FEATURES},
        )
        self.trained_on = source
        self.training_fingerprint = training_fingerprint
        self.vector_version = VECTOR_VERSION
        self.model_schema_version = MODEL_SCHEMA_VERSION
        self.sklearn_version = sklearn.__version__
        return self

    def _raw(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("detector not trained")
        # sklearn's decision_function is lower for anomalies; flip the sign so
        # POTUS consistently uses higher = more anomalous.
        return -self.model.decision_function(X)

    def raw_score(self, vector: Sequence[float]) -> float:
        arr = _validate_vector(vector)
        return float(self._raw(np.asarray([arr], dtype=float))[0])

    def score(self, vector: Sequence[float]) -> float:
        return round(normalize_anomaly(self.raw_score(vector), self.low, self.high), 4)

    def score_many(self, vectors: Sequence[Sequence[float]]) -> list[float]:
        """Score multiple vectors with one forest call, preserving input order."""
        if not vectors:
            return []
        X = np.asarray([_validate_vector(v) for v in vectors], dtype=float)
        return [round(normalize_anomaly(float(raw), self.low, self.high), 4) for raw in self._raw(X)]

    def info(self) -> dict:
        return {
            "model": MODEL_NAME,
            "model_schema_version": self.model_schema_version,
            "sklearn_version": self.sklearn_version,
            "n_estimators": N_ESTIMATORS,
            "random_state": RANDOM_STATE,
            "features": MODEL_FEATURES,
            "vector_version": self.vector_version,
            "trained_on": self.trained_on,
            "training_fingerprint": self.training_fingerprint,
            "calibration": {"low": round(self.low, 5), "high": round(self.high, 5)},
        }
