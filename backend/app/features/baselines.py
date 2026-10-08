"""Population + per-wallet baselines used to express feature deltas."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.features.schemas import MODEL_FEATURES

# Fallback population baselines (overwritten by the trained model's stats).
DEFAULT_POPULATION = {
    "tx_count_10m": 2.0,
    "tx_count_1h": 8.0,
    "unique_contracts_24h": 4.0,
    "new_contract_ratio": 0.2,
    "transfer_value_zscore": 0.0,
    "access_requests_10m": 1.0,
    "failed_access_count": 0.0,
    "flagged_counterparty_count": 0.0,
}

# Minimum baselines so ratios never explode on near-zero denominators.
BASELINE_FLOORS = {
    "tx_count_10m": 1.0,
    "tx_count_1h": 3.0,
    "unique_contracts_24h": 1.0,
    "new_contract_ratio": 0.1,
    "access_requests_10m": 1.0,
}


@dataclass
class PopulationStats:
    median: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_POPULATION))
    mean: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_POPULATION))
    std: dict[str, float] = field(default_factory=lambda: {k: 1.0 for k in MODEL_FEATURES})

    def standardize(self, vector: list[float]) -> list[float]:
        return [(v - self.mean[k]) / (self.std[k] or 1.0) for k, v in zip(MODEL_FEATURES, vector)]


def deviation_signature(stats: PopulationStats, vector: list[float], deadzone: float = 2.0, cap: float = 10.0) -> list[float]:
    """Positive standardized deviations only, with small deviations zeroed.

    Normal behavior maps to (near) the zero vector, so cosine similarity in the
    threat memory reflects the *shape* of genuinely abnormal behavior instead of noise.
    """
    out = []
    for z in stats.standardize(vector):
        z = min(cap, z)
        out.append(round(z, 4) if z >= deadzone else 0.0)
    return out


def wallet_baseline(prior_count: int, prior_seconds: float, window_seconds: float, population: float, floor: float) -> float:
    """Expected count in `window_seconds` from the wallet's own earlier history,
    falling back to the population baseline when history is too thin."""
    if prior_seconds >= 3 * window_seconds and prior_count > 0:
        own = prior_count * (window_seconds / prior_seconds)
        return max(floor, own)
    return max(floor, population)


def ratio(value: float, baseline: float) -> float:
    return round(value / baseline, 2) if baseline > 0 else 0.0
