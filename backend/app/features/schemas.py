"""Feature + evidence-packet schemas (spec §5)."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

# Order matters: this is the vector fed to IsolationForest and threat memory.
MODEL_FEATURES: list[str] = [
    "tx_count_10m",
    "tx_count_1h",
    "unique_contracts_24h",
    "new_contract_ratio",
    "transfer_value_zscore",
    "access_requests_10m",
    "failed_access_count",
    "flagged_counterparty_count",
]
VECTOR_VERSION = "v1-8f"

RESOURCE_SENSITIVITY: dict[str, float] = {
    "research-vault": 0.8,
    "model-endpoint": 0.7,
    "admin-action": 1.0,
    "public-profile": 0.2,
}
DEFAULT_SENSITIVITY = 0.5
# Keep caller-provided counts within the detector's supported numeric range.
MAX_FEATURE_COUNT = 2**31 - 1


class BehaviorFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    wallet_age_blocks: Optional[int] = Field(None, ge=0, description="Blocks since first known tx; None if unknown")
    tx_count_10m: int = Field(0, ge=0, le=MAX_FEATURE_COUNT)
    tx_count_1h: int = Field(0, ge=0, le=MAX_FEATURE_COUNT)
    unique_contracts_24h: int = Field(0, ge=0, le=MAX_FEATURE_COUNT)
    new_contract_ratio: float = Field(0.0, ge=0.0, le=1.0)
    transfer_value_zscore: float = Field(0.0, ge=-10.0, le=10.0)
    access_requests_10m: int = Field(0, ge=0, le=MAX_FEATURE_COUNT)
    failed_access_count: int = Field(0, ge=0, le=MAX_FEATURE_COUNT)
    flagged_counterparty_count: int = Field(0, ge=0, le=MAX_FEATURE_COUNT)
    pattern_similarity: float = Field(0.0, ge=0.0, le=1.0)  # filled after threat-memory lookup
    resource_sensitivity: float = Field(DEFAULT_SENSITIVITY, ge=0.0, le=1.0)
    session_geo_velocity: Optional[float] = Field(None, ge=0.0)  # optional; never fabricated

    def model_vector(self) -> list[float]:
        return [float(getattr(self, f)) for f in MODEL_FEATURES]


class FeatureDelta(BaseModel):
    value: float
    baseline: float
    ratio: float


class FeatureBundle(BaseModel):
    """Everything the feature layer produces for one request."""
    wallet: str
    resource_id: str
    features: BehaviorFeatures
    feature_deltas: dict[str, Any]
    baselines: dict[str, float]
    hard_flags: list[str]
    data_source: str
    simulated: bool = False
    history_confidence: str = "normal"       # "normal" | "low" (cold start / partial window)
    notes: list[str] = Field(default_factory=list)
    vector: list[float] = Field(default_factory=list)          # raw model vector
    signature: list[float] = Field(default_factory=list)       # standardized deviation signature (threat memory)

    def evidence_packet(self, anomaly_score: float) -> dict[str, Any]:
        """Bounded, structured evidence for rules + Gemini (spec §5 example packet).

        transfer_value_zscore / failed_access_count / wallet_age_blocks are also
        exposed at top level because the rule engine reads them there.
        """
        f = self.features
        return {
            "wallet": self.wallet,
            "resource_id": self.resource_id,
            "anomaly_score": round(anomaly_score, 4),
            "feature_deltas": self.feature_deltas,
            "pattern_similarity": round(f.pattern_similarity, 4),
            "hard_flags": list(self.hard_flags),
            "transfer_value_zscore": round(f.transfer_value_zscore, 3),
            "failed_access_count": f.failed_access_count,
            "wallet_age_blocks": f.wallet_age_blocks or 0,
            "flagged_counterparty_count": f.flagged_counterparty_count,
            "resource_sensitivity": f.resource_sensitivity,
            "history_confidence": self.history_confidence,
            "data_source": self.data_source,
            "simulated": self.simulated,
        }
