"""Request / response models for the HTTP API."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.features.schemas import BehaviorFeatures

ADDRESS_PATTERN = r"^0x[0-9a-fA-F]{40}$"
SAFE_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,63}$"
SIGNATURE_PATTERN = r"^0x[0-9a-fA-F]{130}$"


class StrictModel(BaseModel):
    """Reject unknown fields so nothing unexpected slips into the pipeline."""
    model_config = ConfigDict(extra="forbid")


class AccessRequest(StrictModel):
    wallet: str = Field(..., pattern=ADDRESS_PATTERN)
    resource_id: str = Field("research-vault", pattern=SAFE_ID_PATTERN)
    action: str = Field("read", pattern=SAFE_ID_PATTERN)
    session: dict[str, str] = Field(default_factory=dict, max_length=20,
                                    description="Optional session metadata (stored only; never sent to Gemini)")
    nonce: Optional[str] = Field(None, max_length=64, description="From GET /auth/nonce")
    signature: Optional[str] = Field(None, pattern=SIGNATURE_PATTERN, description="personal_sign of the nonce message")
    demo_scenario: Optional[Literal["A", "B", "C", "D", "E", "F"]] = Field(
        None, description="Replay a labeled SIMULATED scenario onto this wallet (demo only)")
    simulate_ai_outage: bool = Field(False, description="Demo: force the Gemini-unavailable fallback path")

    @field_validator("wallet")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()

    @field_validator("session")
    @classmethod
    def _bounded_session(cls, v: dict[str, str]) -> dict[str, str]:
        for k, val in v.items():
            if len(k) > 64 or len(val) > 256:
                raise ValueError("session keys <= 64 chars, values <= 256 chars")
        return v


class ScoreRequest(StrictModel):
    wallet: Optional[str] = Field(None, pattern=ADDRESS_PATTERN)
    resource_id: str = Field("research-vault", pattern=SAFE_ID_PATTERN)
    demo_scenario: Optional[Literal["A", "B", "C", "D", "E", "F"]] = None
    features: Optional[BehaviorFeatures] = Field(None, description="Score a raw feature vector instead of fetching activity")
    simulate_ai_outage: bool = False


class GeminiSignal(BaseModel):
    category: str
    confidence: float
    semantic_risk: int


class Signals(BaseModel):
    anomaly_score: float
    rule_score: float
    pattern_similarity: float
    gemini: Optional[GeminiSignal] = None
    gemini_status: str


class CustomerPayload(BaseModel):
    request_id: str
    decision: str
    status: str
    title: str
    message: str
    next_action: str
    support_code: str


class AccessEvaluation(BaseModel):
    request_id: str
    wallet: str
    resource_id: str
    action: str
    risk_score: int
    decision: str
    expires_at: str
    signals: Signals
    reason_codes: list[str]
    customer: CustomerPayload
    evidence_hash: str
    onchain: dict[str, Any] = Field(default_factory=dict)
    simulated: bool = False
    wallet_verified: bool = False
    access_token: Optional[str] = Field(None, description="Short-lived vault token (ALLOW + proven wallet only)")


class VerifyRequest(StrictModel):
    nonce: str = Field(..., max_length=64)
    signature: str = Field(..., pattern=SIGNATURE_PATTERN)


class VerifyResponse(CustomerPayload):
    access_token: Optional[str] = None


Disposition = Literal["CONFIRMED_INCIDENT", "SIMULATED_ATTACK", "BENIGN", "NEEDS_MORE_EVIDENCE", "CUSTOMER_VERIFIED"]


class ReviewRequest(StrictModel):
    """Reviewer identity comes from the API key, never from the body (no spoofing)."""
    disposition: Disposition
    note: str = Field("", max_length=2000)


class IncidentConfirmRequest(StrictModel):
    case_id: str = Field(..., max_length=64)
    disposition: Literal["CONFIRMED_INCIDENT", "SIMULATED_ATTACK"] = "CONFIRMED_INCIDENT"
    note: str = Field("", max_length=2000)
