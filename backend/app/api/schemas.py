"""Request / response models for the HTTP API."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from app.features.schemas import BehaviorFeatures

ADDRESS_PATTERN = r"^0x[0-9a-fA-F]{40}$"


class AccessRequest(BaseModel):
    wallet: str = Field(..., pattern=ADDRESS_PATTERN)
    resource_id: str = Field("research-vault", min_length=1, max_length=64)
    action: str = Field("read", min_length=1, max_length=64)
    session: dict[str, Any] = Field(default_factory=dict, description="Optional session metadata (never sent to Gemini)")
    demo_scenario: Optional[Literal["A", "B", "C", "D", "E", "F"]] = Field(
        None, description="Replay a labeled SIMULATED scenario onto this wallet (demo only)")
    simulate_ai_outage: bool = Field(False, description="Demo: force the Gemini-unavailable fallback path")

    @field_validator("wallet")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class ScoreRequest(BaseModel):
    wallet: Optional[str] = Field(None, pattern=ADDRESS_PATTERN)
    resource_id: str = "research-vault"
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


class VerifyRequest(BaseModel):
    signature: str = Field(..., min_length=10)


Disposition = Literal["CONFIRMED_INCIDENT", "SIMULATED_ATTACK", "BENIGN", "NEEDS_MORE_EVIDENCE", "CUSTOMER_VERIFIED"]


class ReviewRequest(BaseModel):
    disposition: Disposition
    note: str = Field("", max_length=2000)
    reviewer: str = Field("analyst", max_length=64)


class IncidentConfirmRequest(BaseModel):
    case_id: str
    disposition: Literal["CONFIRMED_INCIDENT", "SIMULATED_ATTACK"] = "CONFIRMED_INCIDENT"
    reviewer: str = "analyst"
    note: str = ""
