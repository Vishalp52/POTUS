"""Strict, bounded classification contract (POTUS specification section 6)."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

Indicator = Annotated[str, Field(min_length=1, max_length=300)]

class GeminiTriage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    category: Literal["NORMAL_OR_BENIGN", "SLIGHT_ANOMALY", "SUSPICIOUS_FRAUD_LIKE",
                      "POTENTIAL_ILLICIT_ACTIVITY", "INSUFFICIENT_EVIDENCE"]
    confidence: float = Field(ge=0.0, le=1.0)
    semantic_risk: int = Field(ge=0, le=100)
    supporting_indicators: list[Indicator] = Field(max_length=12)
    benign_explanations: list[Indicator] = Field(min_length=1, max_length=8)
    employee_summary: str = Field(min_length=1, max_length=2000)
    customer_reason_code: Literal["NONE", "UNUSUAL_ACTIVITY", "VERIFY_IDENTITY",
                                  "SECURITY_REVIEW", "ACCESS_TEMPORARILY_LIMITED"]
    requires_human_review: bool

    @field_validator("category", mode="before")
    @classmethod
    def legacy_labels(cls, value):
        # Read older persisted records while emitting the canonical spec labels.
        return {"NORMAL OR BENIGN": "NORMAL_OR_BENIGN", "SLIGHT ANOMALY": "SLIGHT_ANOMALY"}.get(value, value) if isinstance(value, str) else value


def provider_schema() -> dict:
    """Send the supported JSON Schema subset; enforce text bounds locally.

    Google's documented string constraints are enum/format, not minLength or
    maxLength. Keep the strict Pydantic contract for every accepted response.
    """
    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items()
                    if key not in {"title", "minLength", "maxLength"}}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    return clean(GeminiTriage.model_json_schema())
