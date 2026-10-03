from typing import Literal
from pydantic import BaseModel, Field

class GeminiTriage(BaseModel):
    category: Literal[
        "NORMAL OR BENIGN",
        "SLIGHT ANOMALY",
        "SUSPICIOUS_FRAUD_LIKE",
        "POTENTIAL_ILLICIT_ACTIVITY",
        "INSUFFICIENT_EVIDENCE"
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    semantic_risk: int = Field(ge=0, le=100)
    supporting_indicators: list[str]
    benign_explanations: list[str]
    employee_summary: str
    customer_reason_code: Literal[
        "NONE", "UNUSUAL_ACTIVITY", "VERIFY_IDENTITY",
        "SECURITY_REVIEW", "ACCESS_TEMPORARILY_LIMITED"
    ]
    requires_human_review: bool