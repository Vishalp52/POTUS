from typing import Dict, Any, List, Optional
from app.risk.reason_codes import ReasonCode

DEFAULT_THRESHOLDS = {"allow_max": 34, "challenge_max": 54, "review_max": 74}


class PolicyEngine:
    def __init__(self, thresholds: Optional[Dict[str, int]] = None):
        values = dict(DEFAULT_THRESHOLDS)
        if thresholds is not None:
            if not isinstance(thresholds, dict) or set(thresholds) != set(values):
                raise ValueError("policy thresholds must specify exactly allow_max, challenge_max and review_max")
            values = dict(thresholds)
        if any(isinstance(v, bool) or not isinstance(v, int) for v in values.values()):
            raise ValueError("policy thresholds must be integers")
        if not 0 <= values["allow_max"] < values["challenge_max"] < values["review_max"] < 100:
            raise ValueError("policy thresholds must satisfy 0 <= allow_max < challenge_max < review_max < 100")
        self.allow_max = values["allow_max"]
        self.challenge_max = values["challenge_max"]
        self.review_max = values["review_max"]

    def band(self, risk_score: int) -> str:
        if isinstance(risk_score, bool) or not isinstance(risk_score, int) or not 0 <= risk_score <= 100:
            raise ValueError("risk score must be an integer between 0 and 100")
        if risk_score <= self.allow_max:
            return "ALLOW"
        if risk_score <= self.challenge_max:
            return "CHALLENGE"
        if risk_score <= self.review_max:
            return "REVIEW"
        return "RESTRICT"

    def evaluate(self, risk_score: int, reason_codes: List[ReasonCode], forced_review: bool = False,
                 deterministic_score: Optional[int] = None) -> Dict[str, Any]:
        decision = self.band(risk_score)
        # Uncertain AI output or missing evidence holds the action for review: it
        # lifts ALLOW/CHALLENGE and stops an AI-driven RESTRICT. It never lowers
        # a RESTRICT that anomaly + rules + threat memory reach on their own
        # ("RESTRICT when corroborated", spec §14 Scenario D), even when the
        # uncertain AI term pulled the fused score below the RESTRICT band.
        if forced_review:
            corroborated = deterministic_score is not None and self.band(deterministic_score) == "RESTRICT"
            decision = "RESTRICT" if corroborated else "REVIEW"

        return {
            "decision": decision,
            "risk_score": risk_score,
            "reason_codes": [r.value if isinstance(r, ReasonCode) else r for r in reason_codes],
            "customer": self.customer_message(decision)
        }

    def customer_message(self, decision: str) -> Dict[str, str]:
        messages = {
            "ALLOW": {"status": "APPROVED", "message": "Access approved."},
            "CHALLENGE": {"status": "VERIFY_IDENTITY", "message": "We noticed unusual activity. Please complete a quick verification step to continue."},
            "REVIEW": {"status": "SECURITY_REVIEW", "message": "This action is being reviewed for security. Your account remains available, but this sensitive action is temporarily paused."},
            "RESTRICT": {"status": "ACCESS_TEMPORARILY_LIMITED", "message": "We detected unusual activity and temporarily limited this action to protect your account. Verify your account or contact support to continue."}
        }
        return messages[decision]
