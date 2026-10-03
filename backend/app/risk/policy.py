from typing import Dict, Any, List
from app.risk.reason_codes import ReasonCode

class PolicyEngine:
    def __init__(self, thresholds: Optional[Dict[str, int]] = None):
        self.allow_max = thresholds.get("allow_max", 34) if thresholds else 34
        self.challenge_max = thresholds.get("challenge_max", 54) if thresholds else 54
        self.review_max = thresholds.get("review_max", 74) if thresholds else 74

    def evaluate(self, risk_score: int, reason_codes: List[ReasonCode], forced_review: bool = False) -> Dict[str, Any]:
        if forced_review:
            decision = "REVIEW"
        elif risk_score <= self.allow_max:
            decision = "ALLOW"
        elif risk_score <= self.challenge_max:
            decision = "CHALLENGE"
        elif risk_score <= self.review_max:
            decision = "REVIEW"
        else:
            decision = "RESTRICT"

        return {
            "decision": decision,
            "risk_score": risk_score,
            "reason_codes": [r.value if isinstance(r, ReasonCode) else r for r in reason_codes],
            "customer": self._build_customer_message(decision)
        }

    def _build_customer_message(self, decision: str) -> Dict[str, str]:
        messages = {
            "ALLOW": {"status": "APPROVED", "message": "Access approved."},
            "CHALLENGE": {"status": "VERIFY_IDENTITY", "message": "We noticed unusual activity. Please complete a quick verification step to continue."},
            "REVIEW": {"status": "SECURITY_REVIEW", "message": "This action is being reviewed for security. Your account remains available, but this sensitive action is temporarily paused."},
            "RESTRICT": {"status": "ACCESS_TEMPORARILY_LIMITED", "message": "We detected unusual activity and temporarily limited this action to protect your account. Verify your account or contact support to continue."}
        }
        return messages[decision]