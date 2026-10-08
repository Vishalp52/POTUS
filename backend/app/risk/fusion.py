import math
from typing import Dict, Any, Optional, List, Tuple
from app.risk.reason_codes import ReasonCode

class RiskFusionEngine:
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = {
            "anomaly": 0.45,
            "rules": 0.25,
            "threat_similarity": 0.15,
            "gemini_semantic": 0.15
        }
        if weights is not None:
            if set(weights) != set(self.weights):
                raise ValueError("risk weights must specify all four components")
            self.weights = dict(weights)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0
               for v in self.weights.values()):
            raise ValueError("risk weights must be finite and non-negative")
        if not math.isclose(sum(self.weights.values()), 1.0, abs_tol=1e-9):
            raise ValueError("risk weights must sum to 1")
        if self.weights["gemini_semantic"] > 0.20:
            raise ValueError("Gemini contribution cannot exceed 20 risk points")
        self.min_gemini_confidence = 0.70

    def compute_fused_risk(
        self,
        anomaly_score: float,
        rule_score: float,
        pattern_similarity: float,
        gemini_triage: Optional[Any],
        rule_reasons: List[ReasonCode]
    ) -> Tuple[int, List[ReasonCode], bool]:
        for value in (anomaly_score, rule_score, pattern_similarity):
            if isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("risk component scores must be finite and between 0 and 1")
        if not math.isfinite(self.min_gemini_confidence) or not 0 <= self.min_gemini_confidence <= 1:
            raise ValueError("minimum confidence must be between 0 and 1")
        reasons = list(rule_reasons)
        requires_review = False

        if pattern_similarity >= 0.60:
            reasons.append(ReasonCode.KNOWN_PATTERN_SIMILARITY)

        a_100 = anomaly_score * 100.0
        r_100 = rule_score * 100.0
        t_100 = pattern_similarity * 100.0

        if gemini_triage is not None:
            from app.ai.schemas import GeminiTriage
            # Revalidate constructed objects as well as ordinary JSON-derived models.
            gemini_triage = GeminiTriage.model_validate(gemini_triage.model_dump())
            g_100 = float(gemini_triage.semantic_risk)
            if gemini_triage.requires_human_review and gemini_triage.category not in {
                "SUSPICIOUS_FRAUD_LIKE", "POTENTIAL_ILLICIT_ACTIVITY"
            }:
                requires_review = True
                reasons.append(ReasonCode.LOW_CONFIDENCE_REVIEW)

            if gemini_triage.category == "SUSPICIOUS_FRAUD_LIKE":
                reasons.append(ReasonCode.GEMINI_FRAUD_LIKE)
            elif gemini_triage.category == "POTENTIAL_ILLICIT_ACTIVITY":
                reasons.append(ReasonCode.GEMINI_POTENTIAL_ILLICIT)

            is_high_severity = gemini_triage.category in [
                "SUSPICIOUS_FRAUD_LIKE", "POTENTIAL_ILLICIT_ACTIVITY"
            ]
            if is_high_severity and gemini_triage.confidence < self.min_gemini_confidence:
                requires_review = True
                reasons.append(ReasonCode.LOW_CONFIDENCE_REVIEW)

            weighted_score = (
                self.weights["anomaly"] * a_100 +
                self.weights["rules"] * r_100 +
                self.weights["threat_similarity"] * t_100 +
                self.weights["gemini_semantic"] * g_100
            )
        else:
            # Fallback path: Renormalize remaining weights without Gemini
            remaining = self.weights["anomaly"] + self.weights["rules"] + self.weights["threat_similarity"]
            weighted_score = (
                (self.weights["anomaly"] / remaining) * a_100 +
                (self.weights["rules"] / remaining) * r_100 +
                (self.weights["threat_similarity"] / remaining) * t_100
            )

        if rule_score >= 0.75 and anomaly_score >= 0.80:
            weighted_score = max(weighted_score, 55.0)

        final_score = int(round(max(0.0, min(100.0, weighted_score))))
        return final_score, sorted(set(reasons), key=lambda reason: str(reason)), requires_review