from typing import Dict, Any, Optional, List, Tuple
from app.risk.reason_codes import ReasonCode

class RiskFusionEngine:
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or {
            "anomaly": 0.45,
            "rules": 0.25,
            "threat_similarity": 0.15,
            "gemini_semantic": 0.15
        }
        self.min_gemini_confidence = 0.70

    def compute_fused_risk(
        self,
        anomaly_score: float,
        rule_score: float,
        pattern_similarity: float,
        gemini_triage: Optional[Any],
        rule_reasons: List[ReasonCode]
    ) -> Tuple[int, List[ReasonCode], bool]:
        reasons = list(rule_reasons)
        requires_review = False

        if pattern_similarity >= 0.60:
            reasons.append(ReasonCode.KNOWN_PATTERN_SIMILARITY)

        a_100 = anomaly_score * 100.0
        r_100 = rule_score * 100.0
        t_100 = pattern_similarity * 100.0

        if gemini_triage is not None:
            g_100 = float(gemini_triage.semantic_risk)

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
        return final_score, list(set(reasons)), requires_review