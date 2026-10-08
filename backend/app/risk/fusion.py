import math
from fractions import Fraction
from typing import Dict, Any, Optional, List, Tuple
from app.risk.reason_codes import ReasonCode

HIGH_SEVERITY = {"SUSPICIOUS_FRAUD_LIKE", "POTENTIAL_ILLICIT_ACTIVITY"}


def _exact(value: float) -> Fraction:
    # Use the shortest decimal repr so 0.555 means 111/200, not its binary
    # approximation. Ties then round the same way on every platform.
    return Fraction(repr(float(value)))


def _round_half_up(value: Fraction) -> int:
    # Spec §7 needs reproducible decisions; x.5 rounds toward the stricter band.
    return int(max(0, min(100, math.floor(value + Fraction(1, 2)))))


def _check_unit(value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("risk component scores must be finite and between 0 and 1")


class RiskFusionEngine:
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = {
            "anomaly": 0.45,
            "rules": 0.25,
            "threat_similarity": 0.15,
            "gemini_semantic": 0.15
        }
        if weights is not None:
            if not isinstance(weights, dict) or set(weights) != set(self.weights):
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

    def _weighted(self, anomaly_score: float, rule_score: float, pattern_similarity: float,
                  semantic_risk: Optional[int]) -> Fraction:
        w = {k: _exact(v) for k, v in self.weights.items()}
        total = (w["anomaly"] * _exact(anomaly_score) + w["rules"] * _exact(rule_score)
                 + w["threat_similarity"] * _exact(pattern_similarity)) * 100
        if semantic_risk is not None:
            return total + w["gemini_semantic"] * Fraction(semantic_risk)
        # Fallback path: renormalize remaining weights without Gemini
        return total / (w["anomaly"] + w["rules"] + w["threat_similarity"])

    def deterministic_score(self, anomaly_score: float, rule_score: float, pattern_similarity: float) -> int:
        """Score from anomaly + rules + threat memory only (Gemini term removed and
        renormalized). The policy uses it to tell whether a RESTRICT is corroborated
        without AI (spec §14 Scenario D)."""
        for value in (anomaly_score, rule_score, pattern_similarity):
            _check_unit(value)
        return _round_half_up(self._weighted(anomaly_score, rule_score, pattern_similarity, None))

    def compute_fused_risk(
        self,
        anomaly_score: float,
        rule_score: float,
        pattern_similarity: float,
        gemini_triage: Optional[Any],
        rule_reasons: List[ReasonCode]
    ) -> Tuple[int, List[ReasonCode], bool]:
        for value in (anomaly_score, rule_score, pattern_similarity):
            _check_unit(value)
        _check_unit(self.min_gemini_confidence)
        reasons = list(rule_reasons)
        requires_review = False

        if pattern_similarity >= 0.60:
            reasons.append(ReasonCode.KNOWN_PATTERN_SIMILARITY)

        semantic_risk = None
        if gemini_triage is not None:
            from app.ai.schemas import GeminiTriage
            # Revalidate constructed objects as well as ordinary JSON-derived models.
            gemini_triage = GeminiTriage.model_validate(gemini_triage.model_dump())
            semantic_risk = gemini_triage.semantic_risk
            is_high_severity = gemini_triage.category in HIGH_SEVERITY
            if gemini_triage.requires_human_review and not is_high_severity:
                requires_review = True
                reasons.append(ReasonCode.LOW_CONFIDENCE_REVIEW)

            if gemini_triage.category == "SUSPICIOUS_FRAUD_LIKE":
                reasons.append(ReasonCode.GEMINI_FRAUD_LIKE)
            elif gemini_triage.category == "POTENTIAL_ILLICIT_ACTIVITY":
                reasons.append(ReasonCode.GEMINI_POTENTIAL_ILLICIT)

            if is_high_severity and gemini_triage.confidence < self.min_gemini_confidence:
                requires_review = True
                reasons.append(ReasonCode.LOW_CONFIDENCE_REVIEW)

        weighted_score = self._weighted(anomaly_score, rule_score, pattern_similarity, semantic_risk)

        if rule_score >= 0.75 and anomaly_score >= 0.80:
            weighted_score = max(weighted_score, Fraction(55))

        final_score = _round_half_up(weighted_score)
        return final_score, sorted(set(reasons), key=lambda reason: str(reason)), requires_review
