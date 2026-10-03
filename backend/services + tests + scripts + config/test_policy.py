from app.ai.schemas import GeminiTriage
from app.risk.fusion import RiskFusionEngine
from app.risk.policy import PolicyEngine
from app.risk.reason_codes import ReasonCode

def test_low_confidence_severity_routes_to_review():
    triage = GeminiTriage(
        category="POTENTIAL_ILLICIT_ACTIVITY",
        confidence=0.51,
        semantic_risk=90,
        supporting_indicators=["synthetic typology match"],
        benign_explanations=["limited history"],
        employee_summary="ambiguous",
        customer_reason_code="SECURITY_REVIEW",
        requires_human_review=True
    )

    fusion = RiskFusionEngine()
    policy = PolicyEngine()

    risk_score, reasons, forced_review = fusion.compute_fused_risk(
        anomaly_score=0.8,
        rule_score=0.2,
        pattern_similarity=0.1,
        gemini_triage=triage,
        rule_reasons=[ReasonCode.ACCESS_BURST]
    )

    result = policy.evaluate(risk_score, reasons, forced_review)
    assert result["decision"] == "REVIEW"