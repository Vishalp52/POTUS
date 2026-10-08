import asyncio
from app.api.settings import settings
from app.risk.rules import RuleEngine
from app.risk.fusion import RiskFusionEngine
from app.risk.policy import PolicyEngine
from app.ai.gemini_client import GeminiTriageClient
from app.memory.threat_store import ThreatStore

class EvaluatorService:
    def __init__(self, risk_config: dict):
        self.rules = RuleEngine()
        self.fusion = RiskFusionEngine(weights=risk_config.get("weights"))
        self.fusion.min_gemini_confidence = float(risk_config.get("controls", {}).get("gemini_min_confidence_for_severity", 0.70))
        self.policy = PolicyEngine(thresholds=risk_config.get("thresholds"))
        self.gemini = GeminiTriageClient()
        self.threat_store = ThreatStore()

    async def evaluate_request(self, evidence: dict, anomaly_score: float, vector: list[float]):
        rule_score, rule_reasons = self.rules.evaluate(evidence)
        pattern_similarity, _ = self.threat_store.find_max_similarity(vector)
        
        evidence = {**evidence, "anomaly_score": anomaly_score, "pattern_similarity": pattern_similarity}
        gemini_triage = None
        if anomaly_score >= settings.gemini_trigger_score and settings.gemini_mode != "off":
            try:
                if settings.gemini_mode == "mock":
                    from app.api.engine import mock_triage
                    gemini_triage = mock_triage(evidence, [r.value for r in rule_reasons])
                else:
                    gemini_triage = await asyncio.wait_for(self.gemini.triage(evidence), settings.gemini_timeout_seconds)
            except Exception:
                gemini_triage = None

        risk_score, reasons, forced_review = self.fusion.compute_fused_risk(
            anomaly_score=anomaly_score,
            rule_score=rule_score,
            pattern_similarity=pattern_similarity,
            gemini_triage=gemini_triage,
            rule_reasons=rule_reasons
        )

        return self.policy.evaluate(risk_score, reasons, forced_review)