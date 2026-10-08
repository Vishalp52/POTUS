"""Spec §7 risk fusion + policy engine: exact scoring, guardrails, config and decision record."""
import asyncio
import math
import random
from dataclasses import replace
from fractions import Fraction
from types import SimpleNamespace

import httpx
import pytest

from app.ai.schemas import GeminiTriage
from app.api import engine
from app.risk.fusion import RiskFusionEngine
from app.risk.policy import PolicyEngine
from app.risk.reason_codes import REASON_TEXT, ReasonCode, describe
from app.risk.rules import RuleEngine

SPEC_W = {"anomaly": Fraction(45, 100), "rules": Fraction(25, 100), "threat_similarity": Fraction(15, 100),
          "gemini_semantic": Fraction(15, 100)}


def triage(category="SUSPICIOUS_FRAUD_LIKE", confidence=0.86, semantic_risk=84, review=False):
    return GeminiTriage(category=category, confidence=confidence, semantic_risk=semantic_risk,
                        supporting_indicators=["synthetic"], benign_explanations=["synthetic"],
                        employee_summary="synthetic", customer_reason_code="SECURITY_REVIEW",
                        requires_human_review=review)


def reference_score(a, r, t, g=None):
    """Independent spec §7 formula on exact decimals, rounding x.5 up."""
    a, r, t = (Fraction(str(v)) * 100 for v in (a, r, t))
    if g is None:
        rest = SPEC_W["anomaly"] + SPEC_W["rules"] + SPEC_W["threat_similarity"]
        score = (SPEC_W["anomaly"] * a + SPEC_W["rules"] * r + SPEC_W["threat_similarity"] * t) / rest
    else:
        score = SPEC_W["anomaly"] * a + SPEC_W["rules"] * r + SPEC_W["threat_similarity"] * t + SPEC_W["gemini_semantic"] * g
    return max(0, min(100, math.floor(score + Fraction(1, 2))))


def reference_band(score):
    return "ALLOW" if score <= 34 else "CHALLENGE" if score <= 54 else "REVIEW" if score <= 74 else "RESTRICT"


# ------------------------------------------------------------------ accuracy
def test_fusion_matches_independent_reference_on_decimal_grid():
    fusion, policy, rng = RiskFusionEngine(), PolicyEngine(), random.Random(7)
    cases = 0
    for _ in range(20_000):
        a, r, t = (round(rng.randint(0, 100) / 100, 2) for _ in range(3))
        g = rng.choice([None, rng.randint(0, 100)])
        floor = r >= 0.75 and a >= 0.80
        t_in = triage("NORMAL_OR_BENIGN", 0.9, g) if g is not None else None
        score, _, forced = fusion.compute_fused_risk(a, r, t, t_in, [])
        expected = reference_score(a, r, t, g)
        expected = max(expected, 55) if floor else expected
        assert score == expected, (a, r, t, g)
        assert not forced
        assert policy.evaluate(score, [])["decision"] == reference_band(score)
        cases += 1
    assert cases == 20_000


@pytest.mark.parametrize("a, r, t, g, score, decision", [
    (0.24, 0.0, 0.78, 80, 35, "CHALLENGE"),   # exact 34.5
    (0.4, 0.8, 0.555, None, 55, "REVIEW"),    # exact 54.5, Gemini unavailable
    (0.44, 1.0, 0.98, 100, 75, "RESTRICT"),   # exact 74.5
])
def test_half_point_ties_round_up_into_stricter_band(a, r, t, g, score, decision):
    t_in = None if g is None else triage("NORMAL_OR_BENIGN", 0.9, g)
    risk, _, forced = RiskFusionEngine().compute_fused_risk(a, r, t, t_in, [])
    assert risk == score
    assert PolicyEngine().evaluate(risk, [], forced)["decision"] == decision


@pytest.mark.parametrize("score, decision", [(0, "ALLOW"), (34, "ALLOW"), (35, "CHALLENGE"), (54, "CHALLENGE"),
                                             (55, "REVIEW"), (74, "REVIEW"), (75, "RESTRICT"), (100, "RESTRICT")])
def test_policy_threshold_edges(score, decision):
    assert PolicyEngine().evaluate(score, [])["decision"] == decision


def test_gemini_moves_score_by_at_most_its_weight():
    fusion = RiskFusionEngine()
    for a, r, t in [(0, 0, 0), (0.5, 0.5, 0.5), (1, 1, 1), (0.37, 0.12, 0.91)]:
        low = fusion.compute_fused_risk(a, r, t, triage("NORMAL_OR_BENIGN", 0.9, 0), [])[0]
        high = fusion.compute_fused_risk(a, r, t, triage("NORMAL_OR_BENIGN", 0.9, 100), [])[0]
        assert 0 <= high - low <= 15


# ------------------------------------------------------------------ guardrails
def test_low_confidence_ai_cannot_downgrade_corroborated_restrict():
    fusion, policy = RiskFusionEngine(), PolicyEngine()
    a, r, t = 0.95, 0.8, 0.7
    deterministic = fusion.deterministic_score(a, r, t)
    assert reference_band(deterministic) == "RESTRICT"
    for t_in in (triage("SUSPICIOUS_FRAUD_LIKE", 0.69), triage("INSUFFICIENT_EVIDENCE", 0.5, 35, review=True)):
        risk, reasons, forced = fusion.compute_fused_risk(a, r, t, t_in, [])
        assert forced and ReasonCode.LOW_CONFIDENCE_REVIEW in reasons
        assert policy.evaluate(risk, reasons, forced, deterministic_score=deterministic)["decision"] == "RESTRICT"


def test_uncertain_ai_with_low_semantic_risk_cannot_pull_corroborated_restrict_down():
    fusion = RiskFusionEngine()
    a, r, t = 0.93, 0.91, 0.02
    deterministic = fusion.deterministic_score(a, r, t)
    risk, reasons, forced = fusion.compute_fused_risk(a, r, t, triage("SUSPICIOUS_FRAUD_LIKE", 0.5, 1), [])
    assert reference_band(deterministic) == "RESTRICT" and reference_band(risk) == "REVIEW" and forced
    assert PolicyEngine().evaluate(risk, reasons, forced, deterministic_score=deterministic)["decision"] == "RESTRICT"


def test_low_confidence_ai_alone_routes_to_review_not_restrict():
    fusion, policy = RiskFusionEngine(), PolicyEngine()
    a, r, t = 0.8, 0.5, 0.5  # deterministic 66: REVIEW band without AI
    deterministic = fusion.deterministic_score(a, r, t)
    assert reference_band(deterministic) != "RESTRICT"
    risk, reasons, forced = fusion.compute_fused_risk(a, r, t, triage("POTENTIAL_ILLICIT_ACTIVITY", 0.51, 100, True), [])
    assert forced
    assert policy.evaluate(risk, reasons, forced, deterministic_score=deterministic)["decision"] == "REVIEW"
    low_risk, reasons, forced = fusion.compute_fused_risk(0.05, 0, 0, triage("SUSPICIOUS_FRAUD_LIKE", 0.6, 20), [])
    assert reference_band(low_risk) == "ALLOW"
    assert policy.evaluate(low_risk, reasons, forced, deterministic_score=0)["decision"] == "REVIEW"


def test_strong_rules_and_high_anomaly_reach_at_least_review():
    risk, _, _ = RiskFusionEngine().compute_fused_risk(0.80, 0.75, 0.0, None, [])
    assert PolicyEngine().evaluate(risk, [])["decision"] in {"REVIEW", "RESTRICT"}


# ------------------------------------------------------------------ configuration
@pytest.mark.parametrize("thresholds", [
    {"allow_max": 60, "challenge_max": 40, "review_max": 74},
    {"allow_max": "34", "challenge_max": 54, "review_max": 74},
    {"allow_max": True, "challenge_max": 54, "review_max": 74},
    {"allow_max": 34.9, "challenge_max": 54, "review_max": 74},
    {"allow_max": -5, "challenge_max": 54, "review_max": 74},
    {"allow_max": 34, "challenge_max": 54, "review_max": 100},
    {"allow_max": 34, "challenge_max": 54},
    {"allow_max": 34, "challenge_max": 54, "review_max": 74, "reveiw_max": 70},
    [34, 54, 74],
])
def test_invalid_policy_thresholds_are_rejected(thresholds):
    with pytest.raises(ValueError):
        PolicyEngine(thresholds)


@pytest.mark.parametrize("score", [-1, 101, 34.5, True, float("nan"), "50"])
def test_policy_rejects_invalid_scores(score):
    with pytest.raises(ValueError):
        PolicyEngine().evaluate(score, [])


@pytest.mark.parametrize("value", ["0.5", None, 1j])
def test_fusion_rejects_non_numeric_components_with_value_error(value):
    with pytest.raises(ValueError):
        RiskFusionEngine().compute_fused_risk(value, 0.1, 0.1, None, [])


@pytest.mark.parametrize("controls", [
    "restrict_ttl_minutes: -5", "restrict_ttl_minutes: 0", "restrict_ttl_minutes: 0.9", "restrict_ttl_minutes: true",
    "restrict_ttl_minutes: '20'", "restrict_ttl_minutes: 100000", "low_confidence_high_severity_action: RESTRICT",
])
def test_invalid_risk_controls_fail_at_load(tmp_path, monkeypatch, controls):
    path = tmp_path / "risk.yaml"
    path.write_text(f"controls:\n  {controls}\n")
    monkeypatch.setattr(engine, "settings", replace(engine.settings, risk_config_path=str(path)))
    with pytest.raises(ValueError):
        engine.load_risk_config()


def test_invalid_thresholds_in_risk_file_fail_at_load(tmp_path, monkeypatch):
    path = tmp_path / "risk.yaml"
    path.write_text("thresholds:\n  allow_max: 60\n  challenge_max: 40\n  review_max: 74\n")
    monkeypatch.setattr(engine, "settings", replace(engine.settings, risk_config_path=str(path)))
    with pytest.raises(ValueError):
        engine.load_risk_config()


def test_gemini_client_typo_does_not_break_mock_mode(monkeypatch):
    monkeypatch.setenv("GEMINI_API", "bogus")
    assert engine.settings.gemini_mode == "mock"
    assert engine.Components._gemini_client() is None


# ------------------------------------------------------------------ reason codes
def test_every_reason_code_has_employee_and_customer_text():
    assert set(REASON_TEXT) == set(ReasonCode)
    for code in ReasonCode:
        text = describe(code.value)
        assert text["employee"] and text["customer"]
        assert not any(word in text["customer"].lower() for word in ("gemini", "threshold", "incident", "model"))


@pytest.mark.parametrize("age, cold", [(0, True), (999, True), (1000, False), (None, False)])
def test_cold_start_wallet_includes_new_wallets(age, cold):
    evidence = {} if age is None else {"wallet_age_blocks": age}
    assert (ReasonCode.COLD_START_WALLET in RuleEngine().evaluate(evidence)[1]) == cold


def test_provider_read_timeout_is_reported_as_timeout():
    from app.ai.gemini_client import GeminiTriageClient

    async def generate_content(**_):
        raise httpx.ReadTimeout("slow")

    fake = SimpleNamespace(aio=SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)))
    client = GeminiTriageClient(client=fake)
    with pytest.raises(TimeoutError):
        asyncio.run(client.triage({"anomaly_score": 0.9}))


# ------------------------------------------------------------------ API: RESTRICT TTL + decision record
def request(client, wallet, scenario):
    response = client.post("/access/request", json={"wallet": wallet, "demo_scenario": scenario})
    assert response.status_code == 200, response.text
    return response.json()


def test_restrict_holds_for_ttl_even_if_next_score_is_clean(client, scenarios):
    wallet = scenarios["C"]["wallet"]
    first = request(client, wallet, "C")
    assert first["decision"] == "RESTRICT"
    second = request(client, wallet, "A")
    assert second["decision"] == "RESTRICT"
    assert second["access_token"] is None
    assert second["expires_at"] == first["expires_at"]
    packet = client.get(f"/cases/{second['request_id']}").json()
    assert any("Active RESTRICT" in note for note in packet["policy_trace"]["guardrails"])


def test_restrict_lifts_after_analyst_closes_case(client, scenarios):
    wallet = scenarios["C"]["wallet"]
    first = request(client, wallet, "C")
    assert client.post(f"/cases/{first['request_id']}/review", json={"disposition": "BENIGN"}).status_code == 200
    assert request(client, wallet, "A")["decision"] == "ALLOW"


def test_decision_record_is_persisted_with_reason_codes(client, scenarios):
    from app.api.state import SessionLocal
    from app.db.models import RiskEvaluationModel
    result = request(client, scenarios["C"]["wallet"], "C")
    with SessionLocal() as session:
        row = session.get(RiskEvaluationModel, result["request_id"])
    assert row is not None
    assert row.decision == result["decision"] and row.risk_score == result["risk_score"]
    assert row.reason_codes == result["reason_codes"]
    assert set(row.component_scores) >= {"anomaly", "rules", "threat_similarity"}
    assert row.expiry is not None


def test_missing_chain_data_reviews_without_inflating_score(client):
    result = client.post("/access/request", json={"wallet": "0x" + "7" * 40}).json()
    assert result["decision"] == "REVIEW"
    assert "CHAIN_DATA_UNAVAILABLE" in result["reason_codes"]
    packet = client.get(f"/cases/{result['request_id']}").json()
    points = sum(part["points"] for part in packet["risk_summary"]["components"].values())
    assert abs(points - result["risk_score"]) <= 1
