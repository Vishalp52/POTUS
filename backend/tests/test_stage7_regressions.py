import math
import pytest
import joblib
from app.models import model_store
from app.models.isolation_forest import AnomalyDetector, synthetic_normal
from app.risk.fusion import RiskFusionEngine
from app.ai.schemas import GeminiTriage
from tests.test_gemini_integration import VALID

@pytest.mark.parametrize("weights", [
    {}, {"anomaly": 1},
    dict(anomaly=.2, rules=.2, threat_similarity=.1, gemini_semantic=.5),
    dict(anomaly=.45, rules=.25, threat_similarity=.15, gemini_semantic=.25),
    dict(anomaly=math.nan, rules=.25, threat_similarity=.15, gemini_semantic=.15),
    dict(anomaly=.8, rules=-.1, threat_similarity=.15, gemini_semantic=.15),
])
def test_invalid_weights_fail_closed(weights):
    with pytest.raises(ValueError):
        RiskFusionEngine(weights)

@pytest.mark.parametrize("value", [math.nan, math.inf, -.1, 1.1, True])
def test_invalid_component_rejected(value):
    with pytest.raises(ValueError):
        RiskFusionEngine().compute_fused_risk(value, .2, .1, None, [])

def test_ai_alone_has_bounded_authority_and_fallback_renormalizes():
    engine = RiskFusionEngine()
    triage = GeminiTriage(**{**VALID, "semantic_risk": 100})
    assert engine.compute_fused_risk(0, 0, 0, triage, [])[0] == 15
    assert engine.compute_fused_risk(1, 1, 1, None, [])[0] == 100

def test_uncertain_request_for_review_is_preserved():
    triage = GeminiTriage(**{**VALID, "category": "INSUFFICIENT_EVIDENCE", "requires_human_review": True})
    assert RiskFusionEngine().compute_fused_risk(.4, .1, 0, triage, [])[2]

def test_cached_detector_invalidates_on_changed_training_data(tmp_path, monkeypatch):
    monkeypatch.setattr(model_store, "_detector", None)
    fingerprint = ["first"]
    monkeypatch.setattr(model_store, "training_fingerprint", lambda: fingerprint[0])
    detector = AnomalyDetector().fit(synthetic_normal(30), "first", "first")
    path = tmp_path / "model.joblib"
    joblib.dump(detector, path)
    assert model_store.load_detector(str(path)).trained_on == "first"
    fingerprint[0] = "second"
    replacement = AnomalyDetector().fit(synthetic_normal(30), "second", "second")
    monkeypatch.setattr(model_store, "train_and_save", lambda path: replacement)
    assert model_store.load_detector(str(path)) is replacement

def test_sklearn_version_change_invalidates_artifact():
    detector = AnomalyDetector().fit(synthetic_normal(30), "test", model_store.training_fingerprint())
    detector.sklearn_version = "incompatible"
    assert not model_store._artifact_compatible(detector)

def test_threat_memory_rejects_bad_vectors_and_owns_its_copy():
    from app.memory.threat_store import ThreatStore
    from app.memory.similarity import cosine_similarity
    memory = ThreatStore()
    vector = [1., 2., 3.]
    memory.insert_incident("one", vector, "SUSPICIOUS_FRAUD_LIKE", "CONFIRMED_INCIDENT", "hash")
    vector[0] = 99
    similarity, incident = memory.find_max_similarity([1., 2., 3.])
    assert similarity == pytest.approx(1.) and incident == "one"
    with pytest.raises(ValueError):
        memory.insert_incident("bad", [math.nan], "bad", "CONFIRMED_INCIDENT", "hash")
    memory.insert_incident("one", [2., 3., 4.], "bad", "CONFIRMED_INCIDENT", "hash")
    assert len(memory._stored_incidents) == 1
    assert math.isclose(cosine_similarity([1e308, 1e308], [1e308, 1e308]), 1)
