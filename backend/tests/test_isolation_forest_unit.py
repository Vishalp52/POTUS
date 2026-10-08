"""Focused ML tests that do not require RPC, Envio, Gemini, or FastAPI."""

from app.features.schemas import MODEL_FEATURES, VECTOR_VERSION
from app.models.isolation_forest import AnomalyDetector, load_training_frame, normalize_anomaly

NORMAL = [2, 8, 4, 0.2, 0.0, 1, 0, 0]
ANOMALOUS = [38, 40, 14, 1.0, 10.0, 45, 6, 0]


def test_training_frame_matches_model_contract():
    frame, source = load_training_frame()
    assert len(frame) >= 2
    assert list(frame.columns) == MODEL_FEATURES
    assert source.startswith("csv:") or source == "synthetic"


def test_detector_separates_normal_and_anomalous_behavior():
    frame, source = load_training_frame()
    detector = AnomalyDetector().fit(frame, source)
    normal_score = detector.score(NORMAL)
    anomalous_score = detector.score(ANOMALOUS)
    assert 0.0 <= normal_score <= 1.0
    assert 0.0 <= anomalous_score <= 1.0
    assert anomalous_score > normal_score


def test_detector_is_deterministic():
    frame, source = load_training_frame()
    first = AnomalyDetector().fit(frame, source)
    second = AnomalyDetector().fit(frame, source)
    assert first.score(ANOMALOUS) == second.score(ANOMALOUS)
    assert first.info()["vector_version"] == VECTOR_VERSION


def test_batch_scoring_matches_single_scoring():
    frame, source = load_training_frame()
    detector = AnomalyDetector().fit(frame, source)
    assert detector.score_many([NORMAL, ANOMALOUS]) == [detector.score(NORMAL), detector.score(ANOMALOUS)]


def test_vector_contract_is_rejected():
    frame, source = load_training_frame()
    detector = AnomalyDetector().fit(frame, source)
    try:
        detector.score(NORMAL[:-1])
    except ValueError as exc:
        assert "expected 8" in str(exc)
    else:
        raise AssertionError("invalid vector length was accepted")


def test_normalize_anomaly_clamps_to_unit_interval():
    assert normalize_anomaly(-1.0, 0.0, 1.0) == 0.0
    assert normalize_anomaly(0.5, 0.0, 1.0) == 0.5
    assert normalize_anomaly(2.0, 0.0, 1.0) == 1.0
