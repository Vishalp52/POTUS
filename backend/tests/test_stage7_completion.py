"""Regression coverage for the final stage-7 API and configuration boundary."""
import math
from dataclasses import replace

import pytest

from app.api import engine
from app.api.settings import Settings
from app.features.schemas import BehaviorFeatures
from app.risk.rules import RuleEngine


def test_raw_score_retains_flags_confidence_and_versions(client):
    response = client.post('/score', json={'features': {
        'tx_count_10m': 40, 'tx_count_1h': 80, 'access_requests_10m': 25,
        'transfer_value_zscore': 4, 'failed_access_count': 5,
        'flagged_counterparty_count': 1,
    }})
    assert response.status_code == 200
    body = response.json()
    assert {'ACCESS_BURST', 'VALUE_OUTLIER', 'REPEATED_DENIALS', 'FLAGGED_COUNTERPARTY'} <= set(body['hard_flags'])
    assert body['history_confidence'] == 'low'
    assert body['data_source'] == 'provided'
    assert body['simulated'] is False
    assert body['prompt_version'] and body['vector_version'] == 'v1-8f'
    assert client.get('/cases').json()['cases'] == []
    schema = client.get('/openapi.json').json()
    assert schema['paths']['/score']['post']['responses']['200']['content']['application/json']['schema']['$ref'].endswith('/ScoreEvaluation')


def test_raw_novelty_ratio_uses_fractional_baseline():
    b = engine.bundle_from_features(BehaviorFeatures(new_contract_ratio=.8), '0x' + '0' * 40, 'research-vault')
    delta = b.feature_deltas['new_contract_ratio']
    assert delta['ratio'] == round(.8 / delta['baseline'], 2)
    assert delta['ratio'] > .8
    assert 'NEW_CONTRACT_SPIKE' not in b.hard_flags  # no 1h contract count provided


def test_access_flood_counts_once_even_with_chain_burst():
    rules = RuleEngine()
    evidence = {'feature_deltas': {'access_requests_10m': {'value': 20}}}
    score, reasons = rules.evaluate(evidence)
    assert score == .3 and [r.value for r in reasons] == ['ACCESS_BURST']
    evidence['feature_deltas']['tx_count_10m'] = {'ratio': 10}
    assert rules.evaluate(evidence)[0] == .3


@pytest.mark.parametrize('age, confidence, cold', [(None, 'low', False), (0, 'low', True), (999, 'low', True), (1000, 'normal', False)])
def test_raw_history_does_not_invent_wallet_age(age, confidence, cold):
    b = engine.bundle_from_features(BehaviorFeatures(wallet_age_blocks=age), '0x' + '0' * 40, 'research-vault')
    assert b.history_confidence == confidence
    assert ('COLD_START_WALLET' in b.hard_flags) == cold


@pytest.mark.parametrize('content', ['', '[]', 'weights: [', 'controls: []',
    'controls: {gemini_min_confidence_for_severity: .nan}',
    'controls: {gemini_min_confidence_for_severity: 2}'])
def test_invalid_risk_file_never_silently_uses_defaults(tmp_path, monkeypatch, content):
    path = tmp_path / 'risk.yaml'
    path.write_text(content)
    monkeypatch.setattr(engine, 'settings', replace(engine.settings, risk_config_path=str(path)))
    with pytest.raises(ValueError):
        engine.load_risk_config()


@pytest.mark.parametrize('kwargs', [dict(gemini_mode='typo'), dict(gemini_timeout_seconds=0),
    dict(gemini_timeout_seconds=math.nan), dict(gemini_trigger_score=math.inf), dict(gemini_trigger_score=1.1)])
def test_invalid_gemini_controls_fail_at_startup(kwargs):
    with pytest.raises(ValueError):
        Settings(**kwargs)


@pytest.mark.parametrize('name', ['GEMINI_TIMEOUT_SECONDS', 'GEMINI_TRIGGER_SCORE'])
def test_malformed_gemini_environment_is_not_silently_defaulted(monkeypatch, name):
    monkeypatch.setenv(name, 'not-a-number')
    with pytest.raises(ValueError):
        Settings()
