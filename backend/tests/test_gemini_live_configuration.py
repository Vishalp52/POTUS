"""Prevent regressions in the configuration verified against live Gemini."""
import asyncio
import json
import httpx
import pytest
from pydantic import ValidationError
from app.ai.gemini_client import GeminiTriageClient
from app.ai.schemas import GeminiTriage, provider_schema
from tests.test_gemini_integration import VALID, EVIDENCE, sdk_with_transport
from evaluate import summarize_results


def test_provider_schema_uses_supported_keywords_without_weakening_validation():
    schema = provider_schema()
    assert set(schema['required']) == set(GeminiTriage.model_fields)
    assert schema['additionalProperties'] is False
    assert schema['properties']['semantic_risk']['maximum'] == 100
    assert schema['properties']['benign_explanations']['minItems'] == 1
    assert 'maxLength' not in json.dumps(schema)
    assert 'maxLength' in json.dumps(GeminiTriage.model_json_schema())
    with pytest.raises(ValidationError):
        GeminiTriage(**{**VALID, 'employee_summary': 'x' * 2001})
    with pytest.raises(ValidationError):
        GeminiTriage(**{**VALID, 'benign_explanations': []})


@pytest.mark.parametrize('mode', ['generate_content', 'interactions'])
@pytest.mark.parametrize('level', ['low', 'default'])
def test_thinking_configuration_in_actual_sdk_request(monkeypatch, mode, level):
    monkeypatch.setenv('GEMINI_API', mode)
    monkeypatch.setenv('GEMINI_THINKING_LEVEL', level)
    seen = []
    def handler(req):
        seen.append(json.loads(req.content))
        if mode == 'generate_content':
            payload = {'candidates': [{'content': {'role': 'model', 'parts': [{'text': json.dumps(VALID)}]}, 'finishReason': 'STOP'}]}
        else:
            payload = {'id': 'test', 'status': 'completed', 'steps': [{'type': 'model_output', 'content': [{'type': 'text', 'text': json.dumps(VALID)}]}]}
        return httpx.Response(200, json=payload)
    async def run():
        adapter = GeminiTriageClient(client=sdk_with_transport(handler))
        try:
            assert await adapter.triage(EVIDENCE) is not None
        finally:
            await adapter.aclose()
    asyncio.run(run())
    assert len(seen) == 1
    if mode == 'generate_content':
        config = seen[0]['generationConfig']
        assert config.get('thinkingConfig') == ({'thinking_level': 'LOW'} if level == 'low' else None)
    else:
        assert seen[0]['generation_config'].get('thinking_level') == ('low' if level == 'low' else None)


def test_invalid_thinking_level_rejected(monkeypatch):
    monkeypatch.setenv('GEMINI_THINKING_LEVEL', 'typo')
    with pytest.raises(ValueError):
        GeminiTriageClient()


def test_evaluation_separates_unavailability_from_wrong_classification():
    summary = summarize_results([
        {'id': 'one', 'triage': VALID, 'category_matches_fixture': True, 'elapsed_seconds': 1},
        {'id': 'two', 'triage': VALID, 'category_matches_fixture': False, 'elapsed_seconds': 2},
        {'id': 'three', 'triage': None, 'category_matches_fixture': None, 'elapsed_seconds': 12},
    ])
    assert summary['accepted_fraction'] == 2 / 3
    assert summary['fixture_match_count'] == 1
    assert summary['fixture_mismatch_ids'] == ['two']
    assert summary['unavailable_ids'] == ['three']
    assert summary['latency_seconds']['95'] == 12
