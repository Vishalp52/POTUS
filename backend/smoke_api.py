"""Exercise real Gemini through FastAPI in an isolated, simulated access flow.

python backend/smoke_api.py --output backend/evaluation/live-api-smoke.json
Requires the development dependencies and GEMINI_API_KEY (or GOOGLE_API_KEY).
Creates no real chain writes and keeps cases/audits in a temporary database.
"""
import argparse
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='backend/evaluation/live-api-smoke.json')
    args = parser.parse_args()
    # Read only the explicit project environment; process environment wins.
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / '.env')
    if not (os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')):
        raise SystemExit('Set GEMINI_API_KEY before running the live API smoke test.')
    with tempfile.TemporaryDirectory(prefix='potus-live-smoke-') as temp:
        admin = secrets.token_urlsafe(32)
        os.environ.update(GEMINI_MODE='auto', DATA_SOURCE='none', APP_ENV='development',
            ENABLE_DEMO='true', REQUIRE_WALLET_SIGNATURE='false', POTUS_REGISTRY_ADDRESS='',
            ORACLE_PRIVATE_KEY='', DATABASE_URL='sqlite:///' + str(Path(temp) / 'smoke.db'),
            POTUS_ADMIN_KEY=admin, TOKEN_SECRET=secrets.token_urlsafe(32))
        from fastapi.testclient import TestClient
        from main import app
        from app.api.engine import components
        checks = {}
        with TestClient(app, headers={'X-API-Key': admin}) as client:
            attack = client.post('/access/request', json={
                'wallet': '0x' + 'a' * 40, 'resource_id': 'research-vault', 'demo_scenario': 'C'})
            checks['access_http_200'] = attack.status_code == 200
            data = attack.json()
            checks['live_triage_accepted'] = data.get('signals', {}).get('gemini_status') == 'ok'
            checks['simulated_evidence'] = data.get('simulated') is True
            checks['attack_held'] = data.get('decision') in {'REVIEW', 'RESTRICT'}
            checks['no_access_token'] = data.get('access_token') is None
            checks['vault_denied'] = client.get('/vault/research-vault').status_code in {401, 403}
            case = client.get('/cases/' + data.get('request_id', 'missing'))
            checks['employee_case_available'] = case.status_code == 200
            outage = client.post('/score', json={
                'wallet': '0x' + 'b' * 40, 'demo_scenario': 'F', 'simulate_ai_outage': True})
            fallback = outage.json()
            checks['outage_returns_decision'] = outage.status_code == 200 and fallback.get('decision') in {'ALLOW', 'CHALLENGE', 'REVIEW', 'RESTRICT'}
            checks['outage_removes_ai'] = fallback.get('gemini_triage') is None and 'gemini_semantic' not in fallback.get('breakdown', {})
            checks['registry_disabled'] = components().registry.enabled is False
            report = {'checked_at': datetime.now(timezone.utc).isoformat(),
                'model': components().gemini.model_name, 'checks': checks,
                'passed': all(checks.values()),
                'live_status': data.get('signals', {}).get('gemini_status'),
                'live_category': (data.get('signals', {}).get('gemini') or {}).get('category'),
                'decision': data.get('decision'), 'risk_score': data.get('risk_score'),
                'limitations': 'Synthetic replay through the real API/Gemini path; temporary database; registry disabled.'}
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        if not report['passed']:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
