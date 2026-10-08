# POTUS backend — API, chain, features, models

This covers the API, chain adapters, feature extraction, models, and backend
persistence in the POTUS build specification (§§4, 5, 8, 12, 14).
This delivery completes the backend stages through risk fusion (architecture stage 7).
Frontend and stage-8 policy implementation are outside the changes. See ../README.md.

## Run it

```bash
pip install -r requirements-dev.txt    # from repo root; runtime + test dependencies
cd backend
cp .env.example .env                   # fill in what you have
uvicorn main:app --reload --port 8000  # docs at http://localhost:8000/docs
python -m pytest tests -q              # API, security, retrieval and persistence tests; fully offline
```

For a reliable recorded demo with no API keys: `GEMINI_MODE=mock`.
From the repository root, `python -m pytest -q` also includes the standalone policy test.
Tests use temporary databases and model files, with live data retrieval disabled.

## Pipeline (spec §4)

```
POST /access/request
  -> app/chain/source.py      demo replay | Envio HyperSync | Monad RPC | none
  -> app/features/extractor   feature vector, deltas vs baseline, hard flags
  -> app/models               IsolationForest -> anomaly_score 0..1
  -> app/memory    cosine similarity vs confirmed incident signatures
  -> app/risk/rules
  -> app/ai        Gemini triage only if anomaly >= GEMINI_TRIGGER_SCORE (timeout + fallback)
  -> app/risk/fusion+policy  ALLOW / CHALLENGE / REVIEW / RESTRICT
  -> app/chain/registry.py    minimal on-chain record (score, expiry, decision, evidence hash)
  -> case record (employee view) + customer-safe payload
```

## Security

See **[SECURITY.md](SECURITY.md)** for the threat model. In short: wallet-ownership
signatures, signed short-lived vault tokens, API-key roles for the employee console,
rate limits, strict input validation, security headers, fail-closed production config,
and layered prompt-injection defenses for Gemini.

**Auth legend:** 🌐 public (rate-limited) · 🔑 employee key (`X-API-Key`) · 🛡 admin key

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET 🌐 | `/auth/nonce?wallet=` | One-time message for the wallet to sign |
| POST 🌐 | `/access/request` | Full evaluation for wallet + resource + action. Send `nonce` + `signature` to prove ownership (required in production). ALLOW returns an `access_token` |
| GET 🔑 | `/wallet/{address}/features` | Feature vector + baseline comparisons (no side effects) |
| POST 🔑 | `/score` | Detector + rules + memory + Gemini + policy, no case / no on-chain write. Accepts `wallet` or raw `features` |
| GET 🔑 | `/wallet/{address}/risk` | Latest decision, expiry, score, reason codes |
| POST 🔑 | `/incident/confirm` | Store a reviewed incident signature in threat memory |
| GET 🔑 | `/incidents` | Incident patterns for the employee console |
| GET 🔑 | `/cases` | Case list (filter `?status=OPEN`) |
| GET 🔑 | `/cases/{id}` | Full employee investigation packet (§10 panels) |
| POST 🔑 | `/cases/{id}/review` | Analyst disposition + note (reviewer = API-key owner); confirmed incidents enter memory |
| GET 🌐 | `/customer/status/{request_id}` | Customer-safe status + next step |
| GET 🌐 | `/access/{request_id}/challenge` | One-time, expiring message to sign for a CHALLENGE |
| POST 🌐 | `/access/{request_id}/verify` | `{nonce, signature}` resolves a CHALLENGE and returns an `access_token` |
| GET 🌐 | `/vault/research-vault` | Protected resource. `Authorization: Bearer <access_token>`; re-checks live case state |
| GET · POST 🛡 | `/demo/scenarios` · `/demo/reset` | Deterministic scenarios A–F; reset (admin). Disabled in production |
| GET 🌐 / 🔑 | `/health` · `/health/details` | Liveness only · full status (employee) |

## Demo scenarios (labeled SIMULATED)

Use the fixed demo wallets from `/demo/scenarios`, or send `"demo_scenario": "C"`
with a real connected wallet. Current results with `GEMINI_MODE=mock`:

| | Scenario | Result |
|---|---|---|
| A | Normal wallet | ~1 → ALLOW |
| B | Slight anomaly | ~35 → CHALLENGE |
| C | Account-takeover style | ~78 → RESTRICT |
| D | Potential illicit typology | ~73 → REVIEW |
| E | Pattern recurrence | ~69 REVIEW before; ~82 RESTRICT after C is confirmed |
| F | Gemini unavailable | ~77 → RESTRICT via deterministic fallback |

Demo flow: `POST /demo/reset` → A → B → C → open the C case → `POST /cases/{id}/review`
with `CONFIRMED_INCIDENT` → E (similarity ~0.91, escalates).

## Notes for the frontend

* Decision codes on-chain: `0 ALLOW, 1 CHALLENGE, 2 REVIEW, 3 RESTRICT`.
* Customer UI should only render the `customer` object; the employee UI uses `/cases/{id}`.
* Wallet sign-in: `GET /auth/nonce?wallet=` → `signMessage(message)` (wagmi/viem) → send `nonce` + `signature` with `/access/request`.
* Vault: send `Authorization: Bearer <access_token>` from the ALLOW (or challenge-verify) response.
* Employee console: send `X-API-Key`. Never ship the key in public frontend code; put it behind the console's own login or a server-side proxy.

## Compatibility with shared backend modules

`app/api/teammate.py` retains compatibility with older copies of the shared modules:

1. `app/risk/reason_codes.py` now exports the same enum as the historical `reasons_codes.py` filename.
2. `app/risk/policy.py` imports `Optional`, so risk modules also work without the API bootstrap.
3. `GeminiTriage` emits canonical underscore labels; a validator still accepts the two historical space-separated labels when reading old records.

`requirements.txt`: `websockets` pinned to 16.1.1 (google-genai requires <17) and
`google-genai` + `PyYAML` added — the Gemini client and risk.yaml loading need them.

## Retrieval and data handling

* `DATA_SOURCE=auto` tries configured Envio history, then bounded Monad RPC; `none`
  disables live retrieval. Demo replay requires `ENABLE_DEMO=true` and is labeled simulated.
* Envio uses actual block timestamps to cover the requested day, follows forward
  pagination through empty pages, rejects incomplete responses, and deduplicates
  self-transfers. A stale index falls back to RPC. The adapter follows the
  [HyperSync query contract](https://docs.envio.dev/docs/HyperSync/hypersync-query).
* RPC scans exactly `RPC_SCAN_BLOCKS` blocks (including genesis where applicable).
  Missing blocks are disclosed; total scan failure triggers the unavailable path.
  Bounded RPC scans cannot establish a wallet's first-ever activity or a full day.
* Future-dated and out-of-window transactions do not contribute to features.
  Unknown age and incomplete history carry low confidence. Raw feature inputs
  must be finite and within the supported ranges.
* If both sources fail, otherwise permissive decisions become `REVIEW` with
  `CHAIN_DATA_UNAVAILABLE`; no access token is issued. Stronger restrictions remain.
* `python collect_monad_data.py --blocks 150 --output ../data/real/new_sample.csv`
  collects an explicit RPC sample from the backend directory. Imports do not
  contact the network or write files. Output includes its observed block span;
  a zero-duration sample has no measured transaction rate. See `../data/README.md`.

## Incident persistence

Confirmed incidents retain wallet, source case, simulation label, and vector
version in SQLite/Postgres. Startup adds a nullable `source` JSON column to older
incident tables without deleting existing records. Legacy rows with unknown
provenance remain labeled unknown; explicitly simulated records are excluded
when demo mode is disabled. Only reviewed, finite, compatible vectors are loaded.
Repeated/concurrent confirmations are idempotent, and a failed save returns 503
so the caller can retry instead of assuming the incident was persisted.

## Limitations (say these honestly in the pitch)

* Plain Monad RPC has no address index: the RPC path scans only the last `RPC_SCAN_BLOCKS` blocks; the 24h window needs Envio HyperSync.
* Cases/access history are in memory (requests, incident signatures/provenance, and audit events persist to SQLite). The full case/review/feature snapshot tables proposed in §12 remain future work; run one application process.
* Threat memory uses cosine similarity, which compares the *shape* of a deviation, not its size, so a mild burst can partly resemble a confirmed takeover.
* Single risk-oracle key for on-chain writes — PoC only. Pending-nonce lookup through submission is serialized within one process; multiple processes require a shared nonce coordinator. Submission is reported separately from transaction confirmation.

## Score API quick start (through stage 7)

With the server running and `POTUS_EMPLOYEE_KEY` exported in your terminal to match
an employee key configured on the server:

```bash
curl http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $POTUS_EMPLOYEE_KEY" \
  -d '{"resource_id":"research-vault","features":{"wallet_age_blocks":50000,"tx_count_10m":38,"tx_count_1h":50,"unique_contracts_24h":8,"new_contract_ratio":0.71,"transfer_value_zscore":3.9,"access_requests_10m":25,"failed_access_count":6}}'
```

For retrieved evidence, replace `features` with `wallet` containing the wallet's
full address. `/score` runs the stage 2–7 pipeline and includes the existing policy
mapping as a preview; it creates no access grant, case or registry write. Use
`/access/request` for the existing full access workflow.

The response includes `risk_score`, `decision`, component `signals` and `breakdown`,
`reason_codes`, `hard_flags`, validated `gemini_triage` (or null on fallback),
`prompt_version`, `vector_version`, `data_source`, `history_confidence`, `simulated`,
and a safe `customer_preview`. Exact schemas are available at `/docs` in development.
Raw vectors are labeled `provided`, not verified chain data. Their supplied
`pattern_similarity` is replaced by the server's reviewed threat-memory lookup.
Unknown wallet age produces low history confidence.

For reproducible offline results, configure `GEMINI_MODE=mock`. For live Gemini,
set `GEMINI_API_KEY` in the ignored `backend/.env` and `GEMINI_MODE=auto`.
The verified default is `gemini-3.5-flash-lite`, `GEMINI_THINKING_LEVEL=low`,
and `GEMINI_TIMEOUT_SECONDS=12`. The paced evaluation accepted all 25 live
responses; 19 matched the development fixture categories. Disagreements and
latency are recorded in `evaluation/live-report.json`. The API smoke test also
verified real Gemini triage, case creation, vault denial and forced-outage fallback.

The provider receives the documented JSON Schema subset. String-length limits
are checked locally along with enum, numeric, list and corroboration constraints.
Use `GEMINI_THINKING_LEVEL=default` to omit thinking controls when selecting a
model that does not support them. `/health/details` shows the effective model,
API, reasoning setting and deadline to authenticated employees.

To repeat the API smoke test from the repository root:

```bash
python backend/smoke_api.py --output backend/evaluation/live-api-smoke.json
```

It uses simulated data and a temporary database, disables registry writes, and
exits with an error if any live/API check fails. The ordinary provider evaluator
paces requests at 3.1 seconds by default; adjust `--interval` for account limits.
Both scripts require a key in the environment or ignored `backend/.env`.

Risk configuration must be readable YAML with a mapping at its root; malformed
files and invalid Gemini controls stop startup. This prevents accidental use of
unintended defaults. See the root README for test and evaluation commands.
