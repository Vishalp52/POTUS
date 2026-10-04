# POTUS backend — API, chain, features, models

This covers the first four folders of the spec's backend layout (§8):
`app/api`, `app/chain`, `app/features`, `app/models`, plus `main.py`.
The other four (`app/ai`, `app/risk`, `app/memory` + `app/db`, and
`services + tests + scripts + config`) are owned by the other backend dev and
are **used as-is, not modified**.

## Run it

```bash
pip install -r requirements.txt        # from repo root
cd backend
cp .env.example .env                   # fill in what you have
uvicorn main:app --reload --port 8000  # docs at http://localhost:8000/docs
python -m pytest tests -q              # 26 tests, fully offline
```

For a reliable recorded demo with no API keys: `GEMINI_MODE=mock`.

## Pipeline (spec §4)

```
POST /access/request
  -> app/chain/source.py      demo replay | Envio HyperSync | Monad RPC | none
  -> app/features/extractor   feature vector, deltas vs baseline, hard flags
  -> app/models               IsolationForest -> anomaly_score 0..1
  -> app/memory (teammate)    cosine similarity vs confirmed incident signatures
  -> app/risk/rules (teammate)
  -> app/ai (teammate)        Gemini triage only if anomaly >= GEMINI_TRIGGER_SCORE (timeout + fallback)
  -> app/risk/fusion+policy (teammate)  ALLOW / CHALLENGE / REVIEW / RESTRICT
  -> app/chain/registry.py    minimal on-chain record (score, expiry, decision, evidence hash)
  -> case record (employee view) + customer-safe payload
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/access/request` | Full evaluation for wallet + resource + action (spec response contract) |
| GET | `/wallet/{address}/features` | Feature vector + baseline comparisons (no side effects) |
| POST | `/score` | Detector + rules + memory + Gemini + policy, no case / no on-chain write. Accepts `wallet` or raw `features` |
| GET | `/wallet/{address}/risk` | Latest decision, expiry, score, reason codes |
| POST | `/incident/confirm` | Store a reviewed incident signature in threat memory |
| GET | `/incidents` | Incident patterns for the employee console |
| GET | `/cases` | Case list (filter `?status=OPEN`) |
| GET | `/cases/{id}` | Full employee investigation packet (§10 panels) |
| POST | `/cases/{id}/review` | Analyst disposition + note; confirmed incidents enter memory |
| GET | `/customer/status/{request_id}` | Customer-safe status + next step |
| GET | `/access/{request_id}/challenge` | Message to sign for a CHALLENGE |
| POST | `/access/{request_id}/verify` | Wallet signature (personal_sign) resolves a CHALLENGE |
| GET | `/vault/research-vault?request_id=&wallet=` | The protected resource; 403 unless authorized |
| GET | `/demo/scenarios` · POST `/demo/reset` | Deterministic scenarios A–F; reset to known state |
| GET | `/health` | Model, Gemini, data-source, registry status |

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
* `X-Actor` header (optional) is recorded in the audit trail. No auth on employee routes yet (PoC).

## Compatibility with teammate modules

`app/api/teammate.py` loads the teammate's modules without editing them and works
around three small issues (switches off automatically once they're fixed):

1. `app/risk/reasons_codes.py` is imported as `app.risk.reason_codes` → alias registered.
2. `app/risk/policy.py` uses `Optional` without importing it → loaded with `Optional` pre-seeded.
3. `GeminiTriage` spells `"NORMAL OR BENIGN"` / `"SLIGHT ANOMALY"` with spaces → we map labels to whatever the schema uses, and API responses always use the spec's underscore form.

`requirements.txt`: `websockets` pinned to 16.1.1 (google-genai requires <17) and
`google-genai` + `PyYAML` added — the Gemini client and risk.yaml loading need them.

## Limitations (say these honestly in the pitch)

* Plain Monad RPC has no address index: the RPC path scans only the last `RPC_SCAN_BLOCKS` blocks; the 24h window needs Envio HyperSync.
* Cases/access history are in memory (requests, incidents, audit events persist to SQLite via the teammate's models).
* Threat memory uses cosine similarity, which compares the *shape* of a deviation, not its size, so a mild burst can partly resemble a confirmed takeover.
* Single risk-oracle key for on-chain writes — PoC only.
