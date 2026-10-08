# POTUS backend through stage 7

Implemented against the **POTUS / Monad Metropolis 2026 Build Specification v2.0,
updated October 2, 2026**, using the architecture-stage numbering on page 4.
This is a full copy of the supplied repository with the completed backend changes.

| Stage | Included implementation | Validation |
|---|---|---|
| 1: Wallet / protected app | Existing backend request boundary retained; frontend excluded | Existing API/security tests |
| 2: Chain / event data | Existing Monad RPC and Envio adapters, bounded scans, fallback and simulated replay | Offline RPC, pagination, timestamp, incomplete-data and failure tests |
| 3: Feature service | Eight-feature contract, baseline deltas, real/derived features, partial-history labeling | Feature, range and data regression tests |
| 4: Statistical detector | Seeded IsolationForest; exported trained artifact; atomic saving; training/runtime compatibility checks; training CLI and calibration report | Repeatability, anomaly separation, reload and input-validation tests |
| 5: Threat memory | Reviewed incident persistence/reload; provenance; stable finite cosine matching; duplicate rejection; defensive vector copies | Persistence, poisoning, recurrence and vector validation tests |
| 6: Gemini interpreter | Real asynchronous GenerateContent SDK integration (optional Interactions); strict schema; versioned prompt; privacy filtering; configured typology corroboration; deadline, cancellation and fallback; bounded output | Actual SDK over offline HTTP transport, success/401/429/503, malformed responses and timeout tests |
| 7: Risk fusion | Deterministic weighted risk; validated configuration; AI capped at 20 points; fallback renormalization; review guardrails | Boundaries, invalid weights/scores, AI authority and integration tests |
| 8: Policy engine | Existing code retained unchanged; not newly implemented | Existing compatibility tests retained |

The existing stage-9 registry adapter and API support for employee/customer views
are retained. This delivery does not add a frontend, Solidity contract, deployment,
or stage-8 policy work.

## Run locally

Python 3.14 was used for verification. From this folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp backend/.env.example backend/.env
cd backend
uvicorn main:app --reload --port 8000
```

Configure `POTUS_ADMIN_KEY`, `POTUS_EMPLOYEE_KEYS` and `TOKEN_SECRET` as explained
in `backend/.env.example` and `backend/SECURITY.md`. Public access requests and
employee scoring routes have different authentication requirements. Open
`http://localhost:8000/docs` for development API documentation.

For an offline demo, set `GEMINI_MODE=mock`, `DATA_SOURCE=none`, and `ENABLE_DEMO=true`.
Use `/demo/scenarios` to obtain scenario wallets. To call real Gemini, set:

```dotenv
GEMINI_MODE=auto
GEMINI_API_KEY=your-key-here
GEMINI_MODEL=gemini-3.5-flash-lite
GEMINI_API=generate_content
GEMINI_TIMEOUT_SECONDS=12
GEMINI_THINKING_LEVEL=low
GEMINI_TRIGGER_SCORE=0.35
GEMINI_MAX_OUTPUT_TOKENS=2048
```

Keep the key in `.env`; do not put it in source control or a frontend.
`GOOGLE_API_KEY` is accepted when `GEMINI_API_KEY` is unset. Model availability
and quotas depend on the account. Live structured generation now works with
`gemini-3.5-flash-lite`: the paced 25-packet evaluation accepted all 25 responses
and the real FastAPI access smoke test passed. Median generation latency was
1.26 seconds (95th percentile 1.91 seconds). Fixture category agreement was
19/25; see the explicit mismatches in `backend/evaluation/live-report.json`.
These are synthetic development fixtures, not a production accuracy benchmark.

The older `gemini-flash-latest` setting remains available as an override. In our
checks it had intermittent 503s and a valid response took 6.85 seconds, exceeding
the old six-second deadline. The default now uses a verified explicit model,
low thinking effort, a twelve-second deadline, and a provider-compatible schema.
Strict local validation still enforces all text, array, enum and numeric bounds.
The supplied key was used transiently during validation. At the user’s request,
credentials are now configured in the ignored local `backend/.env`, which is excluded
from the downloadable ZIP.



## Test, train and evaluate

```bash
# Repository root
python -m pytest -q
python backend/model.py --report backend/evaluation/model-report.json
cd backend
python evaluate.py --output evaluation/offline-report.json
# Optional: one billable provider request to smoke-test your configured key/model
python evaluate.py --live --limit 1 --output evaluation/live-smoke.json
# Optional: all 25 synthetic labeled review packets
python evaluate.py --live --limit 25 --interval 3.1 --output evaluation/live-report.json
# Real API -> Gemini -> case -> protected-vault/outage checks (temporary DB)
cd ..
python backend/smoke_api.py --output backend/evaluation/live-api-smoke.json
```

The evaluation runner stops at stage 7 and performs no registry writes or access
changes. Live evaluation intentionally includes below-trigger packets to evaluate
all label classes. Ordinary API traffic calls Gemini only above the trigger.
The included offline report validates detector/rules/fusion on all 25 packets; it
does **not** claim Gemini classification accuracy. Synthetic fixture labels are
review expectations, not verified real-world incidents. The training report is
normal-only calibration, not attack precision or recall.

## Gemini boundary

- Defaults to `client.aio.models.generate_content` with separate system instruction,
  JSON evidence, JSON schema, disabled function calling and strict local validation.
  `GEMINI_API=interactions` retains the alternate SDK path with `store=False`.
- Rejects invalid confidence/risk, unexpected fields, oversized text, unfinished
  results, and unsupported illicit labels. Logs error types without provider bodies.
- Server-owned typologies require multiple deterministic indicators. The included
  `FLAGGED_VALUE_MOVEMENT` typology requires both flagged counterparties and an
  unusual transfer value; it is a PoC indicator, not a legal conclusion.
- Real calls have no automatic retries. The pinned SDK's generated-resource retry
  configuration is explicitly disabled because version 2.28.0 interprets the common
  retry option differently across API families. Actual HTTP-transport tests protect
  this behavior; run them before upgrading the SDK.
- High-severity low-confidence results request review. Explicit review requests on
  ambiguous/non-severe classifications are preserved. Strong corroborated high-risk
  signals can continue through the existing policy mapping.
- Prompt version is retained with the in-memory score record and employee API output.

Integration references: [Google Interactions API](https://ai.google.dev/gemini-api/docs/interactions-overview),
[structured output](https://ai.google.dev/gemini-api/docs/structured-output),
and [Google Python SDK](https://github.com/googleapis/python-genai).

## Remaining operational limitations

- Live Gemini and the simulated access/API flow are verified. Real RPC/Envio
  connectivity and on-chain submission remain unverified.
- Gemini labels agreed with 19 of 25 synthetic fixture expectations; the remaining
  disagreements are preserved in the report. Model variability and rate limits
  remain possible, so deterministic fallback and human review are retained.
- The supplied normal dataset is not evidence of production detector accuracy.
- Cases, full feature/triage snapshots and app attempt history remain in memory;
  confirmed incidents and audit/request records persist. Restarting loses active
  cases. Run one application process for this PoC. Full case persistence is future work.
- Plain RPC is a bounded scan, not a complete wallet index. Missing history remains
  labeled low confidence. See `backend/README_API.md` for retrieval limits.
- Cosine memory compares deviation direction, not attack magnitude. Only reviewed
  or explicitly simulated signatures should enter it.
- The stage-8 policy file and its threshold configuration were preserved byte-for-byte.

## Final API completion pass

The API has been checked against architecture stages 1–7 on page 4 of the supplied
specification. Stage 1 here covers the backend wallet/request boundary; a wallet
frontend is not included. Stages 2–7 cover retrieval, features, detector, reviewed
threat memory, Gemini interpretation, and deterministic risk fusion.

- Raw `/score` vectors now preserve known hard flags, use the same fractional
  baseline floors as extracted features, and label unknown/young wallet history
  as low confidence. Missing hourly contract counts are not fabricated.
- Application access floods contribute to deterministic rules, even without a
  simultaneous chain transaction burst; combined bursts are counted once.
- `/score` has a validated OpenAPI response, including prompt/vector versions,
  evidence source, simulation marker and history confidence.
- Invalid risk files, Gemini modes, deadlines and trigger controls fail startup
  instead of silently changing scoring behavior.
- Evaluation uses the configured runtime weights. Reports identify model, API,
  deadline, timestamp and per-packet latency. A live run with any unavailable triage
  writes its report and exits with status 1, so fallback cannot look like a passing
  provider smoke test.

See [backend/README_API.md](backend/README_API.md) for a ready-to-use scoring request.

The evaluation runner spaces live requests at least 3.1 seconds apart by default;
use `--interval` for your account quota and `--fixture-id` to select individual
fixtures. Pacing affects the development evaluator, not API response deadlines.
The initial unpaced run is retained as `backend/evaluation/live-initial-report.json`
and shows four rate-limit failures, rather than concealing them.

Provider references: [Google structured-output schema support](https://ai.google.dev/gemini-api/docs/structured-output)
and [thinking controls](https://ai.google.dev/gemini-api/docs/thinking).
