# Validation — October 7, 2026

## Implemented resolution

- Default model pinned to `gemini-3.5-flash-lite`, verified with the supplied key.
- Low thinking effort, a bounded 12-second deadline, and provider-compatible
  JSON Schema. Strict local validation and deterministic fallback remain intact.
- Versioned prompt clarifies precedence among server-configured typologies.
- Evaluation pacing avoids the burst quota observed in the initial run. Any
  unavailable response makes the live evaluation command exit nonzero.
- Health details expose effective model settings only to authenticated employees.

## Verification

- **223 offline tests passed**, with 3 dependency deprecation warnings.
- **25/25 live structured triages accepted** using the final model, prompt v4,
  schema, and deadline. Median latency 1.263s; p95 1.913s; maximum 6.575s.
- **19/25 fixture categories matched**. One slight-anomaly packet was interpreted
  as benign; five specific typology packets were interpreted as generic fraud-like
  behavior. Those five still received high risk scores. The exact results remain
  in `backend/evaluation/live-report.json`; this is not production accuracy.
- Real FastAPI smoke test passed all ten checks: live triage accepted, simulated
  attack held, no access token, protected vault denied, employee case available,
  outage fallback, and no registry writes. See `backend/evaluation/live-api-smoke.json`.
- Detector retrained and exported on the supplied **1,000 synthetic normal rows**.
  The calibration probe used 800 training rows and 200 held-out rows; 1.5% of
  held-out normal examples crossed the 0.35 Gemini trigger. Final artifact and
  `backend/evaluation/model-report.json` include provenance and training fingerprint.
- Provider transport regressions cover both API modes, reasoning controls,
  schema compatibility, local text bounds, 401/429/503 fallback, no retries,
  cancellation, privacy filtering and typology corroboration.

## Scope and evidence limits

The earlier alias probes had intermittent 503/504 responses and a successful
response beyond the old six-second deadline. The initial unpaced Flash-Lite run
accepted 21/25 responses and hit four 429 quota errors. These results are retained
in the diagnostic reports; no guaranteed provider availability is implied.
A more explicit experimental prompt did not improve the two checked category
boundaries, so the fully evaluated v4 prompt remains active.

No Gemini weights were trained. The supplied data are sufficient to rebuild the
PoC anomaly detector, but contain no validated attack labels for a production
threat classifier. The 25 development fixtures informed prompt work and are not
an independent accuracy benchmark.

The supplied API key was used transiently during validation. At the user’s request,
it is now stored in the ignored local `backend/.env` with owner-only permissions.
Generated local admin/employee keys and a token-signing secret are configured there
as well. Credentials are excluded from the downloadable ZIP.
No chain transactions were submitted. Live RPC/Envio, deployment, frontend and
on-chain proof remain outside this verification. Cases remain in memory; reviewed
incident signatures persist. The existing stage-8 policy file and thresholds
were preserved.
