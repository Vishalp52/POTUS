# POTUS backend: security model

POTUS is a security product, so the API protecting the vault has to hold up to
the same attacks it detects. This file lists the threats we considered, the
control for each, and the test that proves it (`backend/tests/test_security.py`).

## Threats and controls

| Threat | Control | Test |
|---|---|---|
| Someone requests access *as* another wallet and takes its ALLOW | Wallet-ownership proof: one-time, wallet-bound, 5-min nonce signed with `personal_sign` (`GET /auth/nonce`). Required in production (`REQUIRE_WALLET_SIGNATURE`). Vault tokens are only issued to proven wallets. | `test_signature_required_mode`, `test_nonce_replay_cross_wallet_and_forged_signature`, `test_no_vault_token_without_proof_when_required` |
| Signature / nonce replay | Nonces are single-use, expire, and are bound to one wallet and one purpose | same + `test_expired_nonce_rejected`, challenge replay in `test_challenge_signature_flow` |
| Failed impersonation attempts go unnoticed | Every bad signature is audited (hashed IP) and counted as a failed access, so it raises that wallet's risk score | `test_nonce_replay_cross_wallet_and_forged_signature` |
| Guessing a request ID to read the vault | Vault needs an HMAC-SHA256-signed bearer token bound to request + wallet + resource + expiry; request IDs carry 96 random bits | `test_token_forgery_and_tampering`, `test_request_ids_unguessable` |
| Token stays valid after the wallet turns hostile | Vault re-checks live case state on every read; a later REVIEW/RESTRICT or a confirmed incident revokes earlier grants | `test_escalation_revokes_earlier_grant` |
| Token leakage from logs / employee views | Tokens are never stored in case records or the DB | `test_token_forgery_and_tampering` |
| Unauthorized access to the employee console | API keys (`X-API-Key`), constant-time comparison, `employee` / `admin` roles | `test_employee_routes_reject_anonymous`, `test_wrong_key_rejected_and_employee_cannot_reset` |
| Reviewer impersonation in the audit trail | Reviewer identity comes from the API key; a `reviewer` field in the body is rejected | `test_reviewer_identity_comes_from_key` |
| **Model-evasion / oracle attack**: attacker probes `/score` or `/wallet/*/features` to learn thresholds and stay under them | Those routes and `/wallet/*/risk` are employee-only and rate-limited; customers only see `/customer/status` | `test_employee_routes_reject_anonymous` |
| Leaking detection logic to customers | Customer payload is a fixed allowlist with no scores, labels, thresholds, or incident IDs | `test_customer_payload_has_no_leakage` |
| Request flooding / brute force | Sliding-window rate limits per IP and per wallet, `429` + `Retry-After` | `test_rate_limit_returns_429` |
| Oversized / malformed / unexpected input | Strict schemas (unknown fields rejected), allowlist patterns for IDs, bounded session metadata, 32 KB body limit | `test_malformed_input_rejected`, `test_body_size_limit` |
| Reflected input / info leaks in errors | Validation errors return field names only; 500s return a generic message (no stack traces) | `test_malformed_input_rejected` |
| Browser-side attacks on API responses | `nosniff`, `X-Frame-Options: DENY`, strict CSP, `no-store`, HSTS in production; CORS restricted to configured origins, no credentials | `test_security_headers` |
| Demo shortcuts left open in production | `/demo/*`, fixed demo wallets, and `demo_scenario` are disabled when `APP_ENV=production` (unless `ENABLE_DEMO=true`); reset needs the admin key | `test_demo_disabled` |
| Misconfigured production deploy | Startup refuses to run in production without API keys or `TOKEN_SECRET`, with `*` CORS, or with API keys shorter than 24 characters; `/docs` is turned off | `test_production_fails_closed` |

## Prompt injection and AI safety (Gemini)

Layered so that a fully compromised model still can't grant access:

1. **Nothing user-written reaches the model.** `sanitize_for_gemini` rebuilds the evidence packet from an allowlist of typed numeric fields and a fixed flag vocabulary. Session metadata, action strings, headers, and the wallet address are never sent. → `test_injection_never_reaches_gemini`, `test_sanitizer_drops_unknown_and_coerces`
2. **Strict input patterns.** `resource_id` / `action` must match `^[a-z0-9][a-z0-9_-]{0,63}$`, so injection text is rejected at the edge. → `test_malformed_input_rejected`
3. **Schema-validated output.** Anything that doesn't parse into `GeminiTriage` is discarded and the deterministic fallback decides. → `test_ai_failure_or_garbage_falls_back`
4. **Bounded authority.** Gemini contributes a capped weighted term (15%). A "benign" verdict can't override strong rules and anomaly signals, and a "severe" verdict alone can't hard-restrict. → `test_compromised_ai_cannot_whitelist_an_attack`, `test_ai_alone_cannot_hard_restrict`
5. **Timeouts + fail-soft.** Outages and timeouts drop the AI term and renormalize; the security loop keeps working.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | `development` | `production` turns on fail-closed defaults |
| `POTUS_ADMIN_KEY` | – | ≥ 24 chars; admin role (demo reset) |
| `POTUS_EMPLOYEE_KEYS` | – | `alice:key1,bob:key2` |
| `TOKEN_SECRET` | random per process | HMAC key for vault tokens |
| `REQUIRE_WALLET_SIGNATURE` | `true` in production | Wallet ownership proof on `/access/request` |
| `ENABLE_DEMO` | `true` in dev, `false` in production | |
| `RATE_LIMIT_PER_MINUTE` | `30` | Base budget; score/read routes get multiples |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated; no `*` in production |
| `TRUST_PROXY_HEADERS` | `false` | Only `true` behind a proxy that sets `X-Forwarded-For` |
| `ALLOWED_HOSTS` | – | Host-header allowlist in production |
| `MAX_BODY_BYTES` | `32768` | |

Generate secrets with: `python -c "import secrets; print(secrets.token_urlsafe(32))"`

## Known limits (PoC)

* Rate limits, nonces, and cases are in-process memory: run a single instance, or move them to Redis for multiple instances.
* API keys are static shared secrets. Production would use SSO/OIDC for analysts and rotate keys.
* A single risk-oracle key signs on-chain writes. Production needs an HSM/KMS or multi-signer attestation.
* Development mode with no keys configured leaves employee routes open (logged as a warning at startup).
