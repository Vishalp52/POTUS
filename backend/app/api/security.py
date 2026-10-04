"""Security controls for the POTUS API.

* Employee / admin API keys (constant-time compare; reviewer identity comes from the key)
* Wallet-ownership proof: one-time, expiring sign-in nonces (EIP-191 personal_sign)
* HMAC-signed, short-lived vault access tokens (bound to request, wallet, resource)
* Sliding-window rate limiting per client IP and per wallet
* Security headers, request-size limit, generic error responses
* Gemini evidence sanitization: only allowlisted, typed fields reach the model
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Optional

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import Depends, Header, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.api.settings import settings

log = logging.getLogger("potus.security")

# Fresh random secret per process if none configured (tokens then expire on restart - fail safe)
_TOKEN_SECRET = (settings.token_secret or secrets.token_hex(32)).encode()


# ============================================================ client identity
def client_ip(request: Request) -> str:
    if settings.trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def ip_fingerprint(request: Request) -> str:
    """Hashed IP for audit logs (no raw IPs stored)."""
    return hashlib.sha256((client_ip(request) + _TOKEN_SECRET.decode()[:16]).encode()).hexdigest()[:16]


# ============================================================ API keys / roles
@dataclass(frozen=True)
class Principal:
    name: str
    role: str  # "employee" | "admin"


def _parse_keys(raw: str) -> dict[str, str]:
    out = {}
    for item in filter(None, (p.strip() for p in raw.split(","))):
        name, _, key = item.partition(":")
        if name and key:
            out[key.strip()] = name.strip()
    return out


def _match(provided: str, keys: dict[str, str]) -> Optional[str]:
    found = None
    for key, name in keys.items():  # compare against all keys: no early exit timing signal
        if hmac.compare_digest(provided.encode(), key.encode()):
            found = name
    return found


def authenticate(x_api_key: Optional[str]) -> Optional[Principal]:
    if not x_api_key:
        return None
    if settings.admin_key and hmac.compare_digest(x_api_key.encode(), settings.admin_key.encode()):
        return Principal("admin", "admin")
    name = _match(x_api_key, _parse_keys(settings.employee_keys))
    return Principal(name, "employee") if name else None


def _auth_configured() -> bool:
    return bool(settings.admin_key or settings.employee_keys)


def require_employee(request: Request, x_api_key: Optional[str] = Header(None)) -> Principal:
    p = authenticate(x_api_key)
    if p:
        return p
    if not _auth_configured() and not settings.production:
        return Principal("dev-unauthenticated", "employee")  # local dev only; logged at startup
    log.warning("employee auth failed from %s on %s", ip_fingerprint(request), request.url.path)
    raise HTTPException(401, "missing or invalid API key", headers={"WWW-Authenticate": "ApiKey"})


def require_admin(request: Request, x_api_key: Optional[str] = Header(None)) -> Principal:
    p = authenticate(x_api_key)
    if p and p.role == "admin":
        return p
    if not _auth_configured() and not settings.production:
        return Principal("dev-unauthenticated", "admin")
    log.warning("admin auth failed from %s on %s", ip_fingerprint(request), request.url.path)
    raise HTTPException(403 if p else 401, "admin API key required")


def require_demo_enabled() -> None:
    if not settings.demo_enabled:
        raise HTTPException(404, "not found")


# ============================================================ rate limiting
class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: float = 60.0) -> Optional[int]:
        """Record a hit; return seconds to wait if over the limit, else None."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return max(1, int(window - (now - q[0])) + 1)
            q.append(now)
            if len(self._hits) > 50_000:  # bound memory under key-spraying
                for k in list(self._hits)[:10_000]:
                    if not self._hits[k]:
                        del self._hits[k]
        return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()

# per-minute budgets, scaled from RATE_LIMIT_PER_MINUTE (default 30)
def _budget(kind: str) -> int:
    base = settings.rate_limit_per_minute
    return {"access": base, "score": base * 2, "verify": max(5, base // 3), "nonce": base, "read": base * 4}[kind]


def rate_limit(kind: str):
    def dep(request: Request) -> None:
        wait = limiter.hit(f"{kind}:ip:{client_ip(request)}", _budget(kind))
        if wait:
            raise HTTPException(429, "too many requests", headers={"Retry-After": str(wait)})
    return Depends(dep)


def rate_limit_wallet(kind: str, wallet: str) -> None:
    wait = limiter.hit(f"{kind}:wallet:{wallet.lower()}", _budget(kind))
    if wait:
        raise HTTPException(429, "too many requests", headers={"Retry-After": str(wait)})


# ============================================================ wallet ownership
@dataclass
class Nonce:
    wallet: str
    message: str
    expires: float


class NonceStore:
    def __init__(self):
        self._n: dict[str, Nonce] = {}
        self._lock = threading.Lock()

    def issue(self, wallet: str, purpose: str = "access") -> tuple[str, str, float]:
        nonce = secrets.token_urlsafe(16)
        now = time.time()
        exp = now + settings.nonce_ttl_seconds
        msg = (f"POTUS wants you to prove ownership of this wallet.\n"
               f"Purpose: {purpose}\nWallet: {wallet.lower()}\nNonce: {nonce}\n"
               f"Issued At: {int(now)}\nExpires At: {int(exp)}\n"
               "Signing is free and does not send a transaction.")
        with self._lock:
            self._purge(now)
            self._n[nonce] = Nonce(wallet.lower(), msg, exp)
        return nonce, msg, exp

    def consume(self, nonce: str, wallet: str) -> Optional[str]:
        """One-time use: returns the signed message if valid for this wallet, else None."""
        with self._lock:
            n = self._n.pop(nonce, None)
        if not n or n.wallet != wallet.lower() or time.time() > n.expires:
            return None
        return n.message

    def _purge(self, now: float) -> None:
        if len(self._n) > 10_000:
            for k, v in list(self._n.items()):
                if v.expires < now:
                    del self._n[k]

    def reset(self) -> None:
        with self._lock:
            self._n.clear()


nonces = NonceStore()


def recover_signer(message: str, signature: str) -> Optional[str]:
    try:
        return Account.recover_message(encode_defunct(text=message), signature=signature).lower()
    except Exception:
        return None


def verify_wallet_ownership(wallet: str, nonce: Optional[str], signature: Optional[str]) -> bool:
    if not nonce or not signature:
        return False
    msg = nonces.consume(nonce, wallet)
    return bool(msg) and recover_signer(msg, signature) == wallet.lower()


# ============================================================ vault access tokens
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_access_token(request_id: str, wallet: str, resource_id: str, expires: float) -> str:
    payload = json.dumps({"rid": request_id, "w": wallet.lower(), "res": resource_id, "exp": int(expires)},
                         separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(_TOKEN_SECRET, payload, hashlib.sha256).digest()
    return f"{_b64(payload)}.{_b64(sig)}"


def verify_access_token(token: str) -> Optional[dict[str, Any]]:
    try:
        p64, s64 = token.split(".", 1)
        payload = _unb64(p64)
        if not hmac.compare_digest(_unb64(s64), hmac.new(_TOKEN_SECRET, payload, hashlib.sha256).digest()):
            return None
        claims = json.loads(payload)
        if time.time() > claims["exp"]:
            return None
        return claims
    except Exception:
        return None


def bearer_token(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


# ============================================================ Gemini evidence sanitization
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
ALLOWED_FLAGS = {"ACCESS_BURST", "VALUE_OUTLIER", "NEW_CONTRACT_SPIKE", "REPEATED_DENIALS",
                 "FLAGGED_COUNTERPARTY", "COLD_START_WALLET"}
NUMERIC_DELTAS = ("tx_count_10m", "tx_count_1h", "unique_contracts_24h", "new_contract_ratio", "access_requests_10m")


def _num(v: Any, lo: float = -1e6, hi: float = 1e6) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    if f != f:  # NaN
        return 0.0
    return round(max(lo, min(hi, f)), 4)


def sanitize_for_gemini(evidence: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the evidence packet from an allowlist of typed fields.

    Nothing free-text from a user (session metadata, action strings, headers) can reach
    the model, so there is nothing for a prompt injection to ride in on. Identity
    (wallet address) is also withheld - the model classifies behavior, not people.
    """
    deltas_in = evidence.get("feature_deltas", {}) or {}
    deltas: dict[str, Any] = {}
    for k in NUMERIC_DELTAS:
        d = deltas_in.get(k)
        if isinstance(d, dict):
            deltas[k] = {"value": _num(d.get("value")), "baseline": _num(d.get("baseline")), "ratio": _num(d.get("ratio"))}
    for k in ("transfer_value_zscore", "failed_access_count", "flagged_counterparty_count"):
        if k in deltas_in:
            deltas[k] = _num(deltas_in[k])
    rid = str(evidence.get("resource_id", ""))
    return {
        "resource_id": rid if SAFE_ID.match(rid) else "redacted",
        "anomaly_score": _num(evidence.get("anomaly_score"), 0, 1),
        "pattern_similarity": _num(evidence.get("pattern_similarity"), 0, 1),
        "feature_deltas": deltas,
        "hard_flags": sorted(f for f in evidence.get("hard_flags", []) if f in ALLOWED_FLAGS),
        "transfer_value_zscore": _num(evidence.get("transfer_value_zscore"), -10, 10),
        "failed_access_count": int(_num(evidence.get("failed_access_count"), 0, 10_000)),
        "wallet_age_blocks": int(_num(evidence.get("wallet_age_blocks"), 0, 1e12)),
        "flagged_counterparty_count": int(_num(evidence.get("flagged_counterparty_count"), 0, 10_000)),
        "resource_sensitivity": _num(evidence.get("resource_sensitivity"), 0, 1),
        "history_confidence": "low" if evidence.get("history_confidence") == "low" else "normal",
    }


# ============================================================ middleware
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
            response.headers.setdefault("Content-Security-Policy", API_CSP)
            response.headers.setdefault("Cache-Control", "no-store")
        if settings.production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > settings.max_body_bytes:
                    return JSONResponse({"detail": "request body too large"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "invalid content-length"}, status_code=400)
        elif request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()  # chunked: enforce on actual size
            if len(body) > settings.max_body_bytes:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)


def reset_security_state() -> None:
    limiter.reset()
    nonces.reset()
