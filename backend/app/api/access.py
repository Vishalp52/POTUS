"""Access-request routes, wallet-ownership proof, customer status, challenge
step-up, and the protected Research Data Vault."""
from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request

from app.api.engine import _iso, evaluate_access
from app.api.messages import customer_payload
from app.api.schemas import (
    ADDRESS_PATTERN, AccessEvaluation, AccessRequest, CustomerPayload, VerifyRequest, VerifyResponse,
)
from app.api.security import (
    bearer_token, ip_fingerprint, issue_access_token, nonces, rate_limit, rate_limit_wallet,
    recover_signer, verify_access_token, verify_wallet_ownership,
)
from app.api.settings import settings
from app.api.state import AccessAttempt, db_audit, store
from app.chain.demo_replay import WALLET_TO_SCENARIO

router = APIRouter(tags=["access"])

PROTECTED_CONTENT = {
    "research-vault": {
        "title": "Research Data Vault",
        "records": [
            {"id": "RV-001", "dataset": "Monad validator latency study (private draft)", "rows": 18234},
            {"id": "RV-002", "dataset": "Agent-wallet behavior labels v3", "rows": 4120},
            {"id": "RV-003", "dataset": "Unreleased model eval set", "rows": 960},
        ],
    },
}
GENERIC_404 = "not found"


def _get_case(request_id: str) -> dict:
    case = store.cases.get(request_id)
    if not case:
        raise HTTPException(404, GENERIC_404)
    return case


def _effective_decision(case: dict) -> str:
    return "RESOLVED" if case.get("resolved") else case["decision"]


def _auth_failed(request: Request, wallet: str, resource_id: str, reason: str) -> HTTPException:
    """Bad signatures are security signals: audit them and count them as failed access."""
    store.record_attempt(AccessAttempt("auth_failed", wallet, resource_id, time.time(), "AUTH_FAILED"))
    db_audit(ip_fingerprint(request), "WALLET_AUTH_FAILED", wallet, {"reason": reason, "resource": resource_id})
    return HTTPException(401, "wallet ownership could not be verified")


# ------------------------------------------------------------------ wallet ownership
@router.get("/auth/nonce", dependencies=[rate_limit("nonce")])
def get_nonce(wallet: str = Query(..., pattern=ADDRESS_PATTERN)):
    """One-time, expiring message for the wallet to sign (EIP-191 personal_sign)."""
    nonce, message, exp = nonces.issue(wallet, "access")
    return {"wallet": wallet.lower(), "nonce": nonce, "message": message, "expires_at": _iso(exp)}


# ------------------------------------------------------------------ evaluation
@router.post("/access/request", response_model=AccessEvaluation, dependencies=[rate_limit("access")])
async def request_access(req: AccessRequest, request: Request):
    """Create a complete evaluation for wallet + resource + action."""
    rate_limit_wallet("access", req.wallet)

    is_demo_wallet = req.wallet in WALLET_TO_SCENARIO
    if (req.demo_scenario or req.simulate_ai_outage or is_demo_wallet or settings.data_source == "demo") and not settings.demo_enabled:
        raise HTTPException(403, "demo features are disabled")

    verified = False
    if req.nonce or req.signature:
        verified = verify_wallet_ownership(req.wallet, req.nonce, req.signature)
        if not verified:
            raise _auth_failed(request, req.wallet, req.resource_id, "bad nonce/signature")
    # Fixed demo wallets have no private keys; they are exempt only while demo mode is on.
    ownership_required = settings.require_wallet_signature and not is_demo_wallet
    if ownership_required and not verified:
        raise HTTPException(401, "wallet signature required: GET /auth/nonce, sign the message, resend with nonce + signature")

    return await evaluate_access(req.wallet, req.resource_id, req.action, req.demo_scenario, req.simulate_ai_outage,
                                 actor=ip_fingerprint(request), wallet_verified=verified,
                                 ownership_required=settings.require_wallet_signature)


@router.get("/customer/status/{request_id}", response_model=CustomerPayload, dependencies=[rate_limit("read")])
def customer_status(request_id: str):
    """Customer-safe status + next step (no thresholds, labels, or incident IDs)."""
    case = _get_case(request_id)
    decision = _effective_decision(case)
    policy_customer = None if decision == "RESOLVED" else case["scored"].get("policy_customer")
    return customer_payload(request_id, decision, policy_customer)


# ------------------------------------------------------------------ step-up challenge
@router.get("/access/{request_id}/challenge", dependencies=[rate_limit("nonce")])
def get_challenge(request_id: str):
    case = _get_case(request_id)
    if case["decision"] != "CHALLENGE" or case.get("resolved"):
        raise HTTPException(409, "this request does not require a wallet challenge")
    nonce, message, exp = nonces.issue(case["wallet"], f"step-up verification for {request_id}")
    return {"request_id": request_id, "nonce": nonce, "message": message, "expires_at": _iso(exp)}


@router.post("/access/{request_id}/verify", response_model=VerifyResponse, dependencies=[rate_limit("verify")])
def verify_challenge(request_id: str, body: VerifyRequest, request: Request):
    """Step-up verification: the wallet signs a one-time, expiring challenge."""
    case = _get_case(request_id)
    if case["decision"] != "CHALLENGE" or case.get("resolved"):
        raise HTTPException(409, "only open CHALLENGE decisions can be resolved by wallet signature")
    rate_limit_wallet("verify", case["wallet"])
    msg = nonces.consume(body.nonce, case["wallet"], f"step-up verification for {request_id}")
    if not msg:
        raise _auth_failed(request, case["wallet"], case["resource_id"], "invalid/expired/reused challenge")
    if recover_signer(msg, body.signature) != case["wallet"]:
        raise _auth_failed(request, case["wallet"], case["resource_id"], "signer mismatch")
    now = time.time()
    case.update(resolved=True, status="RESOLVED", wallet_verified=True, expires_at_ts=max(case["expires_at_ts"], now + 600))
    h = db_audit(case["wallet"], "CHALLENGE_VERIFIED", request_id, {"at": int(now)})
    case["audit"].append({"actor": case["wallet"], "event": "CHALLENGE_VERIFIED", "at": _iso(now), "payload_hash": h})
    token = issue_access_token(request_id, case["wallet"], case["resource_id"], case["expires_at_ts"])
    return {**customer_payload(request_id, "RESOLVED"), "access_token": token}


# ------------------------------------------------------------------ protected resource
@router.get("/vault/{resource_id}", dependencies=[rate_limit("read")])
def read_vault(resource_id: str, authorization: Optional[str] = Header(None)):
    """The protected resource. Requires a short-lived signed access token (Authorization: Bearer ...)."""
    claims = verify_access_token(bearer_token(authorization) or "")
    if not claims or claims["res"] != resource_id:
        raise HTTPException(401, "valid access token required", headers={"WWW-Authenticate": "Bearer"})
    case = store.cases.get(claims["rid"])
    # Defense in depth: re-check live case state (a later RESTRICT / review revokes access)
    if not case or case["wallet"] != claims["w"] or _effective_decision(case) not in ("ALLOW", "RESOLVED") \
            or time.time() > case["expires_at_ts"] or case.get("revoked"):
        raise HTTPException(403, "access is no longer authorized")
    content = PROTECTED_CONTENT.get(resource_id, {"title": resource_id, "records": []})
    return {"request_id": claims["rid"], "resource_id": resource_id, "authorized_until": _iso(case["expires_at_ts"]), "data": content}
