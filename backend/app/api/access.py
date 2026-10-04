"""Access-request routes, customer status, wallet challenge, and the protected Research Data Vault."""
from __future__ import annotations

import time

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import APIRouter, Header, HTTPException, Query

from app.api.engine import _iso, evaluate_access
from app.api.messages import challenge_message, customer_payload
from app.api.schemas import AccessEvaluation, AccessRequest, CustomerPayload, VerifyRequest
from app.api.state import db_audit, store

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


def _get_case(request_id: str) -> dict:
    case = store.cases.get(request_id)
    if not case:
        raise HTTPException(404, "unknown request_id")
    return case


def _effective_decision(case: dict) -> str:
    return "RESOLVED" if case.get("resolved") else case["decision"]


@router.post("/access/request", response_model=AccessEvaluation)
async def request_access(req: AccessRequest, x_actor: str = Header("frontend")):
    """Create a complete evaluation for wallet + resource + action."""
    return await evaluate_access(req.wallet, req.resource_id, req.action, req.demo_scenario, req.simulate_ai_outage, actor=x_actor)


@router.get("/customer/status/{request_id}", response_model=CustomerPayload)
def customer_status(request_id: str):
    """Customer-safe status + next step (no thresholds, labels, or incident IDs)."""
    case = _get_case(request_id)
    decision = _effective_decision(case)
    policy_customer = None if decision == "RESOLVED" else case["scored"].get("policy_customer")
    return customer_payload(request_id, decision, policy_customer)


@router.get("/access/{request_id}/challenge")
def get_challenge(request_id: str):
    case = _get_case(request_id)
    if case["decision"] != "CHALLENGE":
        raise HTTPException(409, "this request does not require a wallet challenge")
    return {"request_id": request_id, "message": challenge_message(request_id, case["wallet"])}


@router.post("/access/{request_id}/verify", response_model=CustomerPayload)
def verify_challenge(request_id: str, body: VerifyRequest):
    """Step-up verification: wallet signs the challenge message (EIP-191 personal_sign)."""
    case = _get_case(request_id)
    if case["decision"] != "CHALLENGE":
        raise HTTPException(409, "only CHALLENGE decisions can be resolved by wallet signature")
    try:
        signer = Account.recover_message(encode_defunct(text=challenge_message(request_id, case["wallet"])), signature=body.signature)
    except Exception:
        raise HTTPException(400, "invalid signature")
    if signer.lower() != case["wallet"]:
        raise HTTPException(403, "signature does not match the requesting wallet")
    case["resolved"] = True
    case["status"] = "RESOLVED"
    case["expires_at_ts"] = max(case["expires_at_ts"], time.time() + 600)
    h = db_audit(case["wallet"], "CHALLENGE_VERIFIED", request_id, {"signer": signer.lower()})
    case["audit"].append({"actor": case["wallet"], "event": "CHALLENGE_VERIFIED", "at": _iso(time.time()), "payload_hash": h})
    return customer_payload(request_id, "RESOLVED")


@router.get("/vault/{resource_id}")
def read_vault(resource_id: str, request_id: str = Query(...), wallet: str = Query(...)):
    """The protected resource. Only returns content after POTUS authorized this wallet."""
    case = _get_case(request_id)
    if case["wallet"] != wallet.lower() or case["resource_id"] != resource_id:
        raise HTTPException(403, "request does not match this wallet/resource")
    decision = _effective_decision(case)
    if decision not in ("ALLOW", "RESOLVED"):
        raise HTTPException(403, detail=customer_payload(request_id, decision, case["scored"].get("policy_customer")))
    if time.time() > case["expires_at_ts"]:
        raise HTTPException(403, detail={"request_id": request_id, "message": "Authorization expired. Please request access again."})
    content = PROTECTED_CONTENT.get(resource_id, {"title": resource_id, "records": []})
    return {"request_id": request_id, "resource_id": resource_id, "authorized_until": _iso(case["expires_at_ts"]), "data": content}
