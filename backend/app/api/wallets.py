"""Wallet feature / risk routes and the side-effect-free POST /score."""
from __future__ import annotations

import asyncio
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from app.api.engine import (
    _iso, bundle_from_features, build_bundle, components, public_signals, score_bundle,
)
from app.api.messages import customer_payload
from app.api.schemas import ADDRESS_PATTERN, ScoreEvaluation, ScoreRequest
from app.features.schemas import VECTOR_VERSION
from app.api.security import rate_limit, require_employee
from app.api.settings import settings
from app.api.state import store
from app.chain.demo_replay import WALLET_TO_SCENARIO, scenario_for
from app.chain.source import get_wallet_activity

# Employee-only: exposing features/scores publicly would let an attacker probe the
# detector and tune behavior to stay under thresholds (model-evasion / oracle attack).
router = APIRouter(tags=["wallets"], dependencies=[Depends(require_employee), rate_limit("score")])

ZERO = "0x0000000000000000000000000000000000000000"


def _check_demo_access(wallet: str, demo_scenario: Optional[str], simulate_ai_outage: bool = False) -> None:
    if not settings.demo_enabled and (
        demo_scenario or simulate_ai_outage or wallet.lower() in WALLET_TO_SCENARIO or settings.data_source == "demo"
    ):
        raise HTTPException(403, "demo features are disabled")


@router.get("/wallet/{address}/features")
async def wallet_features(
    address: str = Path(..., pattern=ADDRESS_PATTERN),
    resource_id: str = Query("research-vault", pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$"),
    demo_scenario: Optional[str] = Query(None, pattern="^[A-F]$"),
):
    """Normalized feature vector + baseline comparisons (does not log an access attempt)."""
    _check_demo_access(address, demo_scenario)
    now = time.time()
    activity = await asyncio.to_thread(get_wallet_activity, address, demo_scenario, now)
    b = build_bundle(address, resource_id, demo_scenario, now, activity)
    det = components().detector
    return {
        "wallet": b.wallet, "resource_id": b.resource_id, "data_source": b.data_source, "simulated": b.simulated,
        "history_confidence": b.history_confidence, "features": b.features.model_dump(),
        "feature_deltas": b.feature_deltas, "baselines": b.baselines, "hard_flags": b.hard_flags,
        "anomaly_score": det.score(b.vector), "vector": b.vector, "notes": b.notes,
    }


@router.get("/wallet/{address}/risk")
def wallet_risk(address: str = Path(..., pattern=ADDRESS_PATTERN)):
    """Current policy state, expiry, score, reason codes (latest evaluation)."""
    case = store.latest_case_for(address)
    if not case:
        return {"wallet": address.lower(), "state": "NO_EVALUATION", "active": False}
    decision = "RESOLVED" if case.get("resolved") else case["decision"]
    return {
        "wallet": case["wallet"], "request_id": case["request_id"], "resource_id": case["resource_id"],
        "decision": decision, "risk_score": case["response"]["risk_score"],
        "reason_codes": case["response"]["reason_codes"], "evaluated_at": case["created_at"],
        "expires_at": _iso(case["expires_at_ts"]), "active": time.time() < case["expires_at_ts"] and not case.get("revoked", False),
        "evidence_hash": case["response"]["evidence_hash"], "onchain": case["response"]["onchain"],
    }


@router.post("/score", response_model=ScoreEvaluation)
async def score(req: ScoreRequest):
    """Run detector, rules, threat memory, Gemini triage, and policy - without creating a case,
    logging an access attempt, or writing on-chain. Useful for the Gemini evaluation set."""
    if req.features is None and req.wallet is None:
        raise HTTPException(422, "provide either `wallet` or `features`")
    wallet = (req.wallet or ZERO).lower()
    _check_demo_access(wallet, req.demo_scenario, req.simulate_ai_outage)
    if req.features is not None:
        bundle = bundle_from_features(req.features.model_copy(), wallet, req.resource_id)
    else:
        now = time.time()
        activity = await asyncio.to_thread(get_wallet_activity, wallet, req.demo_scenario, now)
        bundle = build_bundle(wallet, req.resource_id, req.demo_scenario, now, activity)
    scen = scenario_for(wallet, req.demo_scenario)
    scored = await score_bundle(bundle, req.simulate_ai_outage or bool(scen and scen.ai_outage))
    t = scored["triage"]
    return {
        "wallet": wallet, "resource_id": req.resource_id, "risk_score": scored["risk_score"],
        "decision": scored["decision"], "signals": public_signals(scored), "reason_codes": scored["reason_codes"],
        "breakdown": scored["breakdown"], "guardrails": scored["guardrails"], "hard_flags": bundle.hard_flags,
        "gemini_triage": None if t is None else t.model_dump(),
        "prompt_version": scored["prompt_version"], "vector_version": VECTOR_VERSION,
        "data_source": bundle.data_source, "history_confidence": bundle.history_confidence,
        "simulated": bundle.simulated,
        "customer_preview": customer_payload("preview", scored["decision"], scored["policy_customer"]),
    }
