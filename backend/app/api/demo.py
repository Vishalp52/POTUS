"""Demo helpers: list scenarios and reset to a known state (spec §13/§18)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.security import Principal, require_admin, require_demo_enabled, reset_security_state
from app.api.state import db_audit, db_clear_incidents, store
from app.chain.demo_replay import SCENARIOS

# Disabled entirely in production unless ENABLE_DEMO=true; reset needs the admin key.
router = APIRouter(prefix="/demo", tags=["demo"], dependencies=[Depends(require_demo_enabled)])


@router.get("/scenarios")
def scenarios():
    return {"scenarios": [
        {"key": s.key, "name": s.name, "wallet": s.wallet, "description": s.description,
         "expected": s.expected, "ai_outage": s.ai_outage, "simulated": True}
        for s in SCENARIOS.values()
    ]}


@router.post("/reset")
def reset(who: Principal = Depends(require_admin)):
    """Clear cases, access history, flagged wallets, threat memory, nonces, rate limits."""
    store.reset()
    reset_security_state()
    db_clear_incidents()
    db_audit(who.name, "DEMO_RESET", "all", {})
    return {"status": "reset", "cases": 0, "incidents": 0}
