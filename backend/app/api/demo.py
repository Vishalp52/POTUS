"""Demo helpers: list scenarios and reset to a known state (spec §13/§18)."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.state import db_audit, db_clear_incidents, store
from app.chain.demo_replay import SCENARIOS

router = APIRouter(prefix="/demo", tags=["demo"])


@router.get("/scenarios")
def scenarios():
    return {"scenarios": [
        {"key": s.key, "name": s.name, "wallet": s.wallet, "description": s.description,
         "expected": s.expected, "ai_outage": s.ai_outage, "simulated": True}
        for s in SCENARIOS.values()
    ]}


@router.post("/reset")
def reset():
    """Clear cases, access history, flagged wallets, and threat memory."""
    store.reset()
    db_clear_incidents()
    db_audit("demo", "DEMO_RESET", "all", {})
    return {"status": "reset", "cases": 0, "incidents": 0}
