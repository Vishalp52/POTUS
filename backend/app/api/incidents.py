"""Threat-memory routes. Only reviewed incidents or labeled simulations are stored
(no auto-training on flagged events -> no memory poisoning)."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from app.api import teammate as tm
from app.api.engine import _iso
from app.api.schemas import IncidentConfirmRequest
from app.api.security import Principal, require_employee
from app.api.state import db_audit, db_save_incident, store

router = APIRouter(tags=["incidents"], dependencies=[Depends(require_employee)])

STORABLE = {"CONFIRMED_INCIDENT", "SIMULATED_ATTACK"}


def remember_incident(case: dict, disposition: str, reviewer: str) -> dict:
    """Spec §12 safe memory update."""
    if disposition not in STORABLE:
        raise HTTPException(409, f"disposition {disposition} cannot enter threat memory")
    signature = case["bundle"]["signature"]
    if not any(signature):
        raise HTTPException(409, "case has no abnormal deviation signature to remember")
    incident_id = f"inc_{len(store.incident_meta) + 1:03d}"
    triage = case["scored"]["triage"]
    category = tm.normalize_category(triage.category) if triage is not None else "UNCLASSIFIED"
    evidence_hash = case["response"]["evidence_hash"]

    store.threat_store.insert_incident(incident_id=incident_id, vector=signature, category=category,
                                       disposition=disposition, evidence_hash=evidence_hash)
    meta = {
        "incident_id": incident_id, "source_case": case["case_id"], "wallet": case["wallet"],
        "confirmed_by": reviewer, "confirmed_at": datetime.now(timezone.utc).isoformat(),
        "simulated": bool(case["activity"].get("simulated")),
    }
    store.incident_meta[incident_id] = meta
    store.flagged_wallets.add(case["wallet"])
    for other in store.cases.values():  # confirmed incident revokes the wallet's vault grants
        if other["wallet"] == case["wallet"]:
            other["revoked"] = True
    db_save_incident(incident_id, signature, category, disposition, evidence_hash, reviewer)
    h = db_audit(reviewer, "INCIDENT_CONFIRMED", incident_id, {"case": case["case_id"], "disposition": disposition})
    case["audit"].append({"actor": reviewer, "event": "INCIDENT_CONFIRMED", "at": _iso(time.time()), "payload_hash": h})
    case["incident_id"] = incident_id
    return {"incident_id": incident_id, "disposition": disposition, "category": category, "case_id": case["case_id"]}


@router.post("/incident/confirm")
def confirm_incident(req: IncidentConfirmRequest, who: Principal = Depends(require_employee)):
    """Store a reviewed incident signature in threat memory."""
    case = store.cases.get(req.case_id)
    if not case:
        raise HTTPException(404, "unknown case_id")
    if case.get("incident_id"):
        return {"incident_id": case["incident_id"], "status": "already_stored"}
    return remember_incident(case, req.disposition, who.name)


@router.get("/incidents")
def list_incidents():
    """Incident patterns for the employee console."""
    out = []
    for inc in getattr(store.threat_store, "_stored_incidents", []):
        meta = store.incident_meta.get(inc["incident_id"], {})
        out.append({
            "incident_id": inc["incident_id"], "category": inc.get("category"), "disposition": inc.get("disposition"),
            "evidence_hash": inc.get("evidence_hash"), "signature": inc.get("vector"), **{k: v for k, v in meta.items() if k != "incident_id"},
        })
    return {"count": len(out), "incidents": out}
