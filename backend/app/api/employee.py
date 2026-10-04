"""Employee investigation console routes (spec §10). Full evidence lives here;
the customer only ever sees app/api/messages.py output."""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Query

from app.api import teammate as tm
from app.api.engine import _iso, components
from app.api.incidents import STORABLE, remember_incident
from app.api.schemas import ReviewRequest
from app.api.state import db_audit, store
from app.features.baselines import PopulationStats
from app.features.schemas import MODEL_FEATURES

router = APIRouter(tags=["employee"])

ACTIONS = ["CONFIRMED_INCIDENT", "SIMULATED_ATTACK", "BENIGN", "NEEDS_MORE_EVIDENCE", "CUSTOMER_VERIFIED"]


def _severity(decision: str) -> str:
    return {"ALLOW": "LOW", "CHALLENGE": "MEDIUM", "REVIEW": "HIGH", "RESTRICT": "CRITICAL"}[decision]


def _deviations(case: dict) -> list[dict]:
    b = case["bundle"]
    pop: PopulationStats = components().detector.population
    z_all = pop.standardize(b["vector"])
    rows = []
    for name, val, z in zip(MODEL_FEATURES, b["vector"], z_all):
        d = b["feature_deltas"].get(name)
        rows.append({
            "feature": name, "value": val,
            "baseline": d["baseline"] if isinstance(d, dict) else pop.median[name],
            "ratio": d["ratio"] if isinstance(d, dict) else None,
            "population_z": round(z, 2),
        })
    return sorted(rows, key=lambda r: -abs(r["population_z"]))


def _summary_card(case: dict) -> str:
    s = case["scored"]
    t = s["triage"]
    resp = case["response"]
    head = f"CASE {case['case_id']} • RISK {resp['risk_score']} • {resp['decision']}"
    parts = []
    if t is not None:
        parts.append(f"Gemini triage: {tm.normalize_category(t.category)} ({round(t.confidence * 100)}% confidence).")
    else:
        parts.append(f"Gemini triage: {s['gemini_status']} (deterministic path).")
    signals = []
    d = case["bundle"]["feature_deltas"]
    if d["tx_count_10m"]["ratio"] >= 2:
        signals.append(f"{d['tx_count_10m']['ratio']:.1f}x transaction burst")
    if d["transfer_value_zscore"] >= 2:
        signals.append(f"transfer value {d['transfer_value_zscore']:.1f}σ above baseline")
    if d["failed_access_count"]:
        signals.append(f"{d['failed_access_count']} failed protected-resource requests")
    if s["similarity"] >= 0.3 and s["matched_incident"]:
        signals.append(f"{s['similarity']:.2f} similarity to confirmed incident {s['matched_incident']}")
    if signals:
        parts.append("Main signals: " + ", ".join(signals) + ".")
    if t is not None and t.benign_explanations:
        parts.append("Plausible benign explanation: " + t.benign_explanations[0] + ".")
    return head + "\n" + " ".join(parts)


def case_packet(case: dict) -> dict:
    s = case["scored"]
    t = s["triage"]
    c = components()
    matched = s["matched_incident"]
    return {
        "case_header": {
            "case_id": case["case_id"], "wallet": case["wallet"], "request_id": case["request_id"],
            "resource_id": case["resource_id"], "action": case["action"], "timestamp": case["created_at"],
            "decision": "RESOLVED" if case.get("resolved") else case["decision"],
            "ttl_seconds": max(0, int(case["expires_at_ts"] - time.time())), "status": case["status"],
            "scenario": case.get("scenario"), "simulated": case["activity"]["simulated"],
        },
        "summary_card": _summary_card(case),
        "risk_summary": {
            "risk_score": case["response"]["risk_score"], "severity": _severity(case["decision"]),
            "components": s["breakdown"], "review_state": case["status"],
        },
        "behavior_deltas": _deviations(case),
        "hard_flags": case["bundle"]["hard_flags"],
        "gemini_triage": None if t is None else {**t.model_dump(), "category": tm.normalize_category(t.category)},
        "gemini_status": s["gemini_status"],
        "threat_memory": {
            "closest_incident": matched, "similarity": s["similarity"],
            "disposition": next((i["disposition"] for i in getattr(store.threat_store, "_stored_incidents", [])
                                 if i["incident_id"] == matched), None) if matched else None,
            "simulated": store.incident_meta.get(matched, {}).get("simulated") if matched else None,
        },
        "timeline": {
            "data_source": case["activity"]["source"], "notes": case["activity"]["notes"],
            "recent_transactions": case["activity"]["txs"],
            "access_attempts": [
                {"request_id": a.request_id, "resource_id": a.resource_id, "at": _iso(a.ts), "decision": a.decision}
                for a in sorted(store.attempts.get(case["wallet"], []), key=lambda a: -a.ts)[:20]
            ],
        },
        "policy_trace": {
            "reason_codes": s["reason_codes"], "rule_codes": s["rule_codes"], "rule_score": s["rule_score"],
            "thresholds": c.thresholds, "weights": c.weights, "guardrails": s["guardrails"],
            "forced_review": s["forced_review"],
            "note": "Deterministic code produced this decision; Gemini contributes a capped semantic term only.",
        },
        "evidence": {"evidence_hash": case["response"]["evidence_hash"], "onchain": case["response"]["onchain"],
                     "packet": s["evidence"]},
        "actions": ACTIONS,
        "audit": {"reviews": case["reviews"], "events": case["audit"]},
        "customer_view": case["response"]["customer"],
    }


@router.get("/cases")
def list_cases(status: str | None = Query(None), limit: int = Query(50, le=500)):
    cases = sorted(store.cases.values(), key=lambda c: -c["created_at_ts"])
    if status:
        cases = [c for c in cases if c["status"] == status.upper()]
    return {"cases": [{
        "case_id": c["case_id"], "wallet": c["wallet"], "resource_id": c["resource_id"], "created_at": c["created_at"],
        "decision": "RESOLVED" if c.get("resolved") else c["decision"], "risk_score": c["response"]["risk_score"],
        "status": c["status"], "scenario": c.get("scenario"),
    } for c in cases[:limit]]}


@router.get("/cases/{case_id}")
def get_case(case_id: str):
    """Full employee-facing investigation packet."""
    case = store.cases.get(case_id)
    if not case:
        raise HTTPException(404, "unknown case")
    return case_packet(case)


@router.post("/cases/{case_id}/review")
def review_case(case_id: str, req: ReviewRequest):
    """Record analyst disposition / notes; confirmed incidents enter threat memory."""
    case = store.cases.get(case_id)
    if not case:
        raise HTTPException(404, "unknown case")
    now = time.time()
    incident = None
    if req.disposition in STORABLE and not case.get("incident_id"):
        incident = remember_incident(case, req.disposition, req.reviewer)
    if req.disposition == "CUSTOMER_VERIFIED":
        case["resolved"] = True
        case["expires_at_ts"] = max(case["expires_at_ts"], now + 600)
    case["status"] = {"NEEDS_MORE_EVIDENCE": "OPEN", "CUSTOMER_VERIFIED": "RESOLVED"}.get(req.disposition, "CLOSED")
    review = {"reviewer": req.reviewer, "disposition": req.disposition, "note": req.note, "at": _iso(now)}
    case["reviews"].append(review)
    h = db_audit(req.reviewer, "CASE_REVIEWED", case_id, review)
    case["audit"].append({"actor": req.reviewer, "event": "CASE_REVIEWED", "at": _iso(now), "payload_hash": h})
    return {"case_id": case_id, "status": case["status"], "review": review, "incident": incident}
