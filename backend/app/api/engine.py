"""The POTUS evaluation loop (spec §4), wiring:

    chain data (app/chain) -> features (app/features) -> IsolationForest (app/models)
    -> threat memory / rules / Gemini / fusion / policy (shared modules)
    -> on-chain evidence (app/chain/registry) -> case record + customer payload

Mirrors services/evaluator.py's order of operations, but keeps every
intermediate signal so the employee console can explain the decision.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Optional

import yaml

from app.ai.prompt import PROMPT_VERSION
from app.ai.typologies import TypologyMatcher
from app.api import teammate as tm
from app.api.messages import customer_payload
from app.api.security import issue_access_token, sanitize_for_gemini
from app.api.settings import settings
from app.api.state import AccessAttempt, db_audit, db_save_request, store
from app.chain.demo_replay import scenario_for
from app.chain.registry import RegistryWriter
from app.chain.source import get_wallet_activity
from app.chain.types import WalletActivity
from app.features.extractor import AppHistory, COLD_START_BLOCKS, extract_features, feature_flags
from app.features.schemas import MODEL_FEATURES, BehaviorFeatures, FeatureBundle
from app.models.model_store import load_detector

log = logging.getLogger("potus.engine")

HIGH_SEVERITY = {"SUSPICIOUS_FRAUD_LIKE", "POTENTIAL_ILLICIT_ACTIVITY"}
DECISION_TTL_SECONDS = 10 * 60  # validity of non-RESTRICT decisions


# ------------------------------------------------------------------ config + components
def load_risk_config() -> dict[str, Any]:
    try:
        with open(settings.risk_config_path) as f:
            config = yaml.safe_load(f)
    except Exception as exc:
        raise ValueError("risk configuration could not be loaded") from exc
    if not isinstance(config, dict):
        raise ValueError("risk configuration must be a mapping")
    controls = config.get("controls", {})
    if not isinstance(controls, dict):
        raise ValueError("risk controls must be a mapping")
    confidence = controls.get("gemini_min_confidence_for_severity", 0.70)
    import math
    if isinstance(confidence, bool) or not isinstance(confidence, (float, int)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError("minimum Gemini confidence must be between 0 and 1")
    return config


class Components:
    def __init__(self):
        self.config = load_risk_config()
        if tm.EvaluatorService is not None:
            ev = tm.EvaluatorService(self.config)       # teammate wiring (rules/fusion/policy/gemini/threat store)
            self.rules, self.fusion, self.policy = ev.rules, ev.fusion, ev.policy
            self.gemini = ev.gemini if tm.GeminiTriageClient is not None else None
        else:
            self.rules = tm.RuleEngine()
            self.fusion = tm.RiskFusionEngine(weights=self.config.get("weights"))
            self.policy = tm.PolicyEngine(thresholds=self.config.get("thresholds"))
            self.gemini = tm.GeminiTriageClient() if tm.GeminiTriageClient else None
        controls = self.config.get("controls", {}) or {}
        self.restrict_ttl = int(controls.get("restrict_ttl_minutes", 20)) * 60
        min_conf = controls.get("gemini_min_confidence_for_severity")
        if min_conf is not None:
            self.fusion.min_gemini_confidence = float(min_conf)
        self.detector = load_detector()
        self.registry = RegistryWriter()

    @property
    def weights(self) -> dict[str, float]:
        return dict(self.fusion.weights)

    @property
    def thresholds(self) -> dict[str, int]:
        return {"allow_max": self.policy.allow_max, "challenge_max": self.policy.challenge_max, "review_max": self.policy.review_max}


_components: Optional[Components] = None


def components() -> Components:
    global _components
    if _components is None:
        _components = Components()
    return _components


async def close_components() -> None:
    """Release the SDK at shutdown and allow a later application lifespan to reopen it."""
    global _components
    c, _components = _components, None
    if c is not None and c.gemini is not None:
        await c.gemini.aclose()


# ------------------------------------------------------------------ Gemini
def mock_triage(evidence: dict[str, Any], rule_reasons: list[str]) -> Any:
    """Deterministic stand-in with the SAME schema (spec §15 scope gate)."""
    flags = set(evidence.get("hard_flags", [])) | set(rule_reasons)
    strong = flags & {"ACCESS_BURST", "VALUE_OUTLIER", "NEW_CONTRACT_SPIKE", "REPEATED_DENIALS"}
    sim = evidence.get("pattern_similarity", 0.0)
    anomaly = evidence.get("anomaly_score", 0.0)
    if any(t["category"] == "POTENTIAL_ILLICIT_ACTIVITY" for t in TypologyMatcher().match(evidence)):
        cat, conf, sem = "POTENTIAL_ILLICIT_ACTIVITY", 0.74, 80
        summary = "Behavior matches multiple configured high-risk typology indicators; this is not a legal determination."
        reason = "SECURITY_REVIEW"
    elif len(strong) >= 2 or (sim >= 0.6 and strong):
        cat, conf, sem = "SUSPICIOUS_FRAUD_LIKE", 0.89 if len(strong) >= 3 else 0.82, 84
        summary = "Pattern resembles account-takeover style behavior: " + ", ".join(sorted(strong)).lower().replace("_", " ") + "."
        reason = "ACCESS_TEMPORARILY_LIMITED"
    elif evidence.get("history_confidence") == "low" and anomaly < 0.6:
        cat, conf, sem = "INSUFFICIENT_EVIDENCE", 0.55, 35
        summary = "Limited wallet history; evidence does not support a confident classification."
        reason = "VERIFY_IDENTITY"
    elif anomaly >= 0.35:
        cat, conf, sem = "SLIGHT_ANOMALY", 0.78, 28
        summary = "Unusual but weak evidence; no value outlier or known-pattern match."
        reason = "UNUSUAL_ACTIVITY"
    else:
        cat, conf, sem = "NORMAL_OR_BENIGN", 0.9, 5
        summary = "No meaningful threat pattern; consistent with recent baseline."
        reason = "NONE"
    benign = (["automated wallet migration or scripted batch activity", "user resumed activity after inactivity"]
              if cat in HIGH_SEVERITY else
              ["user resumed activity after inactivity", "automated wallet migration or scripted batch activity"])
    return tm.GeminiTriage(
        category=tm.gemini_category(cat), confidence=conf, semantic_risk=sem,
        supporting_indicators=sorted(strong) or ["no strong indicators"],
        benign_explanations=benign if cat != "NORMAL_OR_BENIGN" else ["normal variance"],
        employee_summary=summary, customer_reason_code=reason,
        requires_human_review=cat in HIGH_SEVERITY or cat == "INSUFFICIENT_EVIDENCE",
    )


async def run_triage(evidence: dict, rule_reasons: list[str], anomaly: float, force_outage: bool) -> tuple[Any, str]:
    c = components()
    if anomaly < settings.gemini_trigger_score:
        return None, "not_triggered"
    if force_outage or settings.gemini_mode == "off":
        return None, "unavailable"
    if settings.gemini_mode == "mock":
        return mock_triage(evidence, rule_reasons), "mock"
    if c.gemini is None or getattr(c.gemini, "client", None) is None:
        return None, "unavailable"
    packet = sanitize_for_gemini(evidence)  # allowlisted typed fields only: no identity, no free text
    try:
        triage = await asyncio.wait_for(
            c.gemini.triage(packet),
            timeout=settings.gemini_timeout_seconds,
        )
    except asyncio.TimeoutError:
        return None, "timeout"
    except Exception as exc:
        log.warning("gemini triage failed (%s)", type(exc).__name__)
        return None, "error"
    return (triage, "ok") if triage is not None else (None, "error")


# ------------------------------------------------------------------ core
def new_request_id() -> str:
    # 96 bits of randomness: request IDs are not guessable
    return "req_" + datetime.now(timezone.utc).strftime("%y%m%d%H%M%S") + secrets.token_hex(12).upper()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def build_bundle(wallet: str, resource_id: str, demo_scenario: Optional[str], now: float,
                 activity: Optional[WalletActivity] = None) -> FeatureBundle:
    c = components()
    activity = activity or get_wallet_activity(wallet, demo_scenario, now=now)
    req_10m, failed_1h = store.app_counts(wallet, now)
    scen = scenario_for(wallet, demo_scenario)
    if scen:  # labeled simulated preceding attempts for the scenario
        req_10m += scen.seed_access_requests_10m
        failed_1h += scen.seed_failed_access
    app = AppHistory(access_requests_10m=req_10m + 1, failed_access_count=failed_1h,
                     flagged_counterparties=store.flagged_counterparties())
    return extract_features(activity, resource_id, app, c.detector.population, now=now)


def bundle_from_features(features: BehaviorFeatures, wallet: str, resource_id: str) -> FeatureBundle:
    """For POST /score with a raw feature vector."""
    from app.features.baselines import BASELINE_FLOORS, deviation_signature, ratio
    det = components().detector
    vec = features.model_vector()
    baselines = {k: max(floor, det.population.median[k]) for k, floor in BASELINE_FLOORS.items()}
    deltas = {k: {"value": float(getattr(features, k)), "baseline": baselines[k],
                  "ratio": ratio(float(getattr(features, k)), baselines[k])}
              for k in ("tx_count_10m", "tx_count_1h", "unique_contracts_24h", "new_contract_ratio", "access_requests_10m")}
    deltas.update({"transfer_value_zscore": features.transfer_value_zscore, "failed_access_count": features.failed_access_count,
                   "flagged_counterparty_count": features.flagged_counterparty_count})
    cold = features.wallet_age_blocks is not None and features.wallet_age_blocks < COLD_START_BLOCKS
    return FeatureBundle(wallet=wallet, resource_id=resource_id, features=features, feature_deltas=deltas,
                         baselines=baselines,
                         hard_flags=feature_flags(features, deltas, cold=cold), data_source="provided",
                         history_confidence="low" if cold or features.wallet_age_blocks is None else "normal",
                         vector=vec, signature=deviation_signature(det.population, vec))


def component_breakdown(anomaly: float, rule: float, sim: float, triage: Any) -> dict[str, Any]:
    w = components().weights
    parts = {"anomaly": anomaly * 100, "rules": rule * 100, "threat_similarity": sim * 100}
    if triage is not None:
        parts["gemini_semantic"] = float(triage.semantic_risk)
        active = w
    else:
        total = w["anomaly"] + w["rules"] + w["threat_similarity"]
        active = {k: w[k] / total for k in ("anomaly", "rules", "threat_similarity")}
    return {k: {"value_100": round(v, 1), "weight": round(active[k], 4), "points": round(active[k] * v, 1)}
            for k, v in parts.items()}


async def score_bundle(bundle: FeatureBundle, force_outage: bool = False) -> dict[str, Any]:
    """Detector -> threat memory -> rules -> Gemini -> fusion -> policy. No side effects."""
    c = components()
    anomaly = c.detector.score(bundle.vector)

    try:
        sim, matched = store.threat_store.find_max_similarity(bundle.signature)
    except Exception as exc:  # e.g. vector-length mismatch with an old incident
        log.warning("threat memory lookup failed: %s", exc)
        sim, matched = 0.0, ""
    sim = round(max(0.0, float(sim)), 4)
    bundle.features.pattern_similarity = sim
    evidence = bundle.evidence_packet(anomaly)

    rule_score, rule_reasons = c.rules.evaluate(evidence)
    rule_codes = [r.value if hasattr(r, "value") else str(r) for r in rule_reasons]

    triage, gemini_status = await run_triage(evidence, rule_codes, anomaly, force_outage)

    risk, reasons, forced_review = c.fusion.compute_fused_risk(
        anomaly_score=anomaly, rule_score=rule_score, pattern_similarity=sim,
        gemini_triage=triage, rule_reasons=rule_reasons,
    )
    result = c.policy.evaluate(risk, reasons, forced_review)
    # Missing chain evidence must not look like a clean, inactive wallet.
    # Keep stronger deterministic restrictions, but hold otherwise permissive
    # decisions for review until evidence can be retrieved.
    data_review = bundle.data_source == "none" and result["decision"] in {"ALLOW", "CHALLENGE"}
    if data_review:
        result = c.policy.evaluate(max(risk, c.policy.challenge_max + 1),
                                   [*reasons, "CHAIN_DATA_UNAVAILABLE"], True)
    reason_codes = sorted(result["reason_codes"])

    guardrails = []
    if data_review:
        guardrails.append("Chain evidence unavailable -> REVIEW until evidence can be retrieved")
    if forced_review:
        guardrails.append("AI uncertainty or explicit review request -> REVIEW")
    if rule_score >= 0.75 and anomaly >= 0.80:
        guardrails.append("Strong hard rules + high anomaly -> minimum REVIEW score floor (55)")
    if triage is None and gemini_status not in ("not_triggered",):
        guardrails.append(f"Gemini {gemini_status}: AI term removed and remaining weights renormalized")

    return {
        "anomaly": anomaly, "rule_score": round(float(rule_score), 4), "rule_codes": rule_codes,
        "similarity": sim, "matched_incident": matched or None,
        "triage": triage, "gemini_status": gemini_status, "prompt_version": PROMPT_VERSION,
        "risk_score": int(result["risk_score"]), "decision": result["decision"],
        "reason_codes": reason_codes, "policy_customer": result.get("customer", {}),
        "forced_review": forced_review or data_review, "guardrails": guardrails, "evidence": evidence,
        "breakdown": component_breakdown(anomaly, float(rule_score), sim, triage),
    }


def public_signals(scored: dict[str, Any]) -> dict[str, Any]:
    t = scored["triage"]
    return {
        "anomaly_score": scored["anomaly"],
        "rule_score": scored["rule_score"],
        "pattern_similarity": scored["similarity"],
        "gemini": None if t is None else {
            "category": tm.normalize_category(t.category), "confidence": t.confidence, "semantic_risk": t.semantic_risk},
        "gemini_status": scored["gemini_status"],
    }


async def evaluate_access(wallet: str, resource_id: str, action: str, demo_scenario: Optional[str] = None,
                          simulate_ai_outage: bool = False, actor: str = "api",
                          wallet_verified: bool = False, ownership_required: bool = False) -> dict[str, Any]:
    """Full loop for POST /access/request: score, persist case, write evidence, gate."""
    c = components()
    now = time.time()
    request_id = new_request_id()
    wallet = wallet.lower()
    scen = scenario_for(wallet, demo_scenario)
    force_outage = simulate_ai_outage or bool(scen and scen.ai_outage)

    activity = await asyncio.to_thread(get_wallet_activity, wallet, demo_scenario, now)
    bundle = build_bundle(wallet, resource_id, demo_scenario, now, activity)
    scored = await score_bundle(bundle, force_outage)

    decision = scored["decision"]
    expires = now + (c.restrict_ttl if decision == "RESTRICT" else DECISION_TTL_SECONDS)

    hash_payload = {
        "request_id": request_id, "wallet": wallet, "resource_id": resource_id, "action": action,
        "risk_score": scored["risk_score"], "decision": decision, "reason_codes": scored["reason_codes"],
        "evidence": scored["evidence"], "vector": bundle.vector, "created_at": int(now),
    }
    evidence_hash = "0x" + tm.AuditService.hash_payload(hash_payload)

    onchain = await asyncio.to_thread(c.registry.publish_minimal_record, wallet, scored["risk_score"], int(expires), evidence_hash, decision)

    customer = customer_payload(request_id, decision, scored["policy_customer"])
    # Vault token only for ALLOW, and only when wallet ownership is proven (or not required)
    access_token = None
    if decision == "ALLOW" and (wallet_verified or not ownership_required):
        access_token = issue_access_token(request_id, wallet, resource_id, expires)
    response = {
        "request_id": request_id, "wallet": wallet, "resource_id": resource_id, "action": action,
        "risk_score": scored["risk_score"], "decision": decision, "expires_at": _iso(expires),
        "signals": public_signals(scored), "reason_codes": scored["reason_codes"],
        "customer": customer, "evidence_hash": evidence_hash, "onchain": onchain, "simulated": bundle.simulated,
        "wallet_verified": wallet_verified, "access_token": access_token,
    }

    case = {
        "case_id": request_id, "request_id": request_id, "wallet": wallet, "resource_id": resource_id,
        "action": action, "created_at": _iso(now), "created_at_ts": now, "expires_at_ts": expires,
        "status": "OPEN" if decision != "ALLOW" else "CLOSED",
        "decision": decision, "resolved": False,
        "scored": scored, "bundle": bundle.model_dump(),
        "response": {k: v for k, v in response.items() if k != "access_token"},  # never persist bearer tokens
        "activity": {"source": activity.source, "notes": activity.notes, "simulated": activity.simulated,
                     "txs": [t.__dict__ for t in sorted(activity.txs, key=lambda t: -t.timestamp)[:25]]},
        "scenario": scen.key if scen else None, "reviews": [], "audit": [],
        "wallet_verified": wallet_verified,
    }
    with store.lock:
        if decision in ("REVIEW", "RESTRICT"):  # escalation revokes this wallet's earlier vault grants
            for other in store.cases.values():
                if other["wallet"] == wallet:
                    other["revoked"] = True
        store.cases[request_id] = case
    store.record_attempt(AccessAttempt(request_id, wallet, resource_id, now, decision))

    db_save_request(request_id, wallet, resource_id, action)
    audit_hash = db_audit(actor, "ACCESS_EVALUATED", request_id, {"decision": decision, "evidence_hash": evidence_hash})
    case["audit"].append({"actor": actor, "event": "ACCESS_EVALUATED", "at": _iso(now), "payload_hash": audit_hash})
    return response


def vector_dim() -> int:
    return len(MODEL_FEATURES)
