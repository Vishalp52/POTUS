"""In-process state for the API (cases, access log, flagged wallets) plus
persistence through the teammate's SQLAlchemy models/repository.

Threat memory itself is the teammate's ThreatStore; confirmed incidents are
also written to the `incidents` table and re-loaded on startup.
"""
from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.api import teammate as tm
from app.api.settings import BACKEND_DIR, settings
from app.chain.demo_replay import FLAGGED_COUNTERPARTIES
from app.features.schemas import MODEL_FEATURES, VECTOR_VERSION

log = logging.getLogger("potus.state")

FAILED_DECISIONS = {"CHALLENGE", "REVIEW", "RESTRICT", "AUTH_FAILED"}


@dataclass
class AccessAttempt:
    request_id: str
    wallet: str
    resource_id: str
    ts: float
    decision: str


@dataclass
class Store:
    cases: dict[str, dict[str, Any]] = field(default_factory=dict)
    attempts: dict[str, list[AccessAttempt]] = field(default_factory=lambda: defaultdict(list))
    flagged_wallets: set[str] = field(default_factory=set)
    incident_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    threat_store: Any = None
    lock: threading.RLock = field(default_factory=threading.RLock)

    # ---- access log -------------------------------------------------
    def record_attempt(self, a: AccessAttempt) -> None:
        with self.lock:
            a.wallet = a.wallet.lower()
            self.attempts[a.wallet].append(a)

    def app_counts(self, wallet: str, now: Optional[float] = None) -> tuple[int, int]:
        """(access requests in last 10m, failed/held attempts in last 1h) BEFORE the current request."""
        now = time.time() if now is None else now
        with self.lock:
            hist = self.attempts.get(wallet.lower(), [])
            req_10m = sum(1 for a in hist if 0 <= now - a.ts <= 600)
            failed_1h = sum(1 for a in hist if 0 <= now - a.ts <= 3600 and a.decision in FAILED_DECISIONS)
        return req_10m, failed_1h

    def flagged_counterparties(self) -> set[str]:
        with self.lock:
            return set(self.flagged_wallets) | (set(FLAGGED_COUNTERPARTIES) if settings.demo_enabled else set())

    def latest_case_for(self, wallet: str) -> Optional[dict[str, Any]]:
        with self.lock:
            cs = [c for c in self.cases.values() if c["wallet"] == wallet.lower()]
        return max(cs, key=lambda c: c["created_at_ts"]) if cs else None

    def reset(self) -> None:
        with self.lock:
            self.cases.clear()
            self.attempts.clear()
            self.flagged_wallets.clear()
            self.incident_meta.clear()
            self.threat_store = tm.ThreatStore()


store = Store(threat_store=tm.ThreatStore())

# ---------------------------------------------------------------- database
_db_url = settings.database_url
if _db_url.startswith("sqlite:///./"):
    _db_url = "sqlite:///" + str(BACKEND_DIR / _db_url[len("sqlite:///./"):])
engine = create_engine(_db_url, connect_args={"check_same_thread": False} if _db_url.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    tm.Base.metadata.create_all(engine)
    # Additive migration for databases created before incident provenance was saved.
    # Existing records remain intact and have unknown source metadata.
    if "source" not in {c["name"] for c in inspect(engine).get_columns("incidents")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE incidents ADD COLUMN source JSON"))


def _safe(fn, *args, **kwargs):
    try:
        with SessionLocal() as s:
            return fn(tm.Repository(s), s, *args, **kwargs)
    except Exception as exc:  # persistence must never break the security loop
        log.warning("db write failed: %s", exc)
        return None


def db_save_request(request_id: str, wallet: str, resource_id: str, action: str) -> None:
    _safe(lambda repo, s: repo.save_request(request_id, wallet, resource_id, action))


def db_audit(actor: str, event_type: str, object_id: str, payload: dict) -> str:
    h = tm.AuditService.hash_payload(payload)
    _safe(lambda repo, s: repo.record_audit(actor, event_type, object_id, h))
    return h


def db_save_incident(incident_id: str, vector: list[float], category: str, disposition: str, evidence_hash: str,
                     confirmed_by: str, source: Optional[dict] = None) -> bool:
    def _w(repo, s):
        s.merge(tm.IncidentModel(incident_id=incident_id, vector=vector, category=category, disposition=disposition,
                                 evidence_hash=evidence_hash, confirmed_by=confirmed_by, source=source))
        s.commit()
        return True
    return _safe(_w) is True


def db_clear_incidents() -> None:
    def _w(repo, s):
        s.query(tm.IncidentModel).delete()
        s.commit()
    _safe(_w)


def load_incidents_into_memory() -> int:
    """Restore validated, reviewed signatures and their provenance without duplicates."""
    loaded = 0
    try:
        with store.lock, SessionLocal() as s:
            for row in s.query(tm.IncidentModel).all():
                vec = row.vector or []
                source = row.source if isinstance(row.source, dict) else {}
                if row.incident_id in store.incident_meta:
                    continue
                if row.disposition not in {"CONFIRMED_INCIDENT", "SIMULATED_ATTACK"}:
                    continue
                if source.get("vector_version", VECTOR_VERSION) != VECTOR_VERSION:
                    continue
                if not isinstance(vec, list) or len(vec) != len(MODEL_FEATURES) or not all(
                    isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in vec
                ) or not any(vec):
                    log.warning("skipping incompatible incident signature: %s", row.incident_id)
                    continue
                simulated = source.get("simulated", True if row.disposition == "SIMULATED_ATTACK" else None)
                if simulated and not settings.demo_enabled:
                    continue
                store.threat_store.insert_incident(row.incident_id, vec, row.category or "", row.disposition or "", row.evidence_hash or "")
                wallet = source.get("wallet")
                wallet = wallet.lower() if isinstance(wallet, str) else None
                store.incident_meta[row.incident_id] = {
                    "incident_id": row.incident_id,
                    "confirmed_by": row.confirmed_by,
                    "confirmed_at": (row.confirmed_at or datetime.now(timezone.utc)).isoformat(),
                    "source_case": source.get("source_case"), "wallet": wallet, "simulated": simulated,
                }
                if wallet:
                    store.flagged_wallets.add(wallet)
                loaded += 1
    except Exception as exc:
        log.warning("could not load incidents: %s", exc)
    return loaded
