"""Compatibility imports for the shared backend modules.

Legacy filename/import aliases remain supported. All modules may be maintained
as part of this backend; this adapter imposes no team-ownership restrictions.
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
import typing
from types import ModuleType

from app.api.settings import BACKEND_DIR, TEAM_SERVICES_DIR

log = logging.getLogger("potus.teammate")

for _p in (str(BACKEND_DIR), str(TEAM_SERVICES_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _alias_reason_codes() -> ModuleType:
    try:
        return importlib.import_module("app.risk.reason_codes")
    except ModuleNotFoundError:
        mod = importlib.import_module("app.risk.reasons_codes")
        sys.modules["app.risk.reason_codes"] = mod
        log.info("compat: aliased app.risk.reason_codes -> app.risk.reasons_codes")
        return mod


def _load_policy() -> ModuleType:
    try:
        return importlib.import_module("app.risk.policy")
    except NameError:
        sys.modules.pop("app.risk.policy", None)
        path = BACKEND_DIR / "app" / "risk" / "policy.py"
        spec = importlib.util.spec_from_file_location("app.risk.policy", path)
        mod = importlib.util.module_from_spec(spec)
        mod.Optional = typing.Optional  # missing import in teammate file
        sys.modules["app.risk.policy"] = mod
        spec.loader.exec_module(mod)
        log.info("compat: loaded app.risk.policy with Optional pre-seeded")
        return mod


reason_codes = _alias_reason_codes()
ReasonCode = reason_codes.ReasonCode
policy_mod = _load_policy()
PolicyEngine = policy_mod.PolicyEngine

from app.risk.rules import RuleEngine  # noqa: E402
from app.risk.fusion import RiskFusionEngine  # noqa: E402
from app.memory.threat_store import ThreatStore  # noqa: E402
from app.memory.similarity import cosine_similarity  # noqa: E402
from app.ai.schemas import GeminiTriage  # noqa: E402
from app.db.models import Base, AccessRequestModel, IncidentModel, AuditEventModel  # noqa: E402
from app.db.repository import Repository  # noqa: E402

try:
    from app.ai.gemini_client import GeminiTriageClient  # noqa: E402
except Exception as exc:  # google-genai missing etc. -> deterministic fallback still works
    log.warning("Gemini client unavailable (%s); fallback path only", exc)
    GeminiTriageClient = None  # type: ignore[assignment]

from services.audit import AuditService  # noqa: E402

try:
    from services.evaluator import EvaluatorService  # noqa: E402
except Exception as exc:  # only used for wiring convenience
    log.warning("EvaluatorService import failed (%s)", exc)
    EvaluatorService = None  # type: ignore[assignment]


def gemini_category(name: str) -> str:
    """Map a spec label (e.g. NORMAL_OR_BENIGN) onto the exact literal used in
    the teammate's GeminiTriage schema (which currently spells some with spaces)."""
    allowed = typing.get_args(GeminiTriage.model_fields["category"].annotation)
    norm = lambda s: s.replace(" ", "_").upper()  # noqa: E731
    for value in allowed:
        if norm(value) == norm(name):
            return value
    raise ValueError(f"unknown Gemini category {name!r}; allowed={allowed}")


def normalize_category(value: str | None) -> str | None:
    """Spec-style label (underscored) for API responses."""
    return value.replace(" ", "_").upper() if value else value


__all__ = [
    "ReasonCode", "PolicyEngine", "RuleEngine", "RiskFusionEngine", "ThreatStore",
    "cosine_similarity", "GeminiTriage", "GeminiTriageClient", "Base", "AccessRequestModel",
    "IncidentModel", "AuditEventModel", "Repository", "AuditService", "EvaluatorService",
    "gemini_category", "normalize_category",
]
