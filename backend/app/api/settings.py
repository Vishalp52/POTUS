"""Runtime settings for the POTUS backend (read from environment / .env)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[2]          # .../backend
REPO_DIR = BACKEND_DIR.parent                              # repo root
# Teammate-owned folder (services + tests + scripts + config). Name kept as-is.
TEAM_SERVICES_DIR = BACKEND_DIR / "services + tests + scripts + config"

load_dotenv(BACKEND_DIR / ".env")
load_dotenv(REPO_DIR / ".env")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _default_risk_config() -> str:
    for candidate in (
        TEAM_SERVICES_DIR / "config" / "risk.yaml",
        BACKEND_DIR / "config" / "risk.yaml",
    ):
        if candidate.exists():
            return str(candidate)
    return str(TEAM_SERVICES_DIR / "config" / "risk.yaml")


@dataclass(frozen=True)
class Settings:
    monad_rpc_url: str = field(default_factory=lambda: os.getenv("MONAD_RPC_URL", "https://rpc.monad.xyz"))
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./potus.db"))
    risk_config_path: str = field(default_factory=lambda: os.getenv("RISK_CONFIG_PATH") or _default_risk_config())

    # Gemini: "auto" = real API when GEMINI_API_KEY is set, else deterministic fallback (no AI term)
    #         "mock" = deterministic mock triage (spec scope gate for the recorded demo)
    #         "off"  = never call Gemini (demonstrates the outage fallback path)
    gemini_mode: str = field(default_factory=lambda: os.getenv("GEMINI_MODE", "auto").lower())
    gemini_timeout_seconds: float = field(default_factory=lambda: _env_float("GEMINI_TIMEOUT_SECONDS", 6.0))
    gemini_trigger_score: float = field(default_factory=lambda: _env_float("GEMINI_TRIGGER_SCORE", 0.35))

    # Chain data: "auto" = Envio HyperSync if configured, then Monad RPC; demo wallets always use replay data
    data_source: str = field(default_factory=lambda: os.getenv("DATA_SOURCE", "auto").lower())
    envio_hypersync_url: str = field(default_factory=lambda: os.getenv("ENVIO_HYPERSYNC_URL", ""))
    envio_api_token: str = field(default_factory=lambda: os.getenv("ENVIO_API_TOKEN", ""))
    rpc_scan_blocks: int = field(default_factory=lambda: _env_int("RPC_SCAN_BLOCKS", 150))
    chain_timeout_seconds: float = field(default_factory=lambda: _env_float("CHAIN_TIMEOUT_SECONDS", 8.0))
    monad_block_time_seconds: float = field(default_factory=lambda: _env_float("MONAD_BLOCK_TIME_SECONDS", 0.4))

    # On-chain evidence (PotusRegistry). Writes are skipped unless both are set.
    potus_registry_address: str = field(default_factory=lambda: os.getenv("POTUS_REGISTRY_ADDRESS", ""))
    oracle_private_key: str = field(default_factory=lambda: os.getenv("ORACLE_PRIVATE_KEY", ""))

    model_path: str = field(default_factory=lambda: os.getenv("MODEL_PATH", str(BACKEND_DIR / "app" / "models" / "artifacts" / "isolation_forest.joblib")))
    cors_origins: str = field(default_factory=lambda: os.getenv("CORS_ORIGINS", "*"))


settings = Settings()
