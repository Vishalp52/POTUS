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
    cors_origins: str = field(default_factory=lambda: os.getenv("CORS_ORIGINS", "http://localhost:3000"))

    # ---- security ---------------------------------------------------------------
    # development | production. Production fails closed: keys + wallet signatures required,
    # demo endpoints and /docs disabled unless explicitly enabled.
    app_env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development").lower())
    # "name:key,name2:key2" - employee console keys; reviewer identity comes from the key, not the request body
    employee_keys: str = field(default_factory=lambda: os.getenv("POTUS_EMPLOYEE_KEYS", ""))
    admin_key: str = field(default_factory=lambda: os.getenv("POTUS_ADMIN_KEY", ""))
    token_secret: str = field(default_factory=lambda: os.getenv("TOKEN_SECRET", ""))
    require_wallet_signature_env: str = field(default_factory=lambda: os.getenv("REQUIRE_WALLET_SIGNATURE", ""))
    enable_demo_env: str = field(default_factory=lambda: os.getenv("ENABLE_DEMO", ""))
    trust_proxy_headers: bool = field(default_factory=lambda: os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true")
    max_body_bytes: int = field(default_factory=lambda: _env_int("MAX_BODY_BYTES", 32_768))
    nonce_ttl_seconds: int = field(default_factory=lambda: _env_int("NONCE_TTL_SECONDS", 300))
    rate_limit_per_minute: int = field(default_factory=lambda: _env_int("RATE_LIMIT_PER_MINUTE", 30))

    @property
    def production(self) -> bool:
        return self.app_env == "production"

    @property
    def require_wallet_signature(self) -> bool:
        if self.require_wallet_signature_env:
            return self.require_wallet_signature_env.lower() == "true"
        return self.production

    @property
    def demo_enabled(self) -> bool:
        if self.enable_demo_env:
            return self.enable_demo_env.lower() == "true"
        return not self.production


settings = Settings()
