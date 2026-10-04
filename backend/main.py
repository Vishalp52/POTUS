"""POTUS backend entrypoint.

Run from the backend/ folder:
    uvicorn main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import teammate  # noqa: F401  (must load first: teammate-module compatibility)
from app.api import access, demo, employee, incidents, wallets
from app.api.engine import components
from app.api.settings import settings
from app.api.state import init_db, load_incidents_into_memory

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("potus")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    c = components()  # loads risk config + trains/loads IsolationForest
    n = load_incidents_into_memory()
    log.info("POTUS ready: model=%s, incidents=%d, gemini_mode=%s, registry=%s",
             c.detector.trained_on, n, settings.gemini_mode, "on" if c.registry.enabled else "off")
    yield


app = FastAPI(
    title="POTUS API",
    version="2.0.0",
    description="Adaptive behavioral threat intelligence and access control for Monad.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)

for r in (access.router, wallets.router, incidents.router, employee.router, demo.router):
    app.include_router(r)


@app.get("/health", tags=["meta"])
def health():
    c = components()
    gemini_ready = c.gemini is not None and getattr(c.gemini, "client", None) is not None
    return {
        "status": "ok",
        "model": c.detector.info(),
        "gemini": {"mode": settings.gemini_mode, "client_configured": gemini_ready,
                   "trigger_score": settings.gemini_trigger_score},
        "data_source": settings.data_source,
        "envio_configured": bool(settings.envio_hypersync_url),
        "registry_configured": c.registry.enabled,
        "risk_config": settings.risk_config_path,
    }
