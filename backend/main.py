"""POTUS backend entrypoint.

Run from the backend/ folder:
    uvicorn main:app --reload --port 8000
Docs (development only): http://localhost:8000/docs
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import teammate  # noqa: F401  (must load first: teammate-module compatibility)
from app.api import access, demo, employee, incidents, wallets
from app.api.engine import components
from app.api.security import (
    BodySizeLimitMiddleware, Principal, SecurityHeadersMiddleware, require_employee,
)
from app.api.settings import settings
from app.api.state import init_db, load_incidents_into_memory

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("potus")


def check_security_posture() -> None:
    """Fail closed in production; warn loudly in development."""
    problems = []
    if not (settings.admin_key or settings.employee_keys):
        problems.append("no POTUS_ADMIN_KEY / POTUS_EMPLOYEE_KEYS: employee routes are unauthenticated")
    if not settings.token_secret:
        problems.append("no TOKEN_SECRET: vault tokens use a per-process random key")
    if "*" in settings.cors_origins:
        problems.append("CORS_ORIGINS contains '*'")
    for key in filter(None, [settings.admin_key, *[k.partition(":")[2] for k in settings.employee_keys.split(",")]]):
        if len(key) < 24:
            problems.append("an API key is shorter than 24 characters")
            break
    if settings.production and problems:
        raise RuntimeError("Refusing to start in production: " + "; ".join(problems))
    for p in problems:
        log.warning("SECURITY (dev mode): %s", p)


@asynccontextmanager
async def lifespan(_: FastAPI):
    check_security_posture()
    init_db()
    c = components()  # loads risk config + trains/loads IsolationForest
    n = load_incidents_into_memory()
    log.info("POTUS ready: env=%s, model=%s, incidents=%d, gemini_mode=%s, registry=%s, wallet_sig_required=%s, demo=%s",
             settings.app_env, c.detector.trained_on, n, settings.gemini_mode,
             "on" if c.registry.enabled else "off", settings.require_wallet_signature, settings.demo_enabled)
    try:
        yield
    finally:
        from app.api.engine import close_components
        await close_components()


app = FastAPI(
    title="POTUS API",
    version="2.1.0",
    description="Adaptive behavioral threat intelligence and access control for Monad.",
    lifespan=lifespan,
    docs_url=None if settings.production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.production else "/openapi.json",
)

# Order: outermost first
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    max_age=600,
)
if settings.production:
    import os
    hosts = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()]
    if hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

for r in (access.router, wallets.router, incidents.router, employee.router, demo.router):
    app.include_router(r)


# ------------------------------------------------------------------ error handling
@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    # Field names + messages only; never echo the submitted values back
    errors = [{"loc": [str(x) for x in e.get("loc", [])], "msg": e.get("msg", "invalid")} for e in exc.errors()]
    return JSONResponse({"detail": "invalid request", "errors": errors}, status_code=422)


@app.exception_handler(Exception)
async def unhandled_error(_: Request, exc: Exception):
    log.exception("unhandled error: %s", type(exc).__name__)
    return JSONResponse({"detail": "internal error"}, status_code=500)  # no stack traces to clients


# ------------------------------------------------------------------ health
@app.get("/health", tags=["meta"])
def health():
    """Public liveness only - no configuration details."""
    return {"status": "ok"}


@app.get("/health/details", tags=["meta"])
def health_details(_: Principal = Depends(require_employee)):
    c = components()
    gemini_ready = c.gemini is not None and getattr(c.gemini, "client", None) is not None
    return {
        "status": "ok",
        "env": settings.app_env,
        "model": c.detector.info(),
        "gemini": {"mode": settings.gemini_mode, "client_configured": gemini_ready,
                   "trigger_score": settings.gemini_trigger_score,
                   "model": getattr(c.gemini, "model_name", None),
                   "api": getattr(c.gemini, "api_mode", None),
                   "thinking_level": getattr(c.gemini, "thinking_level", None),
                   "timeout_seconds": settings.gemini_timeout_seconds},
        "data_source": settings.data_source,
        "envio_configured": bool(settings.envio_hypersync_url),
        "registry_configured": c.registry.enabled,
        "security": {"wallet_signature_required": settings.require_wallet_signature,
                     "demo_enabled": settings.demo_enabled,
                     "employee_auth_configured": bool(settings.admin_key or settings.employee_keys)},
    }
