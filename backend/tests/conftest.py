import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

# Deterministic, offline test configuration
os.environ.setdefault("GEMINI_MODE", "mock")
os.environ.setdefault("DATA_SOURCE", "auto")
os.environ["DATABASE_URL"] = "sqlite:///" + str(BACKEND / "tests" / ".test_potus.db")
os.environ["POTUS_REGISTRY_ADDRESS"] = ""
os.environ["ENVIO_HYPERSYNC_URL"] = ""
os.environ["APP_ENV"] = "development"
os.environ["POTUS_ADMIN_KEY"] = ADMIN_KEY = "test-admin-key-0123456789abcdef"
os.environ["POTUS_EMPLOYEE_KEYS"] = "alice:" + (EMPLOYEE_KEY := "test-employee-key-0123456789abc")
os.environ["TOKEN_SECRET"] = "test-token-secret-0123456789abcdef0123456789"
os.environ["RATE_LIMIT_PER_MINUTE"] = "1000"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client():
    import main
    with TestClient(main.app, headers={"X-API-Key": ADMIN_KEY}) as c:
        yield c


@pytest.fixture()
def anon(client):
    """Same app, no API key (public caller / attacker)."""
    return TestClient(client.app)


@pytest.fixture(autouse=True)
def _reset(client):
    client.post("/demo/reset")
    yield


@pytest.fixture(scope="session")
def scenarios(client):
    return {s["key"]: s for s in client.get("/demo/scenarios").json()["scenarios"]}
