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

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client():
    import main
    with TestClient(main.app) as c:
        yield c


@pytest.fixture(autouse=True)
def _reset(client):
    client.post("/demo/reset")
    yield


@pytest.fixture(scope="session")
def scenarios(client):
    return {s["key"]: s for s in client.get("/demo/scenarios").json()["scenarios"]}
