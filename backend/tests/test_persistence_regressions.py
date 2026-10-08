"""Persistence, evidence availability and retrieved-state regressions."""
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import create_engine, inspect, text

from app.api import incidents, state
from app.api.state import AccessAttempt, Store, store
from app.features.schemas import MODEL_FEATURES


def create_case(client, scenarios, key="C"):
    response = client.post("/access/request", json={"wallet": scenarios[key]["wallet"]})
    assert response.status_code == 200, response.text
    return response.json()["request_id"]


def test_incident_provenance_and_flags_survive_reload(client, scenarios):
    case_id = create_case(client, scenarios)
    response = client.post("/incident/confirm", json={"case_id": case_id})
    assert response.status_code == 200, response.text
    incident_id = response.json()["incident_id"]
    original = client.get("/incidents").json()["incidents"][0]
    signature = original["signature"]
    store.reset()
    assert state.load_incidents_into_memory() == 1
    restored = client.get("/incidents").json()["incidents"][0]
    for field in ("source_case", "wallet", "simulated", "confirmed_by", "signature"):
        assert restored[field] == original[field]
    assert restored["incident_id"] == incident_id
    assert restored["simulated"] is True
    assert restored["wallet"] in store.flagged_wallets
    assert store.threat_store.find_max_similarity(signature)[0] > 0.99
    assert state.load_incidents_into_memory() == 0
    assert client.get("/incidents").json()["count"] == 1


def test_legacy_incident_schema_is_migrated_without_data_loss(tmp_path, monkeypatch):
    legacy = create_engine("sqlite:///" + str(tmp_path / "legacy.db"))
    with legacy.begin() as connection:
        connection.execute(text("CREATE TABLE incidents (incident_id VARCHAR PRIMARY KEY, vector JSON NOT NULL, "
                                "category VARCHAR, disposition VARCHAR, evidence_hash VARCHAR, "
                                "confirmed_by VARCHAR, confirmed_at DATETIME)"))
        connection.execute(text("INSERT INTO incidents (incident_id, vector, disposition) "
                                "VALUES ('legacy', '[1,0,0,0,0,0,0,0]', 'CONFIRMED_INCIDENT')"))
    monkeypatch.setattr(state, "engine", legacy)
    state.init_db()
    state.init_db()  # migration is idempotent
    assert "source" in {c["name"] for c in inspect(legacy).get_columns("incidents")}
    with legacy.connect() as connection:
        row = connection.execute(text("SELECT incident_id, source FROM incidents")).one()
        assert tuple(row) == ("legacy", None)
    legacy.dispose()


def test_concurrent_confirmation_is_idempotent(client, scenarios):
    case_id = create_case(client, scenarios)
    case = store.cases[case_id]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: incidents.remember_incident(case, "CONFIRMED_INCIDENT", "alice"), range(16)))
    assert len({r["incident_id"] for r in results}) == 1
    assert len(store.incident_meta) == 1
    assert len(store.threat_store._stored_incidents) == 1
    with state.SessionLocal() as session:
        assert session.query(state.tm.IncidentModel).count() == 1


def test_failed_incident_write_does_not_claim_success(client, scenarios, monkeypatch):
    case_id = create_case(client, scenarios)
    monkeypatch.setattr(incidents, "db_save_incident", lambda *args, **kwargs: False)
    response = client.post("/incident/confirm", json={"case_id": case_id})
    assert response.status_code == 503
    assert not store.incident_meta and not store.flagged_wallets
    assert "incident_id" not in store.cases[case_id]


def test_reload_skips_invalid_unreviewed_and_incompatible_signatures():
    good = [1.0] * len(MODEL_FEATURES)
    cases = [
        ("nan", [float("nan")] * len(good), "CONFIRMED_INCIDENT", {}),
        ("text", ["bad"] * len(good), "CONFIRMED_INCIDENT", {}),
        ("empty", [0.0] * len(good), "CONFIRMED_INCIDENT", {}),
        ("short", [1.0], "CONFIRMED_INCIDENT", {}),
        ("unreviewed", good, "BENIGN", {}),
        ("version", good, "CONFIRMED_INCIDENT", {"vector_version": "unknown"}),
        ("valid", good, "CONFIRMED_INCIDENT", {}),
    ]
    for key, vector, disposition, source in cases:
        assert state.db_save_incident(key, vector, "UNCLASSIFIED", disposition, "hash", "alice", source)
    assert state.load_incidents_into_memory() == 1
    assert list(store.incident_meta) == ["valid"]
    assert store.incident_meta["valid"]["simulated"] is None


def test_resolved_case_returns_current_customer_state(client, scenarios):
    case_id = create_case(client, scenarios, "B")
    response = client.post(f"/cases/{case_id}/review", json={"disposition": "CUSTOMER_VERIFIED"})
    assert response.status_code == 200
    packet = client.get(f"/cases/{case_id}").json()
    status = client.get(f"/customer/status/{case_id}").json()
    assert packet["case_header"]["decision"] == "RESOLVED"
    assert packet["customer_view"] == status
    assert "RESOLVED" in packet["summary_card"]


def test_no_chain_evidence_does_not_approve_access(client):
    wallet = "0x" + "7" * 40
    response = client.post("/access/request", json={"wallet": wallet})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["decision"] == "REVIEW"
    assert result["access_token"] is None
    assert "CHAIN_DATA_UNAVAILABLE" in result["reason_codes"]
    packet = client.get(f"/cases/{result['request_id']}").json()
    assert packet["timeline"]["data_source"] == "none"
    assert any("Chain evidence unavailable" in note for note in packet["policy_trace"]["guardrails"])


def test_app_counts_normalize_wallet_and_exclude_future_attempts():
    local = Store()
    wallet = "0x" + "a" * 40
    local.record_attempt(AccessAttempt("past", wallet.upper(), "vault", -10, "REVIEW"))
    local.record_attempt(AccessAttempt("future", wallet, "vault", 10, "RESTRICT"))
    local.record_attempt(AccessAttempt("old", wallet, "vault", -4000, "CHALLENGE"))
    assert local.app_counts(wallet, now=0) == (1, 1)
