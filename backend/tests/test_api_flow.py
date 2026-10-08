"""End-to-end API tests covering spec §14 'What to test'."""
import json

from eth_account import Account
from eth_account.messages import encode_defunct

from app.api import engine


def req(client, wallet, **kw):
    r = client.post("/access/request", json={"wallet": wallet, **kw})
    assert r.status_code == 200, r.text
    return r.json()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}
    h = client.get("/health/details").json()
    assert h["model"]["model"] == "IsolationForest"


def test_response_contract(client, scenarios):
    r = req(client, scenarios["C"]["wallet"])
    for k in ("request_id", "wallet", "resource_id", "risk_score", "decision", "expires_at", "signals", "reason_codes", "customer", "evidence_hash"):
        assert k in r
    assert set(r["signals"]) >= {"anomaly_score", "rule_score", "pattern_similarity", "gemini", "gemini_status"}
    assert r["evidence_hash"].startswith("0x") and len(r["evidence_hash"]) == 66


def test_scenario_decisions(client, scenarios):
    assert req(client, scenarios["A"]["wallet"])["decision"] == "ALLOW"
    assert req(client, scenarios["B"]["wallet"])["decision"] in ("ALLOW", "CHALLENGE")
    assert req(client, scenarios["C"]["wallet"])["decision"] in ("REVIEW", "RESTRICT")
    assert req(client, scenarios["D"]["wallet"])["decision"] in ("REVIEW", "RESTRICT")


def test_gemini_outage_still_decides(client, scenarios):
    r = req(client, scenarios["F"]["wallet"])
    assert r["signals"]["gemini"] is None
    assert r["signals"]["gemini_status"] == "unavailable"
    assert r["decision"] in ("REVIEW", "RESTRICT")
    r2 = req(client, scenarios["C"]["wallet"], simulate_ai_outage=True)
    assert r2["signals"]["gemini_status"] == "unavailable"


def test_threat_memory_raises_recurrence(client, scenarios):
    before = req(client, scenarios["E"]["wallet"])
    c = req(client, scenarios["C"]["wallet"])
    out = client.post(f"/cases/{c['request_id']}/review", json={"disposition": "CONFIRMED_INCIDENT"}).json()
    assert out["incident"]["incident_id"]
    client.post("/demo/reset")  # clear access history but threat memory is also cleared -> re-confirm
    c = req(client, scenarios["C"]["wallet"])
    client.post("/incident/confirm", json={"case_id": c["request_id"]})
    after = req(client, scenarios["E"]["wallet"])
    assert after["signals"]["pattern_similarity"] > 0.6
    assert after["risk_score"] > before["risk_score"]
    assert "KNOWN_PATTERN_SIMILARITY" in after["reason_codes"]


def test_threat_memory_poisoning_blocked(client, scenarios):
    c = req(client, scenarios["C"]["wallet"])
    client.post(f"/cases/{c['request_id']}/review", json={"disposition": "BENIGN"})
    assert client.get("/incidents").json()["count"] == 0
    a = req(client, scenarios["A"]["wallet"])
    r = client.post("/incident/confirm", json={"case_id": a["request_id"]})
    assert r.status_code == 409  # normal behavior has no abnormal signature to store


def test_customer_payload_has_no_leakage(client, scenarios):
    c = req(client, scenarios["C"]["wallet"])
    client.post("/incident/confirm", json={"case_id": c["request_id"]})
    r = req(client, scenarios["E"]["wallet"])
    for payload in (r["customer"], client.get(f"/customer/status/{r['request_id']}").json()):
        blob = json.dumps(payload).lower()
        for banned in ("inc_", "fraud", "illicit", "threshold", "weight", "anomaly", "similarity", "gemini", "0.", "flag"):
            assert banned not in blob, banned
        assert set(payload) == {"request_id", "decision", "status", "title", "message", "next_action", "support_code"}


def bearer(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_vault_gating(client, scenarios):
    a = req(client, scenarios["A"]["wallet"])
    assert a["access_token"]
    ok = client.get("/vault/research-vault", headers=bearer(a["access_token"]))
    assert ok.status_code == 200 and ok.json()["data"]["records"]
    c = req(client, scenarios["C"]["wallet"])
    assert c["access_token"] is None
    assert client.get("/vault/research-vault").status_code == 401


def sign(acct, msg):
    sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
    return sig if sig.startswith("0x") else "0x" + sig


def test_challenge_signature_flow(client):
    acct = Account.create()
    r = req(client, acct.address, demo_scenario="B")
    assert r["decision"] == "CHALLENGE", r
    ch = client.get(f"/access/{r['request_id']}/challenge").json()
    bad = sign(Account.create(), ch["message"])
    assert client.post(f"/access/{r['request_id']}/verify", json={"nonce": ch["nonce"], "signature": bad}).status_code == 401
    # nonce was consumed by the failed attempt -> must fetch a fresh challenge
    ch = client.get(f"/access/{r['request_id']}/challenge").json()
    good = {"nonce": ch["nonce"], "signature": sign(acct, ch["message"])}
    v = client.post(f"/access/{r['request_id']}/verify", json=good)
    assert v.status_code == 200 and v.json()["decision"] == "RESOLVED"
    assert client.post(f"/access/{r['request_id']}/verify", json=good).status_code == 409  # no replay
    vault = client.get("/vault/research-vault", headers=bearer(v.json()["access_token"]))
    assert vault.status_code == 200


def test_employee_case_packet(client, scenarios):
    c = req(client, scenarios["C"]["wallet"])
    p = client.get(f"/cases/{c['request_id']}").json()
    for k in ("case_header", "risk_summary", "behavior_deltas", "gemini_triage", "threat_memory", "timeline", "policy_trace", "actions", "audit"):
        assert k in p
    assert p["summary_card"].startswith(f"CASE {c['request_id']}")
    zs = [abs(d["population_z"]) for d in p["behavior_deltas"]]
    assert zs == sorted(zs, reverse=True)  # strongest deviations first
    assert client.get("/cases").json()["cases"][0]["case_id"] == c["request_id"]


def test_score_endpoint_is_side_effect_free(client, scenarios):
    s = client.post("/score", json={"wallet": scenarios["C"]["wallet"]}).json()
    assert s["decision"] in ("REVIEW", "RESTRICT")
    assert client.get("/cases").json()["cases"] == []
    raw = client.post("/score", json={"features": {"tx_count_10m": 1, "tx_count_1h": 6, "unique_contracts_24h": 3}}).json()
    assert raw["decision"] == "ALLOW"


def test_policy_determinism(client, scenarios):
    a = client.post("/score", json={"wallet": scenarios["D"]["wallet"]}).json()
    b = client.post("/score", json={"wallet": scenarios["D"]["wallet"]}).json()
    assert (a["risk_score"], a["decision"], a["reason_codes"]) == (b["risk_score"], b["decision"], b["reason_codes"])


def test_low_confidence_high_severity_routes_to_review(client):
    """Spec §14 unit-test example, through the live components."""
    import asyncio
    from app.api import teammate as tm
    c = engine.components()
    triage = tm.GeminiTriage(category="POTENTIAL_ILLICIT_ACTIVITY", confidence=0.51, semantic_risk=90,
                             supporting_indicators=["synthetic typology match"], benign_explanations=["limited history"],
                             employee_summary="ambiguous", customer_reason_code="SECURITY_REVIEW", requires_human_review=True)
    risk, reasons, forced = c.fusion.compute_fused_risk(anomaly_score=0.95, rule_score=0.8, pattern_similarity=0.9,
                                                       gemini_triage=triage, rule_reasons=[tm.ReasonCode.ACCESS_BURST])
    assert c.policy.evaluate(risk, reasons, forced)["decision"] == "REVIEW"


def test_wallet_routes(client, scenarios):
    w = scenarios["C"]["wallet"]
    f = client.get(f"/wallet/{w}/features").json()
    assert f["simulated"] and "ACCESS_BURST" in f["hard_flags"]
    assert client.get(f"/wallet/{w}/risk").json()["state"] == "NO_EVALUATION"
    req(client, w)
    assert client.get(f"/wallet/{w}/risk").json()["decision"] in ("REVIEW", "RESTRICT")
    assert client.get("/wallet/not-an-address/risk").status_code == 422
