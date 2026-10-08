"""Regression coverage for wallet proofs, production demo guards and registry writes."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from app.api.security import NonceStore
from app.api.settings import settings
from app.chain.registry import RegistryWriter, to_bytes32


@pytest.fixture
def override_settings():
    saved = {}

    def change(name, value):
        saved.setdefault(name, getattr(settings, name))
        object.__setattr__(settings, name, value)

    yield change
    for name, value in saved.items():
        object.__setattr__(settings, name, value)


def _signature(account, message):
    return "0x" + account.sign_message(encode_defunct(text=message)).signature.hex().removeprefix("0x")


def test_challenge_signature_cannot_authorize_a_new_access_request(client):
    account = Account.create()
    evaluation = client.post("/access/request", json={"wallet": account.address, "demo_scenario": "B"})
    assert evaluation.status_code == 200
    assert evaluation.json()["decision"] == "CHALLENGE"
    request_id = evaluation.json()["request_id"]
    challenge = client.get(f"/access/{request_id}/challenge").json()

    response = client.post("/access/request", json={
        "wallet": account.address, "demo_scenario": "A", "resource_id": "other-vault",
        "nonce": challenge["nonce"], "signature": _signature(account, challenge["message"]),
    })
    assert response.status_code == 401
    assert len(client.get("/cases").json()["cases"]) == 1

    # Even a failed cross-purpose attempt consumes its nonce.
    replay = client.post(f"/access/{request_id}/verify", json={
        "nonce": challenge["nonce"], "signature": _signature(account, challenge["message"]),
    })
    assert replay.status_code == 401


def test_nonce_requires_exact_request_purpose_and_is_single_use():
    nonces = NonceStore()
    wallet = "0x" + "a" * 40
    purpose = "step-up verification for req_123_extra"
    nonce, _, _ = nonces.issue(wallet, purpose)
    assert nonces.consume(nonce, wallet, "step-up verification for req_123") is None
    assert nonces.consume(nonce, wallet, purpose) is None
    nonce, message, _ = nonces.issue(wallet, purpose)
    assert nonces.consume(nonce, wallet.upper(), purpose) == message
    assert nonces.consume(nonce, wallet, purpose) is None


@pytest.mark.parametrize("method,path,body", [
    ("get", "/wallet/0x" + "a" * 40 + "/features?demo_scenario=A", None),
    ("get", "/wallet/0x000000000000000000000000000000000000c00c/features", None),
    ("post", "/score", {"wallet": "0x" + "a" * 40, "demo_scenario": "A"}),
    ("post", "/score", {"wallet": "0x000000000000000000000000000000000000c00c"}),
    ("post", "/score", {"features": {}, "demo_scenario": "A"}),
    ("post", "/score", {"features": {}, "simulate_ai_outage": True}),
])
def test_demo_disabled_on_employee_scoring_routes(client, override_settings, method, path, body):
    override_settings("enable_demo_env", "false")
    response = getattr(client, method)(path, **({"json": body} if body is not None else {}))
    assert response.status_code == 403


def test_demo_data_source_disabled_across_evaluation_routes(client, override_settings):
    override_settings("enable_demo_env", "false")
    override_settings("data_source", "demo")
    wallet = "0x" + "a" * 40
    assert client.get(f"/wallet/{wallet}/features").status_code == 403
    assert client.post("/score", json={"wallet": wallet}).status_code == 403
    assert client.post("/access/request", json={"wallet": wallet}).status_code == 403


def test_confirmed_incident_is_not_an_active_wallet_grant(client, scenarios):
    wallet = scenarios["C"]["wallet"]
    evaluation = client.post("/access/request", json={"wallet": wallet}).json()
    assert client.get(f"/wallet/{wallet}/risk").json()["active"] is True
    response = client.post("/incident/confirm", json={"case_id": evaluation["request_id"]})
    assert response.status_code == 200
    assert client.get(f"/wallet/{wallet}/risk").json()["active"] is False


@pytest.mark.parametrize("invalid", ["", "0x", "ab", "0x" + "ab" * 31, "0x" + "ab" * 33, "gg" * 32, "ab " * 32])
def test_registry_rejects_incomplete_or_malformed_evidence_hashes(invalid):
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        to_bytes32(invalid)


def test_registry_preserves_exact_evidence_digest():
    digest = "00" + "Ab" * 31
    assert to_bytes32(digest) == to_bytes32("0x" + digest) == bytes.fromhex(digest)


def test_concurrent_registry_writers_use_distinct_pending_nonces(monkeypatch):
    import web3

    nonces = []
    submitted_records = []
    start = threading.Barrier(4)

    class FakeEth:
        chain_id = 143

        def __init__(self):
            signer = SimpleNamespace(address="oracle", sign_transaction=lambda tx: SimpleNamespace(raw_transaction=tx))
            self.account = SimpleNamespace(from_key=lambda _: signer)

        def contract(self, **kwargs):
            def update_risk(*record):
                def build_transaction(tx):
                    return {**tx, "record": record}
                return SimpleNamespace(build_transaction=build_transaction)
            return SimpleNamespace(functions=SimpleNamespace(updateRisk=update_risk))

        def get_transaction_count(self, address, block):
            assert address == "oracle" and block == "pending"
            nonce = len(nonces)
            # Model the RPC round trip: without serialization every worker can
            # read the same pending nonce before any transaction is submitted.
            time.sleep(0.02)
            return nonce

        def send_raw_transaction(self, tx):
            nonces.append(tx["nonce"])
            submitted_records.append(tx["record"])
            return bytes([tx["nonce"] + 1]) * 32

    eth = FakeEth()

    class FakeWeb3:
        HTTPProvider = staticmethod(lambda *args, **kwargs: object())
        to_checksum_address = staticmethod(lambda address: address)

        def __init__(self, provider):
            self.eth = eth

    monkeypatch.setattr(web3, "Web3", FakeWeb3)
    wallet = "0x" + "a" * 40
    digest = "0x" + "bc" * 32

    def publish(_):
        writer = RegistryWriter()
        writer.address, writer.key = "registry", "test-key"
        start.wait(timeout=5)
        return writer.publish_minimal_record(wallet, 80, 1_900_000_000, digest, "RESTRICT")

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(publish, range(4)))

    assert all(result["status"] == "submitted" for result in results)
    assert nonces == [0, 1, 2, 3]
    assert all(record == (wallet, 80, 1_900_000_000, bytes.fromhex(digest[2:]), 3) for record in submitted_records)
    assert len({result["tx_hash"] for result in results}) == 4


def test_risk_modules_import_without_api_compatibility_bootstrap():
    result = subprocess.run(
        [sys.executable, "-c", (
            "from app.risk.reason_codes import ReasonCode; "
            "from app.risk.reasons_codes import ReasonCode as Legacy; "
            "from app.risk.policy import PolicyEngine; "
            "from app.risk.fusion import RiskFusionEngine; "
            "assert ReasonCode is Legacy; "
            "assert PolicyEngine().evaluate(80, [ReasonCode.ACCESS_BURST])['decision'] == 'RESTRICT'"
        )],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
