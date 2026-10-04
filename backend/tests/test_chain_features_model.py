"""Unit tests for app/chain, app/features, app/models (no network)."""
import time

import pytest

from app.chain import envio as envio_mod
from app.chain.demo_replay import SCENARIOS, build_activity
from app.chain.envio import EnvioHyperSync
from app.chain.monad_rpc import MonadRPC
from app.chain.registry import RegistryWriter, to_bytes32
from app.chain.types import ChainTx, WalletActivity
from app.features.baselines import PopulationStats, deviation_signature
from app.features.extractor import AppHistory, extract_features
from app.features.schemas import MODEL_FEATURES
from app.models.isolation_forest import AnomalyDetector, normalize_anomaly, synthetic_normal
from app.models.model_store import load_detector

W = "0x00000000000000000000000000000000000000aa"


def tx(ts, to="0x00000000000000000000000000000000000000c1", value_mon=1.0, call=True, frm=W):
    return ChainTx(hash=f"0x{ts}", block_number=int(ts), timestamp=int(ts), from_addr=frm, to_addr=to,
                   value_wei=int(value_mon * 10**18), is_contract_call=call)


# ---------------------------------------------------------------- models
def test_detector_repeatable():
    d1 = AnomalyDetector().fit(synthetic_normal())
    d2 = AnomalyDetector().fit(synthetic_normal())
    v = [30, 40, 12, 0.9, 6, 40, 6, 0]
    assert d1.score(v) == d2.score(v)
    assert d1.score(v) > d1.score([2, 8, 4, 0.2, 0, 1, 0, 0])


def test_normalize_anomaly_bounds():
    assert normalize_anomaly(-1, 0, 1) == 0.0
    assert normalize_anomaly(5, 0, 1) == 1.0
    assert normalize_anomaly(0.5, 0, 1) == 0.5


def test_model_store_loads_trained_model():
    d = load_detector()
    assert d.model is not None and set(d.population.median) == set(MODEL_FEATURES)


# ---------------------------------------------------------------- features
def test_extractor_counts_and_deltas():
    now = time.time()
    txs = [tx(now - 3 * 3600 - i * 1800) for i in range(30)]             # steady history
    txs += [tx(now - 30 - i * 20, to=f"0x{'d' * 38}{i:02d}") for i in range(12)]  # burst to new contracts
    txs.append(tx(now - 60, value_mon=80, call=False, to="0x" + "e" * 40))
    act = WalletActivity(wallet=W, source="test", txs=txs, latest_block=10_000, first_seen_block=1, window_seconds=86400)
    b = extract_features(act, "research-vault", AppHistory(access_requests_10m=25, failed_access_count=4), load_detector().population, now=now)
    f = b.features
    assert f.tx_count_10m == 13 and f.new_contract_ratio == 1.0
    assert f.transfer_value_zscore >= 3
    assert {"ACCESS_BURST", "VALUE_OUTLIER", "NEW_CONTRACT_SPIKE", "REPEATED_DENIALS"} <= set(b.hard_flags)
    ev = b.evidence_packet(0.9)
    assert ev["feature_deltas"]["tx_count_10m"]["ratio"] >= 5
    assert ev["failed_access_count"] == 4 and "transfer_value_zscore" in ev


def test_cold_start_and_empty_source():
    act = WalletActivity(wallet=W, source="none", complete_window=False, window_seconds=0, nonce=0)
    b = extract_features(act, "research-vault", AppHistory(access_requests_10m=1), load_detector().population)
    assert "COLD_START_WALLET" in b.hard_flags and b.history_confidence == "low"


def test_flagged_counterparty_counted():
    now = time.time()
    bad = "0x" + "b" * 40
    act = WalletActivity(wallet=W, source="t", txs=[tx(now - 100, to=bad, call=False)], latest_block=1, first_seen_block=0)
    b = extract_features(act, "x", AppHistory(flagged_counterparties={bad}), load_detector().population, now=now)
    assert b.features.flagged_counterparty_count == 1 and "FLAGGED_COUNTERPARTY" in b.hard_flags


def test_signature_zero_for_normal():
    pop = load_detector().population
    assert not any(deviation_signature(pop, [2, 8, 4, 0.2, 0, 1, 0, 0]))
    assert any(deviation_signature(pop, [38, 40, 14, 1.0, 10, 45, 6, 0]))


def test_demo_replay_is_deterministic():
    now = 1_800_000_000
    a = build_activity(SCENARIOS["C"], SCENARIOS["C"].wallet, now=now)
    b = build_activity(SCENARIOS["C"], SCENARIOS["C"].wallet, now=now)
    assert [t.hash for t in a.txs] == [t.hash for t in b.txs] and a.simulated


# ---------------------------------------------------------------- chain adapters
class FakeEth:
    def __init__(self, blocks):
        self.blocks = blocks
        self.block_number = max(blocks)
        self.chain_id = 143

    def get_block(self, n, full_transactions=True):
        return self.blocks[n]

    def get_transaction_count(self, addr):
        return 7


def test_rpc_adapter_scans_blocks(monkeypatch):
    now = int(time.time())
    blocks = {n: {"timestamp": now - (110 - n), "transactions": [
        {"hash": bytes([n]) * 32, "from": W if n % 2 else "0x" + "1" * 40, "to": "0x" + "c" * 40, "value": 10**18, "input": "0xabcdef"}
    ]} for n in range(100, 111)}
    rpc = MonadRPC(rpc_url="http://unused")
    monkeypatch.setattr(rpc.w3, "eth", FakeEth(blocks), raising=False)
    act = rpc.wallet_activity(W, scan_blocks=11)
    assert act.source == "rpc" and act.nonce == 7 and not act.complete_window
    assert len(act.txs) == 5 and all(t.is_contract_call for t in act.txs)


def test_envio_adapter_parses_and_paginates(monkeypatch):
    pages = [
        {"data": [{"transactions": [{"block_number": "0x64", "hash": "0x01", "from": W.upper().replace("0X", "0x"), "to": "0x" + "c" * 40, "value": "0xde0b6b3a7640000", "input": "0x12"}],
                   "blocks": [{"number": "0x64", "timestamp": "0x6553f100"}]}], "next_block": 150},
        {"data": [{"transactions": [{"block_number": 160, "hash": "0x02", "from": "0x" + "1" * 40, "to": W, "value": 0, "input": "0x"}],
                   "blocks": [{"number": 160, "timestamp": 1700000100}]}], "next_block": 201},
    ]
    calls = []

    def fake_query(self, body):
        calls.append(dict(body))
        if body.get("max_num_transactions") == 1:
            return {"data": [{"transactions": [{"block_number": 5}]}]}
        return pages[len([c for c in calls if "max_num_transactions" not in c]) - 1]

    monkeypatch.setattr(EnvioHyperSync, "query", fake_query)
    monkeypatch.setattr(EnvioHyperSync, "height", lambda self: 200)
    act = EnvioHyperSync(url="https://example.hypersync").wallet_activity(W)
    assert act.source == "envio" and act.first_seen_block == 5
    assert len(act.txs) == 2 and act.txs[0].value_wei == 10**18 and act.txs[0].timestamp == 0x6553F100
    assert act.txs[1].is_contract_call is False


def test_envio_disabled_falls_back(monkeypatch):
    monkeypatch.setattr(envio_mod.settings.__class__, "envio_hypersync_url", "", raising=False)
    assert EnvioHyperSync(url="").enabled is False


def test_registry_skipped_without_config():
    r = RegistryWriter()
    assert r.publish_minimal_record(W, 80, 0, "0x" + "a" * 64, "RESTRICT")["status"] == "skipped"
    assert len(to_bytes32("0x" + "ab" * 32)) == 32
