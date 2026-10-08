"""Regression coverage for observed features, training inputs and collection CLIs."""
import importlib
import math
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from pydantic import ValidationError

from app.chain.types import ChainTx, WalletActivity
from app.features.baselines import PopulationStats
from app.features.extractor import AppHistory, extract_features
from app.features.schemas import BehaviorFeatures
from app.models import model_store
from app.models.isolation_forest import AnomalyDetector, load_training_frame, synthetic_normal

WALLET = "0x" + "a" * 40
BAD = "0x" + "b" * 40


def transaction(timestamp, *, destination=BAD):
    return ChainTx(hash=f"0x{timestamp}", block_number=1, timestamp=timestamp,
                   from_addr=WALLET, to_addr=destination, value_wei=10**18, is_contract_call=True)


def test_features_only_include_observed_day_and_ignore_future_activity():
    now = 100_000
    activity = WalletActivity(wallet=WALLET, source="test", txs=[
        transaction(now + 1), transaction(now - 86401),
        transaction(now - 86400, destination="0x" + "c" * 40),
        transaction(now - 600, destination="0x" + "d" * 40),
        transaction(now - 3600, destination="0x" + "e" * 40),
    ], first_seen_block=0, latest_block=2000)
    bundle = extract_features(activity, "research-vault", AppHistory(flagged_counterparties={BAD}),
                              PopulationStats(), now=now)
    assert bundle.features.tx_count_10m == 1
    assert bundle.features.tx_count_1h == 2
    assert bundle.features.unique_contracts_24h == 3
    assert bundle.features.flagged_counterparty_count == 0
    assert "FLAGGED_COUNTERPARTY" not in bundle.hard_flags


def test_features_respect_epoch_snapshot_and_genesis_age():
    activity = WalletActivity(wallet=WALLET, source="test", txs=[transaction(0), transaction(1)],
                              first_seen_block=0, latest_block=0)
    bundle = extract_features(activity, "research-vault", AppHistory(), PopulationStats(), now=0)
    assert bundle.features.tx_count_10m == 1
    assert bundle.features.wallet_age_blocks == 0
    assert "COLD_START_WALLET" in bundle.hard_flags


def test_unknown_wallet_age_has_low_history_confidence():
    activity = WalletActivity(wallet=WALLET, source="test", nonce=50)
    bundle = extract_features(activity, "research-vault", AppHistory(), PopulationStats(), now=100_000)
    assert bundle.features.wallet_age_blocks is None
    assert bundle.history_confidence == "low"
    assert "COLD_START_WALLET" not in bundle.hard_flags


@pytest.mark.parametrize("invalid", [
    {"tx_count_10m": -1}, {"wallet_age_blocks": -1}, {"failed_access_count": -1},
    {"new_contract_ratio": 1.01}, {"pattern_similarity": -0.01}, {"resource_sensitivity": 2},
    {"transfer_value_zscore": math.nan}, {"transfer_value_zscore": math.inf},
    {"session_geo_velocity": -1}, {"unrecognized_signal": 10},
    {"tx_count_10m": 10**100}, {"transfer_value_zscore": 1e308},
])
def test_raw_features_reject_invalid_values(invalid):
    with pytest.raises(ValidationError):
        BehaviorFeatures(**invalid)


@pytest.mark.parametrize("invalid", [
    {"tx_count_10m": -1}, {"new_contract_ratio": 2}, {"unknown": 1},
    {"tx_count_10m": 10**100}, {"transfer_value_zscore": 1e308},
])
def test_score_returns_validation_error_for_invalid_nested_features(client, invalid):
    response = client.post("/score", json={"features": invalid})
    assert response.status_code == 422


def test_canonical_training_csv_preserves_transfer_zscores(tmp_path):
    original = synthetic_normal(30)
    path = tmp_path / "normal.csv"
    original.to_csv(path, index=False)
    loaded, source = load_training_frame(path)
    assert source == "csv:normal.csv"
    np.testing.assert_allclose(loaded.to_numpy(), original.to_numpy())


@pytest.mark.parametrize("corruption", ["empty", "one_row", "nan", "negative_count", "invalid_ratio", "text"])
def test_invalid_training_csv_uses_finite_fallback(tmp_path, corruption):
    frame = synthetic_normal(5)
    if corruption == "empty":
        frame = frame.iloc[:0]
    elif corruption == "one_row":
        frame = frame.iloc[:1]
    elif corruption == "nan":
        frame.loc[0, "transfer_value_zscore"] = np.nan
    elif corruption == "negative_count":
        frame.loc[0, "tx_count_10m"] = -1
    elif corruption == "invalid_ratio":
        frame.loc[0, "new_contract_ratio"] = 1.1
    else:
        frame["tx_count_10m"] = "bad"
    path = tmp_path / "normal.csv"
    frame.to_csv(path, index=False)
    loaded, source = load_training_frame(path)
    assert source == "synthetic"
    assert len(loaded) == 1000
    assert np.isfinite(loaded.to_numpy()).all()


def test_model_store_does_not_reuse_a_different_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(model_store, "_detector", None)
    monkeypatch.setattr(model_store, "_detector_path", None)
    first = AnomalyDetector().fit(synthetic_normal(30), "first", model_store.training_fingerprint())
    second = AnomalyDetector().fit(synthetic_normal(30, seed=7), "second", model_store.training_fingerprint())
    first_path, second_path = tmp_path / "first.joblib", tmp_path / "second.joblib"
    joblib.dump(first, first_path)
    joblib.dump(second, second_path)
    loaded_first = model_store.load_detector(str(first_path))
    assert model_store.load_detector(str(first_path)) is loaded_first
    assert model_store.load_detector(str(second_path)).trained_on == "second"


def test_untrained_model_artifact_is_rebuilt(tmp_path, monkeypatch):
    monkeypatch.setattr(model_store, "_detector", None)
    monkeypatch.setattr(model_store, "_detector_path", None)
    path = tmp_path / "untrained.joblib"
    joblib.dump(AnomalyDetector(), path)
    replacement = AnomalyDetector().fit(synthetic_normal(30))
    calls = []
    monkeypatch.setattr(model_store, "train_and_save", lambda path: calls.append(path) or replacement)
    assert model_store.load_detector(str(path)) is replacement
    assert calls == [str(path)]


class CollectorEth:
    block_number = 3

    def __init__(self):
        self.requested = []

    def get_block(self, number, full_transactions):
        self.requested.append(number)
        return {"timestamp": number * 600, "transactions": ([
            {"from": WALLET, "to": BAD, "value": 2 * 10**18, "input": b""},
        ] if number == 3 else [])}


def test_collector_exact_block_span_and_observation_rate():
    from collect_monad_data import collect_activity
    from types import SimpleNamespace

    eth = CollectorEth()
    result = collect_activity(SimpleNamespace(eth=eth), blocks_to_scan=2)
    assert eth.requested == [2, 3]
    assert result.loc[0, "tx_count"] == 1
    assert result.loc[0, "tx_rate_per_minute"] == pytest.approx(0.1)
    assert result.loc[0, "avg_value_mon"] == 2
    assert result.loc[0, "contract_call_ratio"] == 0


def test_collector_scan_includes_genesis_without_negative_blocks():
    from collect_monad_data import collect_activity
    from types import SimpleNamespace

    eth = CollectorEth()
    collect_activity(SimpleNamespace(eth=eth), blocks_to_scan=20)
    assert eth.requested == [0, 1, 2, 3]
    with pytest.raises(ValueError):
        collect_activity(SimpleNamespace(eth=eth), blocks_to_scan=0)


def test_collector_short_windows_are_not_rounded_up_to_a_minute():
    from collect_monad_data import collect_activity
    from types import SimpleNamespace

    eth = CollectorEth()
    get_block = eth.get_block
    def short_block(number, full_transactions):
        block = get_block(number, full_transactions)
        block["timestamp"] = number * 2
        return block
    eth.get_block = short_block
    frame = collect_activity(SimpleNamespace(eth=eth), blocks_to_scan=2)
    assert frame.loc[0, "tx_rate_per_minute"] == 30
    assert frame.loc[0, "observation_seconds"] == 2
    assert not frame.loc[0, "complete_24h_window"]
    single = collect_activity(SimpleNamespace(eth=eth), blocks_to_scan=1)
    assert pd.isna(single.loc[0, "tx_rate_per_minute"])
    assert single.loc[0, "observation_seconds"] == 0


def test_legacy_scripts_are_import_safe_and_paths_are_repo_relative(tmp_path, monkeypatch):
    from web3 import Web3

    monkeypatch.chdir(tmp_path)
    def unexpected_provider(*args, **kwargs):
        raise AssertionError("Import must not create a network provider")
    monkeypatch.setattr(Web3, "HTTPProvider", unexpected_provider)
    for name in ("monad_connection", "collect_monad_data", "generate_data", "test_block"):
        module = importlib.import_module(name)
        importlib.reload(module)
    assert not list(tmp_path.iterdir())
    import collect_monad_data
    import generate_data
    root = Path(__file__).resolve().parents[2]
    assert collect_monad_data.OUTPUT_FILE == root / "data" / "real" / "monad_wallet_activity.csv"
    assert generate_data.OUTPUT_FILE == root / "normal_wallets.csv"
    pd.testing.assert_frame_equal(generate_data.generate_normal_wallets(), pd.read_csv(root / "normal_wallets.csv"))
