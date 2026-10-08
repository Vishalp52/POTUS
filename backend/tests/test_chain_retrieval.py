"""Chain-adapter regressions. All providers are mocked; no live network calls."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.chain import envio, monad_rpc, source
from app.chain.demo_replay import SCENARIOS
from app.chain.envio import EnvioHyperSync
from app.chain.monad_rpc import MonadRPC
from app.chain.types import ChainTx, WalletActivity, chain_quantity

W = "0x00000000000000000000000000000000000000aa"
OTHER = "0x" + "b" * 40


def raw_tx(number=1, tx_hash="0x01", **overrides):
    return {"block_number": number, "hash": tx_hash, "from": W, "to": OTHER,
            "value": "0xde0b6b3a7640001", "input": "0x", **overrides}


def page(next_block, transactions=(), blocks=()):
    return {"next_block": next_block,
            "data": {"transactions": list(transactions), "blocks": list(blocks)}}


@pytest.mark.parametrize("value", [None, True, False, -1, "-1", "", "0x", 0.5, "NaN"])
def test_quantities_reject_missing_negative_or_fractional_values(value):
    with pytest.raises((ValueError, TypeError)):
        chain_quantity(value)


def test_quantities_and_address_normalization_preserve_precision():
    assert chain_quantity("0XDE0B6B3A7640001") == 10**18 + 1
    transaction = ChainTx("0x1", 1, 1, W.upper(), OTHER.upper(), 10**18 + 1, False)
    activity = WalletActivity(W.upper(), "test", [transaction])
    assert activity.wallet == W and activity.outgoing == [transaction]
    assert transaction.to_addr == OTHER


def test_envio_object_response_empty_pages_and_duplicate_self_transfers(monkeypatch):
    client = EnvioHyperSync(url="https://unused")
    transaction = raw_tx(3, to=W.upper())
    responses = iter([
        page(2),
        page(4, [transaction, transaction], [{"number": 3, "timestamp": "0x64"}]),
    ])
    calls = []

    def query(body):
        calls.append(dict(body))
        return next(responses)

    monkeypatch.setattr(client, "query", query)
    transactions = client.wallet_transactions(W, 0, 4)
    assert [body["from_block"] for body in calls] == [0, 2]
    assert len(transactions) == 1
    assert transactions[0].timestamp == 100 and transactions[0].value_wei == 10**18 + 1


@pytest.mark.parametrize("cursor", [None, 0, -1, 4])
def test_envio_invalid_or_missing_cursor_is_not_a_complete_window(monkeypatch, cursor):
    client = EnvioHyperSync(url="https://unused")
    response = page(cursor)
    if cursor is None:
        del response["next_block"]
    monkeypatch.setattr(client, "query", lambda body: response)
    with pytest.raises((KeyError, ValueError)):
        client.wallet_transactions(W, 0, 3)


def test_envio_page_limit_does_not_silently_return_partial_history(monkeypatch):
    client = EnvioHyperSync(url="https://unused")
    monkeypatch.setattr(envio, "MAX_PAGES", 2)
    monkeypatch.setattr(client, "query", lambda body: page(body["from_block"] + 1))
    with pytest.raises(ValueError, match="pagination limit"):
        client.wallet_transactions(W, 0, 10)


def test_envio_reorg_between_adjacent_pages_is_rejected(monkeypatch):
    client = EnvioHyperSync(url="https://unused")
    first = page(2)
    first["rollback_guard"] = {"block_number": 1, "hash": "0xaaa"}
    second = page(3)
    second["rollback_guard"] = {"first_block_number": 2, "first_parent_hash": "0xbbb"}
    responses = iter([first, second])
    monkeypatch.setattr(client, "query", lambda body: next(responses))
    with pytest.raises(ValueError, match="chain changed"):
        client.wallet_transactions(W, 0, 3)


def test_envio_missing_timestamp_cannot_be_mistaken_for_zero_activity(monkeypatch):
    client = EnvioHyperSync(url="https://unused")
    monkeypatch.setattr(client, "query", lambda body: page(2, [raw_tx()]))
    with pytest.raises(ValueError, match="timestamp"):
        client.wallet_transactions(W, 0, 2)


def test_envio_first_seen_scans_empty_pages_and_incoming_activity(monkeypatch):
    client = EnvioHyperSync(url="https://unused")
    responses = iter([page(3), page(10, [{"block_number": 8}, {"block_number": 5}])])
    calls = []

    def query(body):
        calls.append(dict(body))
        return next(responses)

    monkeypatch.setattr(client, "query", query)
    assert client.first_seen_block(W.upper(), 10) == 5
    assert calls[0]["transactions"] == [{"from": [W]}, {"to": [W]}]
    assert [body["from_block"] for body in calls] == [0, 3]


def test_envio_block_timestamp_queries_empty_blocks(monkeypatch):
    client = EnvioHyperSync(url="https://unused")
    calls = []

    def query(body):
        calls.append(body)
        return page(21, blocks=[{"number": "0x14", "timestamp": "0x1234"}])

    monkeypatch.setattr(client, "query", query)
    assert client.block_timestamp(20) == 0x1234
    assert calls[0]["include_all_blocks"] is True
    assert calls[0]["from_block"] == 20 and calls[0]["to_block"] == 21


def test_envio_uses_timestamps_to_expand_window_and_filters_bounds(monkeypatch):
    client = EnvioHyperSync(url="https://unused")
    monkeypatch.setattr(envio, "settings", replace(envio.settings, monad_block_time_seconds=1.0))
    monkeypatch.setattr(client, "height", lambda: 1000)
    # Actual blocks are twice as fast as configured. A count-only estimate
    # would omit the oldest half of the requested ten-minute history.
    monkeypatch.setattr(client, "block_timestamp", lambda number: 1000 + number / 2)
    calls = []
    transactions = [ChainTx(str(ts), 100, ts, W, OTHER, 1, False)
                    for ts in [1199, 1200, 1499, 1501]]

    def wallet_transactions(wallet, start, end):
        calls.append((start, end))
        return transactions

    monkeypatch.setattr(client, "wallet_transactions", wallet_transactions)
    monkeypatch.setattr(client, "first_seen_block", lambda *args: 5)
    activity = client.wallet_activity(W, window_seconds=300, now=1500)
    assert calls == [(0, 1001)]  # 700 and 400 do not predate the cutoff
    assert [tx.timestamp for tx in activity.txs] == [1200, 1499]
    assert activity.complete_window and activity.window_seconds == 300


def test_envio_stale_index_and_unknown_age_are_explicit(monkeypatch):
    client = EnvioHyperSync(url="https://unused")
    monkeypatch.setattr(client, "height", lambda: 10)
    monkeypatch.setattr(client, "block_timestamp", lambda number: 100)
    monkeypatch.setattr(client, "wallet_transactions", lambda *args: [])

    def failed_age(*args):
        raise TimeoutError()

    monkeypatch.setattr(client, "first_seen_block", failed_age)
    activity = client.wallet_activity(W, now=1000)
    assert not activity.complete_window and activity.first_seen_block is None
    assert any("behind" in note for note in activity.notes)
    assert any("age is unknown" in note for note in activity.notes)


def fake_rpc(monkeypatch, blocks, url="https://unused"):
    rpc = MonadRPC(rpc_url=url)

    def get_block(number, full_transactions=True):
        block = blocks[number]
        if isinstance(block, Exception):
            raise block
        return block

    monkeypatch.setattr(rpc.w3, "eth", SimpleNamespace(
        block_number=max(blocks), get_block=get_block, get_transaction_count=lambda wallet: 0))
    return rpc


def test_rpc_all_block_failures_trigger_unavailable_fallback(monkeypatch):
    rpc = fake_rpc(monkeypatch, {1: TimeoutError(), 2: TimeoutError()})
    monkeypatch.setattr(monad_rpc, "MonadRPC", lambda: rpc)
    assert monad_rpc.safe_wallet_activity(W) is None


def test_rpc_partial_scan_reports_missing_blocks_and_does_not_invent_age(monkeypatch):
    rpc = fake_rpc(monkeypatch, {1: {"timestamp": 100, "transactions": []},
                                 2: TimeoutError(), 3: {"timestamp": 102, "transactions": []}})
    activity = rpc.wallet_activity(W, scan_blocks=3)
    assert not activity.complete_window and activity.window_seconds == 2
    assert activity.first_seen_block is None
    assert any("1 requested blocks" in note for note in activity.notes)


def test_rpc_quantities_and_repeated_reads_do_not_reuse_stale_blocks(monkeypatch):
    transaction = raw_tx()
    blocks = {1: {"timestamp": "0x64", "transactions": [transaction]}}
    rpc = fake_rpc(monkeypatch, blocks)
    first = rpc.wallet_activity(W, scan_blocks=1)
    assert first.txs[0].value_wei == 10**18 + 1
    blocks[1] = {"timestamp": "0x65", "transactions": []}
    assert rpc.wallet_activity(W, scan_blocks=1).txs == []
    # Another provider at the same height must never share the first result.
    other = fake_rpc(monkeypatch, blocks, url="https://another-provider")
    assert other.wallet_activity(W, scan_blocks=1).txs == []


def test_rpc_zero_scan_size_is_rejected(monkeypatch):
    rpc = fake_rpc(monkeypatch, {1: {"timestamp": 1, "transactions": []}})
    with pytest.raises(ValueError, match="at least one block"):
        rpc.wallet_activity(W, scan_blocks=0)


def test_source_passes_evaluation_time_and_falls_back_on_envio_failure(monkeypatch):
    monkeypatch.setattr(source, "settings", replace(source.settings, data_source="auto", enable_demo_env="false"))
    calls = []

    def failed_envio(wallet, now=None):
        calls.append(now)
        return None

    monkeypatch.setattr(envio, "safe_wallet_activity", failed_envio)
    monkeypatch.setattr(monad_rpc, "safe_wallet_activity", lambda wallet: WalletActivity(wallet, "rpc"))
    assert source.get_wallet_activity(W, now=123).source == "rpc"
    assert calls == [123]


def test_source_cannot_use_simulation_when_demo_is_disabled(monkeypatch):
    monkeypatch.setattr(source, "settings", replace(source.settings, data_source="demo", enable_demo_env="false"))
    activity = source.get_wallet_activity(SCENARIOS["A"].wallet, demo_scenario="C")
    assert activity.source == "none" and not activity.simulated and not activity.complete_window


def test_source_falls_back_when_indexed_history_is_stale(monkeypatch):
    monkeypatch.setattr(source, "settings", replace(source.settings, data_source="auto", enable_demo_env="false"))
    monkeypatch.setattr(envio, "safe_wallet_activity", lambda wallet, now=None:
                        WalletActivity(wallet, "envio", complete_window=False))
    monkeypatch.setattr(monad_rpc, "safe_wallet_activity", lambda wallet:
                        WalletActivity(wallet, "rpc", complete_window=False))
    assert source.get_wallet_activity(W).source == "rpc"
    monkeypatch.setattr(monad_rpc, "safe_wallet_activity", lambda wallet: None)
    assert source.get_wallet_activity(W).source == "none"
