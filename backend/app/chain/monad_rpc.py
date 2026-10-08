"""Monad JSON-RPC adapter (web3.py).

Plain JSON-RPC has no "transactions by address" index, so this adapter scans a
bounded window of recent blocks (RPC_SCAN_BLOCKS) and reads nonce/latest block.
It is the first-48-hours data path from the spec; Envio (envio.py) is the
indexed path for longer windows. Everything degrades gracefully on RPC errors.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from web3 import Web3

from app.api.settings import settings
from app.chain.types import ChainTx, WalletActivity, chain_quantity

log = logging.getLogger("potus.chain.rpc")

def _hex(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    h = v.hex() if hasattr(v, "hex") and not isinstance(v, str) else str(v)
    return h if h.startswith("0x") else "0x" + h


def _has_calldata(inp) -> bool:
    if inp in (None, "", "0x", b""):
        return False
    if isinstance(inp, (bytes, bytearray)):
        return len(inp) > 0
    return str(inp) not in ("0x", "")


class MonadRPC:
    def __init__(self, rpc_url: Optional[str] = None, timeout: Optional[float] = None):
        self.rpc_url = rpc_url or settings.monad_rpc_url
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": timeout or settings.chain_timeout_seconds}))

    # ---- basic reads -------------------------------------------------
    def is_connected(self) -> bool:
        try:
            return bool(self.w3.is_connected())
        except Exception:
            return False

    def latest_block(self) -> int:
        return int(self.w3.eth.block_number)

    def chain_id(self) -> int:
        return int(self.w3.eth.chain_id)

    def nonce(self, wallet: str) -> int:
        return int(self.w3.eth.get_transaction_count(Web3.to_checksum_address(wallet)))

    def is_contract(self, address: str) -> bool:
        try:
            return len(self.w3.eth.get_code(Web3.to_checksum_address(address))) > 0
        except Exception:
            return False

    # ---- block scanning ---------------------------------------------
    def _fetch_block(self, number: int) -> tuple[int, list[ChainTx]]:
        # Read the canonical block on every scan. A cache keyed only by number
        # can leak data between endpoints and retain blocks replaced by a reorg.
        block = self.w3.eth.get_block(number, full_transactions=True)
        ts = chain_quantity(block["timestamp"])
        txs: list[ChainTx] = []
        for tx in block["transactions"]:
            sender = tx["from"].lower()
            if not sender or not tx.get("hash"):
                raise ValueError("RPC returned an incomplete transaction")
            to = tx.get("to")
            txs.append(ChainTx(
                hash=_hex(tx.get("hash")),
                block_number=number,
                timestamp=ts,
                from_addr=sender,
                to_addr=to.lower() if to else None,
                value_wei=chain_quantity(tx["value"]),
                is_contract_call=_has_calldata(tx.get("input")),
            ))
        return ts, txs

    def recent_blocks(self, count: int, latest: Optional[int] = None) -> list[tuple[int, int, list[ChainTx]]]:
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError("The RPC scan must contain at least one block")
        latest = self.latest_block() if latest is None else latest
        start = max(0, latest - count + 1)
        numbers = list(range(start, latest + 1))
        out: list[tuple[int, int, list[ChainTx]]] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            for n, res in zip(numbers, pool.map(self._safe_fetch, numbers)):
                if res is not None:
                    out.append((n, res[0], res[1]))
        return out

    def _safe_fetch(self, n: int):
        try:
            return self._fetch_block(n)
        except Exception as exc:  # one bad block shouldn't kill the scan
            log.debug("block %s fetch failed: %s", n, exc)
            return None

    # ---- main entry --------------------------------------------------
    def wallet_activity(self, wallet: str, scan_blocks: Optional[int] = None) -> WalletActivity:
        wallet = wallet.lower()
        scan_blocks = settings.rpc_scan_blocks if scan_blocks is None else scan_blocks
        t0 = time.time()
        latest = self.latest_block()
        nonce = None
        try:
            nonce = self.nonce(wallet)
        except Exception as exc:
            log.debug("nonce lookup failed: %s", exc)

        blocks = self.recent_blocks(scan_blocks, latest)
        if not blocks:
            raise RuntimeError("RPC did not return any requested blocks")
        txs = [t for _, _, btxs in blocks for t in btxs if t.from_addr == wallet or t.to_addr == wallet]
        window = max(0, blocks[-1][1] - blocks[0][1])

        act = WalletActivity(
            wallet=wallet, source="rpc", txs=txs, latest_block=latest, nonce=nonce,
            window_seconds=window,
            complete_window=False,
        )
        act.notes.append(f"RPC scanned {len(blocks)} recent blocks in {time.time() - t0:.1f}s; "
                         "longer windows require the Envio indexed path")
        missing = min(scan_blocks, latest + 1) - len(blocks)
        if missing:
            act.notes.append(f"RPC failed to retrieve {missing} requested blocks; activity is incomplete")
        # A zero nonce proves no outgoing transactions, not when an address was
        # first funded. Keep wallet age unknown on this bounded, unindexed path.
        return act


def safe_wallet_activity(wallet: str) -> Optional[WalletActivity]:
    try:
        rpc = MonadRPC()
        return rpc.wallet_activity(wallet)
    except Exception as exc:
        log.warning("Monad RPC unavailable: %s", exc)
        return None
