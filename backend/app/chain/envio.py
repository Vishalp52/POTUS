"""Envio HyperSync adapter (indexed path).

Queries a wallet's incoming + outgoing transactions for the last 24h (and its
first-ever transaction for wallet age) through HyperSync's JSON query API.
Configure with:
    ENVIO_HYPERSYNC_URL   e.g. https://monad-testnet.hypersync.xyz  (check Envio docs for your network)
    ENVIO_API_TOKEN       Envio API token (sent as a Bearer token)
If either the URL is unset or the call fails, the caller falls back to Monad RPC.
"""
from __future__ import annotations

import logging
import math
import time
from typing import Any, Optional

import httpx

from app.api.settings import settings
from app.chain.types import ChainTx, WalletActivity, chain_quantity

log = logging.getLogger("potus.chain.envio")

TX_FIELDS = ["block_number", "hash", "from", "to", "value", "input"]
BLOCK_FIELDS = ["number", "timestamp"]
MAX_PAGES = 20
# An index that is more than a minute behind cannot describe current activity.
MAX_INDEX_LAG_SECONDS = 60


def _int(v: Any) -> int:
    return chain_quantity(v)


class EnvioHyperSync:
    def __init__(self, url: Optional[str] = None, token: Optional[str] = None, timeout: Optional[float] = None):
        self.url = (url if url is not None else settings.envio_hypersync_url).rstrip("/")
        self.token = token if token is not None else settings.envio_api_token
        self.timeout = timeout or settings.chain_timeout_seconds

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json"}
        if self.token:
            h["authorization"] = f"Bearer {self.token}"
        return h

    def height(self) -> int:
        r = httpx.get(f"{self.url}/height", headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return _int(r.json()["height"])

    def query(self, body: dict) -> dict:
        r = httpx.post(f"{self.url}/query", json=body, headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _parse(resp: dict) -> tuple[list[dict], dict[int, int]]:
        txs: list[dict] = []
        ts: dict[int, int] = {}
        data = resp["data"]
        # Current servers return an object; older JSON servers return chunks.
        chunks = [data] if isinstance(data, dict) else data
        if not isinstance(chunks, list):
            raise ValueError("Invalid HyperSync response data")
        for chunk in chunks:
            txs.extend(chunk.get("transactions", []) or [])
            for b in chunk.get("blocks", []) or []:
                ts[_int(b["number"])] = _int(b["timestamp"])
        return txs, ts

    def _pages(self, body: dict):
        """Require a forward cursor and a completed range, including empty pages."""
        body = dict(body)
        if body["from_block"] >= body["to_block"]:
            return
        previous_guard = None
        for _ in range(MAX_PAGES):
            resp = self.query(body)
            nxt = _int(resp["next_block"])
            if nxt <= body["from_block"] or nxt > body["to_block"]:
                raise ValueError("HyperSync returned an invalid pagination cursor")
            guard = resp.get("rollback_guard")
            if (previous_guard and guard
                    and guard.get("first_block_number") == previous_guard.get("block_number", -2) + 1
                    and guard.get("first_parent_hash") != previous_guard.get("hash")):
                raise ValueError("HyperSync chain changed during pagination")
            previous_guard = guard
            yield resp
            if nxt == body["to_block"]:
                return
            body["from_block"] = nxt
        raise ValueError("HyperSync pagination limit reached before completing the range")

    def block_timestamp(self, number: int) -> int:
        resp = self.query({
            "from_block": number,
            "to_block": number + 1,
            "include_all_blocks": True,
            "field_selection": {"block": BLOCK_FIELDS},
        })
        _, timestamps = self._parse(resp)
        if number not in timestamps:
            raise ValueError("HyperSync did not return the requested block timestamp")
        return timestamps[number]

    def wallet_transactions(self, wallet: str, from_block: int, to_block: int) -> list[ChainTx]:
        wallet = wallet.lower()
        body = {
            "from_block": from_block,
            "to_block": to_block,
            "transactions": [{"from": [wallet]}, {"to": [wallet]}],
            "field_selection": {"transaction": TX_FIELDS, "block": BLOCK_FIELDS},
        }
        out: dict[str, ChainTx] = {}
        for resp in self._pages(body):
            raw, ts = self._parse(resp)
            for t in raw:
                bn = _int(t["block_number"])
                if not from_block <= bn < to_block or bn not in ts:
                    raise ValueError("HyperSync transaction has no valid block timestamp")
                to = t.get("to")
                inp = t.get("input") or "0x"
                sender = str(t["from"]).lower()
                recipient = str(to).lower() if to else None
                if not t.get("hash") or not sender or wallet not in (sender, recipient):
                    raise ValueError("HyperSync returned an invalid wallet transaction")
                tx = ChainTx(
                    hash=str(t["hash"]).lower(),
                    block_number=bn,
                    timestamp=ts[bn],
                    from_addr=sender,
                    to_addr=recipient,
                    value_wei=_int(t["value"]),
                    is_contract_call=inp not in ("0x", ""),
                )
                out[tx.hash] = tx
        return sorted(out.values(), key=lambda t: (t.block_number, t.hash))

    def first_seen_block(self, wallet: str, to_block: int) -> Optional[int]:
        body = {
            "from_block": 0,
            "to_block": to_block,
            "transactions": [{"from": [wallet.lower()]}, {"to": [wallet.lower()]}],
            "field_selection": {"transaction": ["block_number"]},
            "max_num_transactions": 1,
        }
        for resp in self._pages(body):
            raw, _ = self._parse(resp)
            if raw:
                first = min(_int(t["block_number"]) for t in raw)
                if not 0 <= first < to_block:
                    raise ValueError("HyperSync returned an invalid first activity block")
                return first
        return None

    def wallet_activity(self, wallet: str, window_seconds: int = 24 * 3600,
                        now: Optional[float] = None) -> WalletActivity:
        if window_seconds <= 0:
            raise ValueError("History window must be positive")
        now = time.time() if now is None else now
        cutoff = now - window_seconds
        latest = self.height()
        latest_timestamp = self.block_timestamp(latest)
        if latest_timestamp > now + MAX_INDEX_LAG_SECONDS:
            raise ValueError("HyperSync head timestamp is in the future")
        span = max(1, math.ceil(window_seconds / max(settings.monad_block_time_seconds, 0.05)))
        start = max(0, latest - span)
        # Block time is an estimate, not evidence of 24h coverage. Expand until
        # an actual block predates the cutoff (or the scan reaches genesis).
        while start > 0 and self.block_timestamp(start) >= cutoff:
            span *= 2
            start = max(0, latest - span)
        txs = [t for t in self.wallet_transactions(wallet, start, latest + 1)
               if cutoff <= t.timestamp <= now]
        first = None
        notes = []
        try:
            first = self.first_seen_block(wallet, latest + 1)
        except Exception as exc:
            log.debug("first_seen lookup failed: %s", exc)
            notes.append("Earliest wallet activity could not be established; wallet age is unknown")
        complete = now - latest_timestamp <= MAX_INDEX_LAG_SECONDS
        if not complete:
            notes.append("Envio index is behind the current time; recent activity may be missing")
        act = WalletActivity(wallet=wallet.lower(), source="envio", txs=txs, latest_block=latest,
                             first_seen_block=first, window_seconds=window_seconds,
                             complete_window=complete, notes=notes)
        act.notes.append(f"Envio HyperSync blocks {start}-{latest}: {len(txs)} txs")
        return act


def safe_wallet_activity(wallet: str, now: Optional[float] = None) -> Optional[WalletActivity]:
    client = EnvioHyperSync()
    if not client.enabled:
        return None
    try:
        return client.wallet_activity(wallet, now=now)
    except Exception as exc:
        log.warning("Envio HyperSync unavailable, falling back: %s", exc)
        return None
