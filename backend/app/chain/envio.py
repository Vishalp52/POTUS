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
from typing import Any, Optional

import httpx

from app.api.settings import settings
from app.chain.types import ChainTx, WalletActivity

log = logging.getLogger("potus.chain.envio")

TX_FIELDS = ["block_number", "hash", "from", "to", "value", "input"]
BLOCK_FIELDS = ["number", "timestamp"]
MAX_PAGES = 20


def _int(v: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    s = str(v)
    return int(s, 16) if s.startswith("0x") else int(s or 0)


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
        for chunk in resp.get("data", []) or []:
            txs.extend(chunk.get("transactions", []) or [])
            for b in chunk.get("blocks", []) or []:
                ts[_int(b.get("number"))] = _int(b.get("timestamp"))
        return txs, ts

    def wallet_transactions(self, wallet: str, from_block: int, to_block: int) -> list[ChainTx]:
        wallet = wallet.lower()
        body = {
            "from_block": from_block,
            "to_block": to_block,
            "transactions": [{"from": [wallet]}, {"to": [wallet]}],
            "field_selection": {"transaction": TX_FIELDS, "block": BLOCK_FIELDS},
        }
        out: dict[str, ChainTx] = {}
        for _ in range(MAX_PAGES):
            resp = self.query(body)
            raw, ts = self._parse(resp)
            for t in raw:
                bn = _int(t.get("block_number"))
                to = t.get("to")
                inp = t.get("input") or "0x"
                tx = ChainTx(
                    hash=str(t.get("hash", "")),
                    block_number=bn,
                    timestamp=ts.get(bn, 0),
                    from_addr=str(t.get("from", "")).lower(),
                    to_addr=str(to).lower() if to else None,
                    value_wei=_int(t.get("value")),
                    is_contract_call=inp not in ("0x", ""),
                )
                out[tx.hash or f"{bn}:{len(out)}"] = tx
            nxt = _int(resp.get("next_block"))
            if not nxt or nxt >= to_block:
                break
            body["from_block"] = nxt
        return sorted(out.values(), key=lambda t: (t.block_number, t.hash))

    def first_seen_block(self, wallet: str, to_block: int) -> Optional[int]:
        body = {
            "from_block": 0,
            "to_block": to_block,
            "transactions": [{"from": [wallet.lower()]}],
            "field_selection": {"transaction": ["block_number"]},
            "max_num_transactions": 1,
        }
        raw, _ = self._parse(self.query(body))
        return _int(raw[0]["block_number"]) if raw else None

    def wallet_activity(self, wallet: str, window_seconds: int = 24 * 3600) -> WalletActivity:
        latest = self.height()
        span = int(window_seconds / max(settings.monad_block_time_seconds, 0.05))
        start = max(0, latest - span)
        txs = self.wallet_transactions(wallet, start, latest + 1)
        first = None
        try:
            first = self.first_seen_block(wallet, latest + 1)
        except Exception as exc:
            log.debug("first_seen lookup failed: %s", exc)
        act = WalletActivity(wallet=wallet.lower(), source="envio", txs=txs, latest_block=latest,
                             first_seen_block=first, window_seconds=window_seconds, complete_window=True)
        act.notes.append(f"Envio HyperSync blocks {start}-{latest}: {len(txs)} txs")
        return act


def safe_wallet_activity(wallet: str) -> Optional[WalletActivity]:
    client = EnvioHyperSync()
    if not client.enabled:
        return None
    try:
        return client.wallet_activity(wallet)
    except Exception as exc:
        log.warning("Envio HyperSync unavailable, falling back: %s", exc)
        return None
