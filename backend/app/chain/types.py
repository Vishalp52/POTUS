"""Normalized chain data shared by the RPC, Envio, and demo-replay adapters."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ChainTx:
    hash: str
    block_number: int
    timestamp: int            # unix seconds
    from_addr: str            # lowercase 0x...
    to_addr: Optional[str]    # lowercase 0x... (None for contract creation)
    value_wei: int
    is_contract_call: bool    # tx carried calldata


@dataclass
class WalletActivity:
    wallet: str
    source: str                                  # "envio" | "rpc" | "demo" | "none"
    txs: list[ChainTx] = field(default_factory=list)
    latest_block: int = 0
    first_seen_block: Optional[int] = None       # earliest known activity (wallet age)
    nonce: Optional[int] = None                  # outgoing tx count (RPC)
    window_seconds: int = 24 * 3600              # how much history `txs` covers
    complete_window: bool = True                 # False when only a partial window was scanned
    notes: list[str] = field(default_factory=list)
    simulated: bool = False                      # True for labeled demo/replay data

    @property
    def outgoing(self) -> list[ChainTx]:
        w = self.wallet.lower()
        return [t for t in self.txs if t.from_addr == w]
