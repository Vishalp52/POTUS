"""Normalized chain data shared by the RPC, Envio, and demo-replay adapters."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


def chain_quantity(value) -> int:
    """Parse an EVM quantity without silently coercing missing or fractional data."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("Invalid chain quantity")
    number = int(value, 16 if value.lower().startswith("0x") else 10) if isinstance(value, str) else value
    if number < 0:
        raise ValueError("Negative chain quantity")
    return number


@dataclass(frozen=True)
class ChainTx:
    hash: str
    block_number: int
    timestamp: int            # unix seconds
    from_addr: str            # lowercase 0x...
    to_addr: Optional[str]    # lowercase 0x... (None for contract creation)
    value_wei: int
    is_contract_call: bool    # tx carried calldata

    def __post_init__(self):
        object.__setattr__(self, "from_addr", self.from_addr.lower())
        if self.to_addr is not None:
            object.__setattr__(self, "to_addr", self.to_addr.lower())


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

    def __post_init__(self):
        self.wallet = self.wallet.lower()

    @property
    def outgoing(self) -> list[ChainTx]:
        w = self.wallet.lower()
        return [t for t in self.txs if t.from_addr == w]
