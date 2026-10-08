"""Deterministic demo scenarios (spec §13). Clearly labeled SIMULATED data.

Each scenario generates the same activity pattern every time (seeded RNG,
timestamps relative to the request time), so the judge demo never depends on
live-chain randomness. Scenario data can be attached to a fixed demo wallet or
replayed onto any connected wallet via `demo_scenario` on /access/request.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Optional

from app.chain.types import ChainTx, WalletActivity

WEI = 10 ** 18

# Familiar contracts every "normal" history interacts with
FAMILIAR = [
    "0x00000000000000000000000000000000c0ffee01",
    "0x00000000000000000000000000000000c0ffee02",
    "0x00000000000000000000000000000000c0ffee03",
]
# Simulated "previously flagged" counterparties (seeded into the flagged set on reset)
FLAGGED_COUNTERPARTIES = [
    "0x000000000000000000000000000000000bad0001",
    "0x000000000000000000000000000000000bad0002",
    "0x000000000000000000000000000000000bad0003",
]


@dataclass(frozen=True)
class Scenario:
    key: str
    name: str
    wallet: str
    description: str
    expected: str
    seed_access_requests_10m: int = 0
    seed_failed_access: int = 0
    ai_outage: bool = False


SCENARIOS: dict[str, Scenario] = {s.key: s for s in [
    Scenario("A", "Normal wallet", "0x000000000000000000000000000000000000a00a",
             "Low request rate, familiar contracts, stable transfer values", "ALLOW"),
    Scenario("B", "Slight anomaly", "0x000000000000000000000000000000000000b00b",
             "Short burst after a long quiet period; no value outlier; no pattern match", "ALLOW or CHALLENGE",
             seed_access_requests_10m=5, seed_failed_access=1),
    Scenario("C", "Account-takeover style", "0x000000000000000000000000000000000000c00c",
             "Large request burst + new contracts + failed access + value outlier", "REVIEW / RESTRICT",
             seed_access_requests_10m=44, seed_failed_access=6),
    Scenario("D", "Potential illicit typology", "0x000000000000000000000000000000000000d00d",
             "Multiple high-risk indicators incl. flagged counterparties + value outlier", "REVIEW / RESTRICT",
             seed_access_requests_10m=8, seed_failed_access=2),
    Scenario("E", "Pattern recurrence", "0x000000000000000000000000000000000000e00e",
             "Second wallet resembling the confirmed scenario-C signature (milder burst)",
             "Earlier escalation once scenario C is confirmed", seed_access_requests_10m=24, seed_failed_access=3),
    Scenario("F", "Gemini unavailable", "0x000000000000000000000000000000000000f00f",
             "Fraud-like activity while the AI layer is down", "Deterministic fallback decision",
             seed_access_requests_10m=30, seed_failed_access=4, ai_outage=True),
]}

WALLET_TO_SCENARIO = {s.wallet: s.key for s in SCENARIOS.values()}


def scenario_for(wallet: str, override: Optional[str] = None) -> Optional[Scenario]:
    if override:
        return SCENARIOS.get(override.upper())
    key = WALLET_TO_SCENARIO.get(wallet.lower())
    return SCENARIOS.get(key) if key else None


def _addr(rng: random.Random, prefix: str = "") -> str:
    return "0x" + prefix + "".join(rng.choice("0123456789abcdef") for _ in range(40 - len(prefix)))


def _mk(rng, wallet, ts, to, value_mon, call=True, latest=10_000_000, now=0.0) -> ChainTx:
    block = latest - int((now - ts) / 0.4)
    return ChainTx(hash=_addr(rng), block_number=block, timestamp=int(ts), from_addr=wallet,
                   to_addr=to, value_wei=int(value_mon * WEI), is_contract_call=call)


def _normal_history(rng, wallet, now, latest, n=36, start=3 * 3600, end=24 * 3600):
    """Steady history: n txs spread over [now-end, now-start] to familiar contracts, ~1 MON values."""
    txs = []
    for i in range(n):
        ts = now - start - (end - start) * (i + rng.random()) / n
        txs.append(_mk(rng, wallet, ts, rng.choice(FAMILIAR), max(0.05, rng.gauss(1.0, 0.25)), latest=latest, now=now))
    return txs


def build_activity(scenario: Scenario, wallet: str, now: Optional[float] = None, latest_block: int = 10_000_000) -> WalletActivity:
    now = now or time.time()
    wallet = wallet.lower()
    rng = random.Random(f"potus-demo-{scenario.key}")
    txs: list[ChainTx] = []
    k = scenario.key

    if k == "A":
        txs += _normal_history(rng, wallet, now, latest_block, n=40, start=20 * 60)
        txs.append(_mk(rng, wallet, now - 25 * 60, FAMILIAR[0], 1.1, latest=latest_block, now=now))
        txs.append(_mk(rng, wallet, now - 4 * 60, FAMILIAR[1], 0.9, latest=latest_block, now=now))
    elif k == "B":
        # active long ago, quiet for ~20h, then a short ordinary burst
        txs += _normal_history(rng, wallet, now, latest_block, n=12, start=20 * 3600, end=24 * 3600)
        for i in range(8):
            value = 2.3 if i == 0 else max(0.05, rng.gauss(1.0, 0.2))   # slightly larger, not an outlier
            txs.append(_mk(rng, wallet, now - 30 - i * 65, FAMILIAR[i % 3], value, latest=latest_block, now=now))
    elif k in ("C", "E", "F"):
        txs += _normal_history(rng, wallet, now, latest_block, n=36)
        burst = {"C": 38, "E": 20, "F": 32}[k]
        new_contracts = [_addr(rng, "dead") for _ in range({"C": 12, "E": 7, "F": 10}[k])]
        for i in range(burst):
            txs.append(_mk(rng, wallet, now - 15 - i * (540 / burst), new_contracts[i % len(new_contracts)],
                           max(0.05, rng.gauss(1.0, 0.3)), latest=latest_block, now=now))
        if k != "E":  # E: same takeover shape but no value outlier -> needs threat memory to escalate
            big = {"C": 60.0, "F": 45.0}[k]
            txs.append(_mk(rng, wallet, now - 90, _addr(rng, "beef"), big, call=False, latest=latest_block, now=now))
    elif k == "D":
        txs += _normal_history(rng, wallet, now, latest_block, n=30)
        new_contracts = [_addr(rng, "dead") for _ in range(5)]
        for i in range(12):
            txs.append(_mk(rng, wallet, now - 20 - i * 45, new_contracts[i % 5], max(0.05, rng.gauss(1.0, 0.3)), latest=latest_block, now=now))
        for i, bad in enumerate(FLAGGED_COUNTERPARTIES[:2]):
            txs.append(_mk(rng, wallet, now - 60 - i * 30, bad, 25.0 + 10 * i, call=False, latest=latest_block, now=now))

    act = WalletActivity(
        wallet=wallet, source="demo", txs=sorted(txs, key=lambda t: t.timestamp),
        latest_block=latest_block, first_seen_block=latest_block - 2_500_000,
        nonce=sum(1 for t in txs if t.from_addr == wallet), window_seconds=24 * 3600, complete_window=True,
        simulated=True,
    )
    act.notes.append(f"SIMULATED demo scenario {scenario.key} ({scenario.name})")
    return act
