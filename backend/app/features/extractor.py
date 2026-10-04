"""Behavioral feature extraction (spec §5).

Turns normalized chain activity (RPC / Envio / demo replay) plus POTUS
application history into a normalized feature vector, human-readable deltas,
and hard flags.
"""
from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from app.chain.types import ChainTx, WalletActivity
from app.features.baselines import (
    BASELINE_FLOORS, PopulationStats, deviation_signature, ratio, wallet_baseline,
)
from app.features.schemas import (
    DEFAULT_SENSITIVITY, RESOURCE_SENSITIVITY, BehaviorFeatures, FeatureBundle,
)

TEN_MIN = 600
ONE_HOUR = 3600
ONE_DAY = 86400
COLD_START_BLOCKS = 1000
ZSCORE_CAP = 10.0
WEI_PER_MON = 10 ** 18


@dataclass
class AppHistory:
    """POTUS application-side signals for one wallet."""
    access_requests_10m: int = 0
    failed_access_count: int = 0          # denied/challenged/held attempts in the last hour
    flagged_counterparties: set[str] = field(default_factory=set)


def _log_mon(wei: int) -> float:
    return math.log10(max(wei, 1) / WEI_PER_MON + 1e-9)


def _value_zscore(recent: list[ChainTx], prior: list[ChainTx]) -> tuple[float, Optional[str]]:
    recent_vals = [_log_mon(t.value_wei) for t in recent if t.value_wei > 0]
    prior_vals = [_log_mon(t.value_wei) for t in prior if t.value_wei > 0]
    if not recent_vals:
        return 0.0, None
    if len(prior_vals) < 3:
        return 0.0, "transfer_value_zscore: not enough prior transfers for a baseline"
    mu = statistics.fmean(prior_vals)
    sd = max(statistics.pstdev(prior_vals), 0.25)   # floor avoids blow-ups on identical values
    z = (max(recent_vals) - mu) / sd
    return round(max(-ZSCORE_CAP, min(ZSCORE_CAP, z)), 3), None


def _contracts(txs: Iterable[ChainTx]) -> set[str]:
    return {t.to_addr for t in txs if t.is_contract_call and t.to_addr}


def extract_features(
    activity: WalletActivity,
    resource_id: str,
    app: AppHistory,
    population: PopulationStats,
    now: Optional[float] = None,
) -> FeatureBundle:
    now = now or time.time()
    wallet = activity.wallet.lower()
    notes = list(activity.notes)

    # If the data source has no usable timestamps (e.g. partial RPC scan), anchor to newest tx.
    out_txs = sorted(activity.outgoing, key=lambda t: t.timestamp)
    all_txs = sorted(activity.txs, key=lambda t: t.timestamp)

    in_10m = [t for t in out_txs if now - t.timestamp <= TEN_MIN]
    in_1h = [t for t in out_txs if now - t.timestamp <= ONE_HOUR]
    in_24h = [t for t in out_txs if now - t.timestamp <= ONE_DAY]
    prior = [t for t in in_24h if now - t.timestamp > ONE_HOUR]

    recent_contracts = _contracts(in_1h)
    prior_contracts = _contracts(prior)
    new_contracts = recent_contracts - prior_contracts
    new_ratio = round(len(new_contracts) / len(recent_contracts), 3) if recent_contracts else 0.0

    z, z_note = _value_zscore(in_1h, prior)
    if z_note:
        notes.append(z_note)

    counterparties = {t.to_addr for t in all_txs if t.from_addr == wallet and t.to_addr} | \
                     {t.from_addr for t in all_txs if t.to_addr == wallet}
    flagged = len(counterparties & {a.lower() for a in app.flagged_counterparties})

    age: Optional[int] = None
    if activity.first_seen_block is not None and activity.latest_block:
        age = max(0, activity.latest_block - activity.first_seen_block)

    features = BehaviorFeatures(
        wallet_age_blocks=age,
        tx_count_10m=len(in_10m),
        tx_count_1h=len(in_1h),
        unique_contracts_24h=len(_contracts(in_24h)),
        new_contract_ratio=new_ratio,
        transfer_value_zscore=z,
        access_requests_10m=app.access_requests_10m,
        failed_access_count=app.failed_access_count,
        flagged_counterparty_count=flagged,
        resource_sensitivity=RESOURCE_SENSITIVITY.get(resource_id, DEFAULT_SENSITIVITY),
    )

    # ---- baselines: wallet's own earlier 23h when available, else population ----
    covered = min(activity.window_seconds, ONE_DAY)
    prior_seconds = max(0.0, covered - ONE_HOUR) if activity.complete_window else 0.0
    pop = population.median
    baselines = {
        "tx_count_10m": wallet_baseline(len(prior), prior_seconds, TEN_MIN, pop["tx_count_10m"], BASELINE_FLOORS["tx_count_10m"]),
        "tx_count_1h": wallet_baseline(len(prior), prior_seconds, ONE_HOUR, pop["tx_count_1h"], BASELINE_FLOORS["tx_count_1h"]),
        "unique_contracts_24h": max(BASELINE_FLOORS["unique_contracts_24h"], pop["unique_contracts_24h"]),
        "new_contract_ratio": max(BASELINE_FLOORS["new_contract_ratio"], pop["new_contract_ratio"]),
        "access_requests_10m": max(BASELINE_FLOORS["access_requests_10m"], pop["access_requests_10m"]),
    }
    baselines = {k: round(v, 3) for k, v in baselines.items()}

    deltas: dict = {}
    for key in ("tx_count_10m", "tx_count_1h", "unique_contracts_24h", "new_contract_ratio", "access_requests_10m"):
        val = float(getattr(features, key))
        deltas[key] = {"value": val, "baseline": baselines[key], "ratio": ratio(val, baselines[key])}
    deltas["transfer_value_zscore"] = features.transfer_value_zscore
    deltas["failed_access_count"] = features.failed_access_count
    deltas["flagged_counterparty_count"] = features.flagged_counterparty_count

    hard_flags: list[str] = []
    if deltas["tx_count_10m"]["ratio"] >= 5 or features.access_requests_10m >= 20:
        hard_flags.append("ACCESS_BURST")
    if features.transfer_value_zscore >= 3:
        hard_flags.append("VALUE_OUTLIER")
    if features.new_contract_ratio >= 0.5 and len(recent_contracts) >= 3:
        hard_flags.append("NEW_CONTRACT_SPIKE")
    if features.failed_access_count >= 3:
        hard_flags.append("REPEATED_DENIALS")
    if features.flagged_counterparty_count > 0:
        hard_flags.append("FLAGGED_COUNTERPARTY")

    cold = (age is not None and age < COLD_START_BLOCKS) or (activity.nonce == 0 and not out_txs)
    if cold:
        hard_flags.append("COLD_START_WALLET")
    low_conf = cold or not activity.complete_window or activity.source == "none"
    if not activity.complete_window:
        notes.append("Partial history window: baselines fall back to population values")

    vector = features.model_vector()
    return FeatureBundle(
        wallet=wallet,
        resource_id=resource_id,
        features=features,
        feature_deltas=deltas,
        baselines=baselines,
        hard_flags=hard_flags,
        data_source=activity.source,
        simulated=activity.simulated,
        history_confidence="low" if low_conf else "normal",
        notes=notes,
        vector=vector,
        signature=deviation_signature(population, vector),
    )
