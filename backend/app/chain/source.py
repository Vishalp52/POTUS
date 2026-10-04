"""Picks the chain-data source for a wallet: demo replay -> Envio -> Monad RPC -> empty."""
from __future__ import annotations

import time
from typing import Optional

from app.api.settings import settings
from app.chain import envio, monad_rpc
from app.chain.demo_replay import build_activity, scenario_for
from app.chain.types import WalletActivity


def get_wallet_activity(wallet: str, demo_scenario: Optional[str] = None, now: Optional[float] = None) -> WalletActivity:
    wallet = wallet.lower()
    scenario = scenario_for(wallet, demo_scenario)
    if scenario is not None or settings.data_source == "demo":
        return build_activity(scenario or scenario_for("", "A"), wallet, now=now)

    if settings.data_source in ("auto", "envio"):
        act = envio.safe_wallet_activity(wallet)
        if act is not None:
            return act
    if settings.data_source in ("auto", "envio", "rpc"):
        act = monad_rpc.safe_wallet_activity(wallet)
        if act is not None:
            return act

    empty = WalletActivity(wallet=wallet, source="none", complete_window=False, window_seconds=0)
    empty.notes.append(f"No chain data source reachable at {time.strftime('%H:%M:%S')}; app signals only")
    return empty
