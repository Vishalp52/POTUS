"""Generate the reproducible, explicitly synthetic normal-wallet population."""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

NUM_WALLETS = 1000
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "normal_wallets.csv"


def generate_normal_wallets(count: int = NUM_WALLETS, seed: int = 42) -> pd.DataFrame:
    if count < 2:
        raise ValueError("At least two normal-wallet samples are required")
    # A local generator preserves the existing fixture without changing callers' RNG state.
    rng = np.random.RandomState(seed)
    return pd.DataFrame({
        "tx_10m": rng.poisson(2, count),
        "tx_1h": rng.poisson(8, count),
        "unique_contracts_24h": rng.poisson(4, count),
        "access_requests_10m": rng.poisson(1, count),
        "failed_requests_1h": rng.poisson(0.2, count),
        "new_contract_ratio": rng.beta(2, 8, count),
        "avg_transfer_value": rng.lognormal(2, 0.5, count),
        "flagged_counterparties": rng.binomial(1, 0.02, count),
    })


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_FILE)
    args = parser.parse_args(argv)
    frame = generate_normal_wallets()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, index=False)
    print(f"Generated synthetic normal-wallet training data: {args.output}")
    print(frame.head())


if __name__ == "__main__":
    main()
