"""Collect a bounded RPC block sample, not a complete 24-hour wallet history."""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import pandas as pd

if __package__:
    from .monad_connection import connect_monad
else:
    from monad_connection import connect_monad

BLOCKS_TO_SCAN = 20
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "data" / "real" / "monad_wallet_activity.csv"


def collect_activity(w3, blocks_to_scan: int = BLOCKS_TO_SCAN) -> pd.DataFrame:
    """Return outgoing-wallet observations from exactly the requested block span.

    Rates use the scanned observation interval rather than each wallet's first
    and last transaction; a quiet wallet must not appear active every minute.
    No output is written until the entire scan has succeeded.
    """
    if isinstance(blocks_to_scan, bool) or not isinstance(blocks_to_scan, int) or blocks_to_scan < 1:
        raise ValueError("blocks_to_scan must be a positive integer")
    latest = int(w3.eth.block_number)
    start = max(0, latest - blocks_to_scan + 1)
    wallets = defaultdict(lambda: {
        "tx_count": 0, "destinations": set(), "total_value_wei": 0, "contract_calls": 0,
    })
    timestamps = []
    for number in range(start, latest + 1):
        block = w3.eth.get_block(number, full_transactions=True)
        timestamps.append(int(block["timestamp"]))
        for tx in block["transactions"]:
            sender = tx.get("from")
            if not sender:
                continue
            data = wallets[sender.lower()]
            data["tx_count"] += 1
            data["total_value_wei"] += int(tx["value"])
            destination = tx.get("to")
            if destination:
                data["destinations"].add(destination.lower())
            if tx.get("input") not in (None, "", "0x", "0X", b""):
                data["contract_calls"] += 1

    if not wallets:
        raise RuntimeError("No transactions found in scanned blocks")
    observation_seconds = max(timestamps) - min(timestamps)
    rows = []
    for wallet, data in wallets.items():
        count = data["tx_count"]
        total = data["total_value_wei"] / 10**18
        rows.append({
            "wallet": wallet,
            "tx_count": count,
            "unique_destinations": len(data["destinations"]),
            "total_value_mon": total,
            "avg_value_mon": total / count,
            "tx_rate_per_minute": count * 60 / observation_seconds if observation_seconds > 0 else None,
            "contract_call_ratio": data["contract_calls"] / count,
            "source": "monad_rpc",
            "first_scanned_block": start,
            "last_scanned_block": latest,
            "scanned_blocks": len(timestamps),
            "observation_seconds": observation_seconds,
            "complete_24h_window": False,
        })
    return pd.DataFrame(rows).sort_values(["tx_count", "wallet"], ascending=[False, True]).reset_index(drop=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blocks", type=int, default=BLOCKS_TO_SCAN)
    parser.add_argument("--output", type=Path, default=OUTPUT_FILE)
    args = parser.parse_args(argv)
    if args.blocks < 1:
        parser.error("--blocks must be positive")
    frame = collect_activity(connect_monad(), args.blocks)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, index=False)
    print(f"Collected {len(frame)} wallets from a partial RPC block sample")
    print(f"Saved to {args.output}")
    print(frame.head(10))


if __name__ == "__main__":
    main()
