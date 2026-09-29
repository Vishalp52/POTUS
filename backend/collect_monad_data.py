import os
from collections import defaultdict

import pandas as pd

from dotenv import load_dotenv
from web3 import Web3


load_dotenv()

RPC_URL = os.getenv("MONAD_RPC_URL")

if not RPC_URL:
    raise ValueError("MONAD_RPC_URL missing from .env")


w3 = Web3(
    Web3.HTTPProvider(
        RPC_URL,
        request_kwargs={"timeout": 30}
    )
)


if not w3.is_connected():
    raise ConnectionError("Could not connect to Monad")


print("Connected to Monad")
print("Chain ID:", w3.eth.chain_id)


# Keep this SMALL at first.
BLOCKS_TO_SCAN = 20

latest_block = w3.eth.block_number

start_block = max(
    0,
    latest_block - BLOCKS_TO_SCAN
)


print(
    f"Scanning blocks {start_block} to {latest_block}"
)


wallets = defaultdict(
    lambda: {
        "tx_count": 0,
        "destinations": set(),
        "total_value_wei": 0,
        "contract_calls": 0,
        "first_timestamp": None,
        "last_timestamp": None,
    }
)


for block_number in range(
    start_block,
    latest_block + 1
):

    print(
        f"Scanning {block_number}/{latest_block}",
        end="\r"
    )

    block = w3.eth.get_block(
        block_number,
        full_transactions=True
    )

    timestamp = int(block["timestamp"])

    for tx in block["transactions"]:

        sender = tx.get("from")

        if not sender:
            continue

        sender = sender.lower()

        data = wallets[sender]

        data["tx_count"] += 1

        # Transaction value
        value = int(tx["value"])

        data["total_value_wei"] += value


        # Destination
        destination = tx.get("to")

        if destination:

            data["destinations"].add(
                destination.lower()
            )


        # Contract-call-like transaction
        input_data = tx.get("input")

        if input_data not in (
            None,
            "0x",
            b"",
        ):
            data["contract_calls"] += 1


        # First timestamp
        if data["first_timestamp"] is None:
            data["first_timestamp"] = timestamp

        data["first_timestamp"] = min(
            data["first_timestamp"],
            timestamp
        )


        # Last timestamp
        if data["last_timestamp"] is None:
            data["last_timestamp"] = timestamp

        data["last_timestamp"] = max(
            data["last_timestamp"],
            timestamp
        )


print()
print("Finished scanning.")


rows = []


for wallet, data in wallets.items():

    tx_count = data["tx_count"]

    total_value_mon = float(
        w3.from_wei(
            data["total_value_wei"],
            "ether"
        )
    )


    avg_value_mon = (
        total_value_mon / tx_count
        if tx_count
        else 0
    )


    seconds_active = (
        data["last_timestamp"]
        - data["first_timestamp"]
    )


    minutes_active = max(
        seconds_active / 60,
        1
    )


    tx_rate_per_minute = (
        tx_count / minutes_active
    )


    contract_call_ratio = (
        data["contract_calls"] / tx_count
        if tx_count
        else 0
    )


    rows.append(
        {
            "wallet": wallet,
            "tx_count": tx_count,
            "unique_destinations": len(
                data["destinations"]
            ),
            "total_value_mon": total_value_mon,
            "avg_value_mon": avg_value_mon,
            "tx_rate_per_minute": tx_rate_per_minute,
            "contract_call_ratio": contract_call_ratio,
        }
    )


df = pd.DataFrame(rows)


if df.empty:
    raise RuntimeError(
        "No transactions found in scanned blocks"
    )


df = df.sort_values(
    "tx_count",
    ascending=False
)


os.makedirs(
    "data/real",
    exist_ok=True
)


OUTPUT_FILE = (
    "data/real/monad_wallet_activity.csv"
)


df.to_csv(
    OUTPUT_FILE,
    index=False
)


print(
    f"Collected {len(df)} wallets"
)

print(
    f"Saved to {OUTPUT_FILE}"
)

print()

print(df.head(10))