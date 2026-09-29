import os

from dotenv import load_dotenv
from web3 import Web3


load_dotenv()

RPC_URL = os.getenv("MONAD_RPC_URL")

w3 = Web3(
    Web3.HTTPProvider(RPC_URL)
)


latest_block_number = w3.eth.block_number

block = w3.eth.get_block(
    latest_block_number,
    full_transactions=True
)


print("Block number:", block["number"])
print("Timestamp:", block["timestamp"])
print("Transactions:", len(block["transactions"]))


if len(block["transactions"]) > 0:

    tx = block["transactions"][0]

    print()
    print("Example transaction:")
    print("Hash:", tx["hash"].hex())
    print("From:", tx["from"])
    print("To:", tx["to"])
    print("Value:", w3.from_wei(tx["value"], "ether"))