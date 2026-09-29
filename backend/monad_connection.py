import os

from dotenv import load_dotenv
from web3 import Web3


# Load variables from .env
load_dotenv()

RPC_URL = os.getenv("MONAD_RPC_URL")

if not RPC_URL:
    raise ValueError("MONAD_RPC_URL is missing from .env")


# Connect to Monad
w3 = Web3(
    Web3.HTTPProvider(
        RPC_URL,
        request_kwargs={"timeout": 30}
    )
)

print("Connecting to Monad...")


if not w3.is_connected():
    raise ConnectionError("Could not connect to Monad RPC")


print("Connected to Monad!")
print("Chain ID:", w3.eth.chain_id)
print("Latest block:", w3.eth.block_number)