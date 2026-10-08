"""Explicit connection helper and CLI; importing this module never contacts RPC."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

BACKEND_DIR = Path(__file__).resolve().parent


def connect_monad(rpc_url: str | None = None, timeout: float = 30) -> Web3:
    load_dotenv(BACKEND_DIR / ".env")
    load_dotenv(BACKEND_DIR.parent / ".env")
    url = rpc_url or os.getenv("MONAD_RPC_URL")
    if not url:
        raise ValueError("MONAD_RPC_URL is missing from .env")
    if timeout <= 0:
        raise ValueError("RPC timeout must be positive")
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout}))
    if not w3.is_connected():
        raise ConnectionError("Could not connect to Monad RPC")
    return w3


def main() -> None:
    w3 = connect_monad()
    print("Connected to Monad!")
    print("Chain ID:", w3.eth.chain_id)
    print("Latest block:", w3.eth.block_number)


if __name__ == "__main__":
    main()
