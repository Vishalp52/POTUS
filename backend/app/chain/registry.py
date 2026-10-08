"""PotusRegistry writer (spec §9): publish the MINIMAL on-chain record
(score, expiry, decision, evidence hash). Full evidence stays off-chain.

Skipped (status "skipped") unless POTUS_REGISTRY_ADDRESS and ORACLE_PRIVATE_KEY are set.
Decision encoding (must match the contract owner's enum):
    0 = ALLOW, 1 = CHALLENGE, 2 = REVIEW, 3 = RESTRICT
"""
from __future__ import annotations

import logging
import re
import threading
from typing import Any

from app.api.settings import settings

log = logging.getLogger("potus.chain.registry")

DECISION_CODES = {"ALLOW": 0, "CHALLENGE": 1, "REVIEW": 2, "RESTRICT": 3}
# All evaluations share the configured oracle account. Protect its pending nonce
# until submission succeeds, including when more than one writer is instantiated.
_SUBMISSION_LOCK = threading.Lock()

REGISTRY_ABI = [
    {"type": "function", "name": "updateRisk", "stateMutability": "nonpayable", "outputs": [], "inputs": [
        {"name": "wallet", "type": "address"}, {"name": "score", "type": "uint8"},
        {"name": "expiresAt", "type": "uint64"}, {"name": "evidenceHash", "type": "bytes32"},
        {"name": "decision", "type": "uint8"}]},
    {"type": "function", "name": "isAllowed", "stateMutability": "view",
     "inputs": [{"name": "wallet", "type": "address"}], "outputs": [{"name": "", "type": "bool"}]},
    {"type": "function", "name": "getRisk", "stateMutability": "view",
     "inputs": [{"name": "wallet", "type": "address"}],
     "outputs": [{"name": "", "type": "tuple", "components": [
         {"name": "score", "type": "uint8"}, {"name": "expiresAt", "type": "uint64"},
         {"name": "evidenceHash", "type": "bytes32"}, {"name": "decision", "type": "uint8"}]}]},
]


def to_bytes32(hex_hash: str) -> bytes:
    if not isinstance(hex_hash, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", hex_hash):
        raise ValueError("evidence hash must contain exactly 32 bytes of hexadecimal data")
    h = hex_hash[2:] if hex_hash.startswith("0x") else hex_hash
    return bytes.fromhex(h)


class RegistryWriter:
    def __init__(self):
        self.address = settings.potus_registry_address
        self.key = settings.oracle_private_key

    @property
    def enabled(self) -> bool:
        return bool(self.address and self.key)

    def publish_minimal_record(self, wallet: str, score: int, expires_at: int, evidence_hash: str, decision: str) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "skipped", "reason": "POTUS_REGISTRY_ADDRESS / ORACLE_PRIVATE_KEY not configured"}
        try:
            digest = to_bytes32(evidence_hash)
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(settings.monad_rpc_url, request_kwargs={"timeout": settings.chain_timeout_seconds}))
            acct = w3.eth.account.from_key(self.key)
            c = w3.eth.contract(address=Web3.to_checksum_address(self.address), abi=REGISTRY_ABI)
            fn = c.functions.updateRisk(Web3.to_checksum_address(wallet), max(0, min(255, int(score))),
                                        int(expires_at), digest, DECISION_CODES[decision])
            with _SUBMISSION_LOCK:
                tx = fn.build_transaction({
                    "from": acct.address,
                    "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
                    "chainId": w3.eth.chain_id,
                })
                signed = acct.sign_transaction(tx)
                raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
                tx_hash = w3.eth.send_raw_transaction(raw)
            h = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
            return {"status": "submitted", "tx_hash": h if h.startswith("0x") else "0x" + h}
        except Exception as exc:
            log.warning("registry write failed: %s", exc)
            return {"status": "failed", "error": str(exc)[:300]}
