"""PotusRegistry writer (spec §9): publish the MINIMAL on-chain record
(score, expiry, decision, evidence hash). Full evidence stays off-chain.

Skipped (status "skipped") unless POTUS_REGISTRY_ADDRESS and ORACLE_PRIVATE_KEY are set.
Decision encoding (must match the contract owner's enum):
    0 = ALLOW, 1 = CHALLENGE, 2 = REVIEW, 3 = RESTRICT
"""
from __future__ import annotations

import logging
from typing import Any

from app.api.settings import settings

log = logging.getLogger("potus.chain.registry")

DECISION_CODES = {"ALLOW": 0, "CHALLENGE": 1, "REVIEW": 2, "RESTRICT": 3}

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
    h = hex_hash[2:] if hex_hash.startswith("0x") else hex_hash
    return bytes.fromhex(h.rjust(64, "0")[:64])


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
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(settings.monad_rpc_url, request_kwargs={"timeout": settings.chain_timeout_seconds}))
            acct = w3.eth.account.from_key(self.key)
            c = w3.eth.contract(address=Web3.to_checksum_address(self.address), abi=REGISTRY_ABI)
            fn = c.functions.updateRisk(Web3.to_checksum_address(wallet), max(0, min(255, int(score))),
                                        int(expires_at), to_bytes32(evidence_hash), DECISION_CODES[decision])
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
