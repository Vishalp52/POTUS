"""Customer-safe messaging (spec §11). Never exposes thresholds, weights,
incident IDs, model labels, or counterparty flags."""
from __future__ import annotations

import hashlib

TITLES = {
    "ALLOW": "Access approved",
    "CHALLENGE": "Quick verification needed",
    "REVIEW": "Security review in progress",
    "RESTRICT": "Action temporarily limited",
    "RESOLVED": "Access restored",
}
NEXT_ACTIONS = {
    "ALLOW": "NONE",
    "CHALLENGE": "SIGN_WALLET_CHALLENGE",
    "REVIEW": "WAIT_FOR_REVIEW",
    "RESTRICT": "VERIFY_OR_CONTACT_SUPPORT",
    "RESOLVED": "NONE",
}
STATUS = {
    "ALLOW": "APPROVED",
    "CHALLENGE": "VERIFY_IDENTITY",
    "REVIEW": "SECURITY_REVIEW",
    "RESTRICT": "ACCESS_TEMPORARILY_LIMITED",
    "RESOLVED": "RESOLVED",
}
FALLBACK_MESSAGES = {
    "ALLOW": "Access approved.",
    "CHALLENGE": "We noticed unusual activity. Please complete a quick verification step to continue.",
    "REVIEW": "This action is being reviewed for security. Your account remains available, but this sensitive action is temporarily paused.",
    "RESTRICT": "We detected unusual activity and temporarily limited this action to protect your account. Verify your account or contact support to continue.",
    "RESOLVED": "Verification completed. Your access has been restored.",
}


def support_code(request_id: str) -> str:
    return "SEC-" + hashlib.sha256(request_id.encode()).hexdigest()[:4].upper()


def customer_payload(request_id: str, decision: str, policy_customer: dict | None = None) -> dict:
    """Merge the policy engine's customer message with title / next action / support code."""
    policy_customer = policy_customer or {}
    return {
        "request_id": request_id,
        "decision": decision,
        "status": policy_customer.get("status") or STATUS[decision],
        "title": TITLES[decision],
        "message": policy_customer.get("message") or FALLBACK_MESSAGES[decision],
        "next_action": NEXT_ACTIONS[decision],
        "support_code": support_code(request_id),
    }


def challenge_message(request_id: str, wallet: str) -> str:
    return f"POTUS verification\nRequest: {request_id}\nWallet: {wallet.lower()}\nSign to confirm it's you. This costs no gas."
