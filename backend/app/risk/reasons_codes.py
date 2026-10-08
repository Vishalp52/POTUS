from enum import Enum

class ReasonCode(str, Enum):
    ACCESS_BURST = "ACCESS_BURST"
    NEW_CONTRACT_SPIKE = "NEW_CONTRACT_SPIKE"
    VALUE_OUTLIER = "VALUE_OUTLIER"
    REPEATED_DENIALS = "REPEATED_DENIALS"
    KNOWN_PATTERN_SIMILARITY = "KNOWN_PATTERN_SIMILARITY"
    GEMINI_FRAUD_LIKE = "GEMINI_FRAUD_LIKE"
    GEMINI_POTENTIAL_ILLICIT = "GEMINI_POTENTIAL_ILLICIT"
    LOW_CONFIDENCE_REVIEW = "LOW_CONFIDENCE_REVIEW"
    COLD_START_WALLET = "COLD_START_WALLET"
    # Extension to the spec §7 vocabulary: chain evidence could not be retrieved,
    # so the request is held for review instead of looking like a clean wallet.
    CHAIN_DATA_UNAVAILABLE = "CHAIN_DATA_UNAVAILABLE"


# Spec §7: compact codes are stored in the decision record; the UI maps them to
# employee detail and customer-safe language. Customer text never names models,
# thresholds, labels, incidents or counterparties (spec §11).
REASON_TEXT = {
    ReasonCode.ACCESS_BURST: (
        "Transaction or access-request rate far above this wallet's baseline.",
        "We noticed an unusual burst of activity."),
    ReasonCode.NEW_CONTRACT_SPIKE: (
        "High share of interactions with contracts this wallet has not used before.",
        "We noticed activity that is different from your usual pattern."),
    ReasonCode.VALUE_OUTLIER: (
        "Transfer value is a statistical outlier against the wallet's history.",
        "We noticed a transfer that is unusual for your account."),
    ReasonCode.REPEATED_DENIALS: (
        "Repeated failed or denied access attempts in the last hour.",
        "We noticed several unsuccessful access attempts."),
    ReasonCode.KNOWN_PATTERN_SIMILARITY: (
        "Behavior vector closely matches a reviewed incident in threat memory.",
        "We noticed activity that needs an extra security check."),
    ReasonCode.GEMINI_FRAUD_LIKE: (
        "Gemini triage interpreted the evidence as fraud-like (advisory, capped weight).",
        "We noticed activity that needs an extra security check."),
    ReasonCode.GEMINI_POTENTIAL_ILLICIT: (
        "Gemini triage matched a corroborated configured typology; not a legal determination.",
        "We noticed activity that needs an extra security check."),
    ReasonCode.LOW_CONFIDENCE_REVIEW: (
        "AI output was uncertain or requested review; routed to an analyst instead of automatic action.",
        "This action is waiting for a quick security review."),
    ReasonCode.COLD_START_WALLET: (
        "Wallet is new or its history is unknown; baselines are low confidence.",
        "We have limited history for this wallet."),
    ReasonCode.CHAIN_DATA_UNAVAILABLE: (
        "Chain evidence could not be retrieved; held for review rather than approved.",
        "We could not complete our usual checks yet."),
}


def describe(code) -> dict:
    """Employee detail + customer-safe phrase for a stored reason code."""
    try:
        employee, customer = REASON_TEXT[ReasonCode(code)]
    except ValueError:
        employee, customer = f"Unmapped reason code {code}.", "We noticed unusual activity."
    return {"code": str(getattr(code, "value", code)), "employee": employee, "customer": customer}
