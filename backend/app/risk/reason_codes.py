"""Canonical import path for the shared risk reason codes.

Keep the original module available for callers using the historical filename.
Both imports expose the same enum class.
"""
from app.risk.reasons_codes import REASON_TEXT, ReasonCode, describe

__all__ = ["ReasonCode", "REASON_TEXT", "describe"]
