"""Match only server-configured typologies against deterministic indicators."""
from pathlib import Path
import yaml
from app.api.settings import TEAM_SERVICES_DIR
from app.risk.rules import RuleEngine

class TypologyMatcher:
    def __init__(self, path=None):
        path = Path(path) if path else TEAM_SERVICES_DIR / "typologies.yaml"
        config = yaml.safe_load(path.read_text()) or {}
        self.entries = config.get("typologies", [])
        for entry in self.entries:
            signals = entry.get("signals", [])
            if not isinstance(entry.get("name"), str) or len(set(signals)) < 2:
                raise ValueError("typologies require a name and at least two distinct signals")
            if entry.get("category", "SUSPICIOUS_FRAUD_LIKE") not in {
                "SUSPICIOUS_FRAUD_LIKE", "POTENTIAL_ILLICIT_ACTIVITY"
            }:
                raise ValueError("unsupported typology category")

    def match(self, evidence):
        _, reasons = RuleEngine().evaluate(evidence)
        signals = {reason.value for reason in reasons}
        if evidence.get("pattern_similarity", 0) >= 0.6:
            signals.add("KNOWN_PATTERN_SIMILARITY")
        if evidence.get("flagged_counterparty_count", 0) > 0:
            signals.add("FLAGGED_COUNTERPARTY")
        return [{"name": entry["name"], "category": entry.get("category", "SUSPICIOUS_FRAUD_LIKE"),
                 "signals": sorted(set(entry["signals"]))}
                for entry in self.entries if set(entry["signals"]).issubset(signals)]
