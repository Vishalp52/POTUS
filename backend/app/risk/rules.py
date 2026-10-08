from typing import Dict, Any, List, Tuple
from app.risk.reason_codes import ReasonCode

class RuleEngine:
    def __init__(self):
        self.tx_burst_ratio_threshold = 5.0
        self.new_contract_ratio_threshold = 0.50
        self.transfer_zscore_threshold = 3.0
        self.failed_access_threshold = 3

    def evaluate(self, evidence: Dict[str, Any]) -> Tuple[float, List[ReasonCode]]:
        triggered: List[ReasonCode] = []
        points = 0.0

        deltas = evidence.get("feature_deltas", {})

        if (deltas.get("tx_count_10m", {}).get("ratio", 0.0) >= self.tx_burst_ratio_threshold
                or deltas.get("access_requests_10m", {}).get("value", 0) >= 20):
            points += 30.0
            triggered.append(ReasonCode.ACCESS_BURST)

        if deltas.get("new_contract_ratio", {}).get("value", 0.0) >= self.new_contract_ratio_threshold:
            points += 25.0
            triggered.append(ReasonCode.NEW_CONTRACT_SPIKE)

        if evidence.get("transfer_value_zscore", 0.0) >= self.transfer_zscore_threshold:
            points += 25.0
            triggered.append(ReasonCode.VALUE_OUTLIER)

        if evidence.get("failed_access_count", 0) >= self.failed_access_threshold:
            points += 20.0
            triggered.append(ReasonCode.REPEATED_DENIALS)

        if 0 < evidence.get("wallet_age_blocks", 0) < 1000:
            triggered.append(ReasonCode.COLD_START_WALLET)

        normalized_score = min(1.0, points / 100.0)
        return normalized_score, triggered
