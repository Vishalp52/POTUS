import yaml
from services.evaluator import EvaluatorService

def run_replay():
    with open("config/risk.yaml", "r") as f:
        config = yaml.safe_load(f)

    evaluator = EvaluatorService(config)
    evaluator.threat_store.insert_incident(
        incident_id="inc_001",
        vector=[15, 0.8, 30.0, 4],
        category="SUSPICIOUS_FRAUD_LIKE",
        disposition="CONFIRMED_INCIDENT",
        evidence_hash="0xabc123"
    )
    print("Threat memory seeded successfully.")

if __name__ == "__main__":
    run_replay()