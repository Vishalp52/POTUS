"""Train/export the stage-4 detector: python backend/model.py [--output PATH]."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from app.models.model_store import train_and_save
from app.models.isolation_forest import AnomalyDetector, load_training_frame


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="Model artifact path (defaults to MODEL_PATH)")
    parser.add_argument("--report", help="Write normal-only holdout calibration report as JSON")
    args = parser.parse_args()
    frame, source = load_training_frame()
    if len(frame) < 10:
        raise SystemExit("At least 10 normal examples are required for holdout evaluation")
    # This measures normal-data calibration only, never fraud-detection accuracy.
    order = np.random.default_rng(42).permutation(len(frame))
    split = max(2, int(.8 * len(frame)))
    train, test = frame.iloc[order[:split]], frame.iloc[order[split:]]
    probe = AnomalyDetector().fit(train, source + ":holdout-train")
    scores = probe.score_many(test.to_numpy().tolist())
    detector = train_and_save(args.output)
    report = {"model": detector.info(), "training_rows": len(frame), "holdout_rows": len(test),
              "trained_at": datetime.now(timezone.utc).isoformat(), "holdout_training_rows": len(train),
              "data_provenance": "Supplied synthetic normal-wallet fixture; no verified real attack labels.",
              "holdout_anomaly_percentiles": {str(q): round(float(np.percentile(scores, q)), 4) for q in (50, 90, 95, 99)},
              "holdout_gemini_trigger_fraction_at_035": sum(s >= .35 for s in scores) / len(scores),
              "limitations": "Normal-only calibration; no validated attack labels or production accuracy claims. Final artifact is fitted to all normal rows."}
    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
