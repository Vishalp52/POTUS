# POTUS ML model

The ML layer is the statistical anomaly detector used by the evaluation engine.

## Current integration

`app.models.model_store.load_detector()` loads a persisted `IsolationForest` and
re-trains it automatically when the artifact is missing, incompatible with the
current vector contract, or trained from a different `normal_wallets.csv`.

The live path is:

`chain activity -> feature extraction -> 8-feature model vector -> IsolationForest -> anomaly_score -> risk fusion/policy`

The model does **not** make ALLOW/CHALLENGE/REVIEW/RESTRICT decisions. Those
remain in the deterministic risk/policy layer.

## Model contract

The vector order is owned by `app.features.schemas.MODEL_FEATURES` and currently
contains 8 features. `VECTOR_VERSION` is stored with the artifact so changing
the feature contract forces a retrain instead of silently loading an old model.

The detector also validates each inference vector for dimensionality, finite
values, and the feature ranges already defined by the feature schema.

## Training

Training uses `normal_wallets.csv` when it is available. If that file is absent
or unusable, a deterministic synthetic normal population is used as a fallback.
The training source is recorded in the model metadata.

## Calibration

scikit-learn's `decision_function` is lower for more abnormal observations. POTUS
flips that sign and calibrates it against the normal training population into a
bounded `0.0..1.0` anomaly score, where higher means more anomalous.

## Useful APIs

- `AnomalyDetector.score(vector)` — one normalized anomaly score.
- `AnomalyDetector.score_many(vectors)` — batch scoring in input order.
- `AnomalyDetector.raw_score(vector)` — calibrated-independent raw signal.
- `AnomalyDetector.info()` — model, vector, training, and calibration metadata.
- `load_detector()` — cached production detector with stale-artifact detection.

## Training and evaluation commands

From the repository root:

```bash
python backend/model.py --report backend/evaluation/model-report.json
cd backend
python evaluate.py --output evaluation/offline-report.json
```

The exported artifact is included under `app/models/artifacts`. Model writes use an
atomic replacement. Both loaded and cached models are checked against the CSV
fingerprint, vector/schema version, and scikit-learn version. The calibration
report uses a deterministic 80/20 normal-only split; it does not establish attack
precision/recall or production effectiveness. The final artifact trains on all
1,000 normal rows.
