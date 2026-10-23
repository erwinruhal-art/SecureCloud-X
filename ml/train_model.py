"""
SecureCloud-X: Machine Learning Model Trainer
Trains an Isolation Forest anomaly detection model using scikit-learn
on the synthetic user behavior dataset (ml/security_events.csv).

Saves the trained model and feature scaler to ml/model.pkl.
Run command: python ml/train_model.py
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "ml" / "security_events.csv"
MODEL_PATH = BASE_DIR / "ml" / "model.pkl"

FEATURE_COLUMNS = [
    "failed_login_count",
    "files_accessed",
    "download_count",
    "download_volume_mb",
    "session_duration_min",
    "access_hour",
    "new_ip_flag",
    "new_device_flag",
    "unusual_download_frequency"
]


def train_anomaly_model():
    """Trains the Isolation Forest model and persists it to disk."""
    print("=" * 60)
    print("SecureCloud-X: Training ML Threat Detection Model")
    print("Algorithm: Isolation Forest (scikit-learn)")
    print("=" * 60)

    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

    # Load dataset
    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df)} records from {DATASET_PATH.name}")

    X = df[FEATURE_COLUMNS].values

    # Fit feature scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Calculate contamination rate from dataset labels if present
    contamination_rate = 0.15
    if "label" in df.columns:
        anomaly_count = (df["label"] == "anomaly").sum()
        contamination_rate = max(0.05, min(0.30, anomaly_count / len(df)))
        print(f"Anomaly ratio in training set: {anomaly_count}/{len(df)} ({contamination_rate:.2%})")

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination_rate,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    # Evaluate on training data
    preds = model.predict(X_scaled)
    detected_anomalies = (preds == -1).sum()
    detected_normal = (preds == 1).sum()

    print(f"Model fitted successfully.")
    print(f"Classified: {detected_normal} Normal | {detected_anomalies} Anomaly")

    # Compute baseline score bounds for normalized risk calculation
    raw_scores = model.decision_function(X_scaled)
    min_score = float(np.min(raw_scores))
    max_score = float(np.max(raw_scores))

    # Package model artifact
    model_artifact = {
        "model": model,
        "scaler": scaler,
        "feature_columns": FEATURE_COLUMNS,
        "min_score": min_score,
        "max_score": max_score,
        "contamination": contamination_rate
    }

    # Save to disk
    os.makedirs(MODEL_PATH.parent, exist_ok=True)
    joblib.dump(model_artifact, MODEL_PATH)
    print(f"Saved trained model artifact to: {MODEL_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    train_anomaly_model()
