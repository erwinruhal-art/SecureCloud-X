"""
SecureCloud-X: Machine Learning Threat Detection Service
Uses scikit-learn Isolation Forest to detect abnormal user activity
and compute normalized security risk scores.

Configurable Decision Rules:
  - Low Risk   (0.00 - 0.30): Operation Allowed (Normal)
  - Medium Risk (0.30 - 0.70): Operation Allowed with Log Warning
  - High Risk  (0.70 - 1.00): Sensitive Operation Blocked & Security Alert
"""

import json
import joblib
import numpy as np
from datetime import datetime
from config import ML_MODEL_PATH, RISK_THRESHOLD_LOW, RISK_THRESHOLD_HIGH
from ml.feature_engineering import FEATURE_COLUMNS, feature_dict_to_list
from database.database import get_db_connection, log_security_event


class AnomalyDetector:
    """
    Evaluates user behavior feature vectors using a pre-trained Isolation Forest model.
    """

    def __init__(self):
        self.model_artifact = None
        self.model = None
        self.scaler = None
        self.min_score = -0.3
        self.max_score = 0.3
        self._load_model()

    def _load_model(self):
        """Loads the pre-trained Isolation Forest model from disk."""
        if ML_MODEL_PATH.exists():
            try:
                self.model_artifact = joblib.load(ML_MODEL_PATH)
                self.model = self.model_artifact["model"]
                self.scaler = self.model_artifact["scaler"]
                self.min_score = self.model_artifact.get("min_score", -0.3)
                self.max_score = self.model_artifact.get("max_score", 0.3)
            except Exception as e:
                print(f"Warning: Could not load ML model ({e}). Using heuristic evaluator.")
                self.model = None
        else:
            self.model = None

    def evaluate_behavior(self, features: dict, username: str = "anonymous", action: str = "OPERATION") -> dict:
        """
        Analyzes user behavior features and returns risk assessment and access decision.
        
        Args:
            features: Dictionary containing the 9 feature values.
            username: User account performing the action.
            action: Type of action being evaluated (e.g. LOGIN, UPLOAD, DOWNLOAD).
            
        Returns:
            dict with keys: prediction, risk_score, risk_level, decision, action_taken
        """
        if self.model is None:
            # Reload attempt or rule-based fallback
            self._load_model()

        if self.model is not None and self.scaler is not None:
            # ML Model Inference
            raw_features = np.array([feature_dict_to_list(features)])
            scaled_features = self.scaler.transform(raw_features)

            # Isolation Forest decision_function: lower values indicate higher anomaly likelihood
            raw_score = float(self.model.decision_function(scaled_features)[0])
            pred_class = int(self.model.predict(scaled_features)[0])  # 1: Normal, -1: Anomaly

            # Map raw score to normalized [0.00, 1.00] risk scale
            # If model classifies as Anomaly (pred_class == -1), risk score is mapped to >= 0.70 (High Risk)
            # If model classifies as Normal (pred_class == 1), risk score is mapped to <= 0.65 (Low/Medium Risk)
            if pred_class == -1:
                severity = abs(raw_score) * 1.5
                risk_score = round(float(np.clip(0.70 + severity, 0.70, 0.99)), 2)
                prediction_label = "ANOMALY"
            else:
                baseline = max(0.0, raw_score) * 1.2
                risk_score = round(float(np.clip(0.30 - baseline, 0.05, 0.60)), 2)
                prediction_label = "NORMAL"
        else:
            # Fallback heuristic evaluation if model file has not yet been generated
            failed = features.get("failed_login_count", 0)
            vol = features.get("download_volume_mb", 0)
            downloads = features.get("download_count", 0)

            if failed >= 5 or vol > 1000 or downloads > 25:
                risk_score = 0.85
                prediction_label = "ANOMALY"
            elif failed >= 2 or vol > 200:
                risk_score = 0.45
                prediction_label = "NORMAL"
            else:
                risk_score = 0.15
                prediction_label = "NORMAL"

        # Apply configurable threshold decisions
        if risk_score <= RISK_THRESHOLD_LOW:
            risk_level = "LOW"
            decision = "ALLOW"
            action_taken = "Operation permitted. Behavior matches baseline profile."
        elif risk_score <= RISK_THRESHOLD_HIGH:
            risk_level = "MEDIUM"
            decision = "WARN"
            action_taken = "Operation permitted with warning. Elevated activity logged."
            log_security_event(username, "ML_ANOMALY_WARNING", details=f"action={action} risk={risk_score}")
        else:
            risk_level = "HIGH"
            decision = "BLOCK"
            action_taken = "Operation blocked by AI threat detection engine. Excessive risk."
            log_security_event(username, "ACCESS_BLOCKED", details=f"action={action} risk={risk_score} reason=ANOMALY_DETECTED")

        result = {
            "prediction": prediction_label,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "decision": decision,
            "action_taken": action_taken,
            "features": features
        }

        # Persist ML decision to SQLite
        try:
            conn = get_db_connection()
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("""
                INSERT INTO ml_predictions (timestamp, username, action, risk_score, prediction, features_json, decision)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp_str, username, action, risk_score, prediction_label, json.dumps(features), decision))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error persisting ML prediction: {e}")

        return result


# Global anomaly detector instance
anomaly_detector = AnomalyDetector()
