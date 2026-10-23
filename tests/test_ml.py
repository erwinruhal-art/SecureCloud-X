"""
Unit Tests: Machine Learning Threat Detection Engine
Verifies Isolation Forest inference, risk score normalization, and action blocking.
"""

import unittest
from ml.feature_engineering import create_feature_dict
from ml.anomaly_detector import AnomalyDetector


class TestMLThreatDetector(unittest.TestCase):

    def setUp(self):
        self.detector = AnomalyDetector()

    def test_normal_behavior_classification(self):
        """Standard activity must evaluate as low risk and allow operation."""
        normal_feats = create_feature_dict(
            failed_login_count=0,
            files_accessed=2,
            download_count=1,
            download_volume_mb=3.0,
            session_duration_min=12.0,
            access_hour=14,
            new_ip_flag=0,
            new_device_flag=0,
            unusual_download_frequency=0
        )
        result = self.detector.evaluate_behavior(normal_feats, username="test_normal", action="TEST")
        self.assertEqual(result["prediction"], "NORMAL")
        self.assertLessEqual(result["risk_score"], 0.70)
        self.assertIn(result["decision"], ["ALLOW", "WARN"])

    def test_anomalous_behavior_blocking(self):
        """Excessive downloads, failed logins, and night access must trigger BLOCK."""
        anomalous_feats = create_feature_dict(
            failed_login_count=10,
            files_accessed=150,
            download_count=60,
            download_volume_mb=4500.0,
            session_duration_min=300.0,
            access_hour=3,
            new_ip_flag=1,
            new_device_flag=1,
            unusual_download_frequency=1
        )
        result = self.detector.evaluate_behavior(anomalous_feats, username="test_attacker", action="TEST")
        self.assertEqual(result["prediction"], "ANOMALY")
        self.assertGreater(result["risk_score"], 0.70)
        self.assertEqual(result["decision"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
