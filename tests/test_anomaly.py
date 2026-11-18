"""
Unit Test Suite for AI Anomaly Detection Module (Stage 3.1)
===========================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices
"""

import sys
from pathlib import Path
import unittest
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from models.train_model import compute_features, RAW_FEATURE_COLS
from models.anomaly_detection import MedicalDeviceAnomalyDetector


class TestMedicalDeviceAnomalyDetection(unittest.TestCase):
    """Test suite validating model loading, feature extraction, and inference accuracy."""

    @classmethod
    def setUpClass(cls):
        """Initialize the anomaly detector once for all tests."""
        cls.detector = MedicalDeviceAnomalyDetector()

    def test_01_model_artifact_integrity(self):
        """Verify saved model artifact contains all required components."""
        self.assertIsNotNone(self.detector.model, "Isolation Forest model missing from artifact.")
        self.assertIsNotNone(self.detector.scaler, "StandardScaler missing from artifact.")
        self.assertIsNotNone(self.detector.threshold, "Calibrated threshold missing from artifact.")
        self.assertGreater(self.detector.threshold, 0.50, "Calibrated threshold suspiciously low.")
        self.assertLess(self.detector.threshold, 0.70, "Calibrated threshold suspiciously high.")
        self.assertEqual(len(self.detector.feature_names), 8, "Expected 8 total features (6 raw + 2 engineered).")

    def test_02_feature_transformation(self):
        """Verify feature engineering outputs the expected shape and columns."""
        sample_raw = pd.DataFrame([{
            "heart_rate": 75.0,
            "systolic_bp": 115.0,
            "diastolic_bp": 75.0,
            "oxygen_saturation": 98.0,
            "body_temperature": 37.0,
            "device_activity_level": 25.0,
        }])
        X_trans = compute_features(sample_raw, self.detector.scaler)
        self.assertEqual(X_trans.shape, (1, 8))
        self.assertIn("max_zscore", X_trans.columns)
        self.assertIn("mean_zscore", X_trans.columns)

    def test_03_normal_reading_inference(self):
        """Verify that typical healthy baseline telemetry is classified as NORMAL."""
        normal_reading = {
            "device_id": "DEV-MON-003",
            "heart_rate": 74.0,
            "systolic_bp": 115.0,
            "diastolic_bp": 75.0,
            "oxygen_saturation": 98.5,
            "body_temperature": 37.0,
            "device_activity_level": 24.0,
        }
        result = self.detector.predict_reading(normal_reading)
        self.assertEqual(result["status"], "NORMAL")
        self.assertEqual(result["is_anomaly"], 0)
        self.assertLess(result["anomaly_score"], result["calibrated_threshold"])
        self.assertEqual(result["severity"], "NORMAL")

    def test_04_tachycardia_anomaly_inference(self):
        """Verify that severe tachycardia and hypertensive crisis is classified as ANOMALY."""
        tachycardia_reading = {
            "device_id": "DEV-ECG-005",
            "heart_rate": 185.0,
            "systolic_bp": 180.0,
            "diastolic_bp": 115.0,
            "oxygen_saturation": 98.0,
            "body_temperature": 37.0,
            "device_activity_level": 26.0,
        }
        result = self.detector.predict_reading(tachycardia_reading)
        self.assertEqual(result["status"], "ANOMALY")
        self.assertEqual(result["is_anomaly"], 1)
        self.assertGreater(result["anomaly_score"], result["calibrated_threshold"])

    def test_05_hypoxia_anomaly_inference(self):
        """Verify that acute oxygen desaturation (SpO2=72%) is classified as ANOMALY."""
        hypoxia_reading = {
            "device_id": "DEV-VENT-002",
            "heart_rate": 125.0,
            "systolic_bp": 115.0,
            "diastolic_bp": 75.0,
            "oxygen_saturation": 72.0,
            "body_temperature": 37.0,
            "device_activity_level": 25.0,
        }
        result = self.detector.predict_reading(hypoxia_reading)
        self.assertEqual(result["status"], "ANOMALY")
        self.assertEqual(result["is_anomaly"], 1)
        self.assertGreater(result["anomaly_score"], result["calibrated_threshold"])

    def test_06_cyber_dos_burst_inference(self):
        """Verify that a network traffic burst (850 pkts/min) is classified as ANOMALY."""
        dos_reading = {
            "device_id": "DEV-PUMP-001",
            "heart_rate": 75.0,
            "systolic_bp": 115.0,
            "diastolic_bp": 75.0,
            "oxygen_saturation": 98.0,
            "body_temperature": 37.0,
            "device_activity_level": 850.0,
        }
        result = self.detector.predict_reading(dos_reading)
        self.assertEqual(result["status"], "ANOMALY")
        self.assertEqual(result["is_anomaly"], 1)
        self.assertGreater(result["anomaly_score"], result["calibrated_threshold"])

    def test_07_batch_inference(self):
        """Verify that batch inference returns expected DataFrame schema with prediction columns."""
        df_batch = pd.DataFrame([
            {
                "heart_rate": 75.0, "systolic_bp": 115.0, "diastolic_bp": 75.0,
                "oxygen_saturation": 98.0, "body_temperature": 37.0,
                "device_activity_level": 25.0,
            },
            {
                "heart_rate": 190.0, "systolic_bp": 195.0, "diastolic_bp": 120.0,
                "oxygen_saturation": 96.0, "body_temperature": 37.0,
                "device_activity_level": 25.0,
            },
        ])
        res_df = self.detector.predict_batch(df_batch)
        self.assertEqual(len(res_df), 2)
        self.assertIn("model_prediction", res_df.columns)
        self.assertIn("model_score", res_df.columns)
        self.assertEqual(res_df["model_prediction"].iloc[0], "NORMAL")
        self.assertEqual(res_df["model_prediction"].iloc[1], "ANOMALY")


if __name__ == "__main__":
    unittest.main()
