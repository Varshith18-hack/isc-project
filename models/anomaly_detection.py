"""
Medical Device Anomaly Inference Engine (Optimized Stage 3.1)
============================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Provides an inference engine for real-time anomaly detection on incoming IoMT telemetry streams.
Loads the trained Isolation Forest pipeline and calibrated decision threshold, providing:
- Binary Classification: 'NORMAL' or 'ANOMALY'
- Raw decision anomaly scores: -score_samples(X)
- Normalized anomaly confidence score (0.0 to 1.0)
- Risk / Severity categorization ('NORMAL', 'WARNING', 'CRITICAL')
- Telemetry contribution explainability (identifying which vital signs deviated the most)
"""

import sys
from pathlib import Path
from datetime import datetime
import joblib
import numpy as np
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from models.train_model import compute_features, RAW_FEATURE_COLS


class MedicalDeviceAnomalyDetector:
    """
    Inference service for real-time IoMT telemetry anomaly detection.
    """

    def __init__(self, model_path: Path = config.MODEL_FILE_PATH):
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None
        self.threshold = None
        self.feature_names = None
        self.metadata = None
        self.load_model()

    def load_model(self):
        """Load the persisted model artifact from disk."""
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model file not found at {self.model_path}. "
                "Please run 'python models/train_model.py' to train and save the model."
            )

        artifact = joblib.load(self.model_path)
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.threshold = artifact["threshold"]
        self.feature_names = artifact["feature_names"]
        self.metadata = artifact
        return self

    def _extract_telemetry_dict(self, reading: dict) -> dict:
        """Extract and validate raw telemetry values from input reading."""
        telemetry = {}
        for col in RAW_FEATURE_COLS:
            val = reading.get(col)
            if val is None:
                raise ValueError(f"Missing required telemetry feature: '{col}' in reading.")
            try:
                telemetry[col] = float(val)
            except (ValueError, TypeError):
                raise ValueError(f"Invalid non-numeric value for '{col}': {val}")
        return telemetry

    def _determine_contributing_factors(self, telemetry: dict) -> list[str]:
        """
        Explainability helper: Identifies which vitals deviated most
        from normal healthy baselines using the fitted scaler parameters.
        """
        means = self.scaler.mean_
        stds = self.scaler.scale_

        factors = []
        for idx, col in enumerate(RAW_FEATURE_COLS):
            val = telemetry[col]
            mean = means[idx]
            std = stds[idx]
            z = (val - mean) / std

            if abs(z) >= 2.5:
                direction = "critically high" if z > 0 else "critically low"
                factors.append(f"{col.replace('_', ' ').title()} is {direction} ({val} vs normal ~{mean:.1f})")

        return factors if factors else ["Normal variance within expected physiological limits"]

    def predict_reading(self, reading: dict) -> dict:
        """
        Run inference on a single medical device telemetry reading.

        Parameters:
        -----------
        reading: dict
            Dictionary containing device telemetry (must contain features in RAW_FEATURE_COLS,
            plus optional 'device_id' and 'timestamp').

        Returns:
        --------
        dict
            Structured prediction result with score, label, severity, and contributing factors.
        """
        device_id = reading.get("device_id", "DEV-UNKNOWN")
        timestamp = reading.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        telemetry = self._extract_telemetry_dict(reading)
        reading_df = pd.DataFrame([telemetry])

        # Transform using the saved standard scaler and compute features
        X_trans = compute_features(reading_df, self.scaler)

        # Raw score: higher = more isolated / anomalous
        raw_score = float(-self.model.score_samples(X_trans)[0])

        is_anomaly = int(raw_score > self.threshold)
        status = "ANOMALY" if is_anomaly else "NORMAL"

        # Normalized score mapped to 0.0 - 1.0 scale
        norm_score = float(np.clip((raw_score - 0.40) / (0.68 - 0.40), 0.0, 1.0))

        # Severity categorization
        if not is_anomaly:
            severity = "NORMAL"
        elif raw_score > (self.threshold * 1.05):
            severity = "CRITICAL"
        else:
            severity = "WARNING"

        contributing = self._determine_contributing_factors(telemetry)

        return {
            "device_id": device_id,
            "timestamp": timestamp,
            "status": status,
            "is_anomaly": is_anomaly,
            "anomaly_score": round(raw_score, 4),
            "normalized_score": round(norm_score, 4),
            "calibrated_threshold": round(self.threshold, 4),
            "severity": severity,
            "telemetry": telemetry,
            "contributing_factors": contributing,
        }

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Run batch inference on a DataFrame of medical device readings.
        Returns a copy of the DataFrame with added prediction columns.
        """
        missing = set(RAW_FEATURE_COLS) - set(df.columns)
        if missing:
            raise ValueError(f"Input DataFrame missing required telemetry columns: {missing}")

        X_trans = compute_features(df, self.scaler)
        raw_scores = -self.model.score_samples(X_trans)
        is_anomaly = (raw_scores > self.threshold).astype(int)

        result_df = df.copy()
        result_df["model_score"] = np.round(raw_scores, 4)
        result_df["model_prediction"] = np.where(is_anomaly == 1, "ANOMALY", "NORMAL")
        result_df["model_is_anomaly"] = is_anomaly
        result_df["model_severity"] = np.where(
            is_anomaly == 0,
            "NORMAL",
            np.where(raw_scores > (self.threshold * 1.05), "CRITICAL", "WARNING")
        )
        return result_df


if __name__ == "__main__":
    print("=" * 80)
    print("DEMONSTRATION: REAL-TIME INFERENCE WITH OPTIMIZED ISOLATION FOREST")
    print("=" * 80)

    detector = MedicalDeviceAnomalyDetector()
    print(f"[+] Loaded Model Version: {detector.metadata.get('model_version')}")
    print(f"[+] Calibrated Decision Threshold: {detector.threshold:.4f}")
    print(f"[+] Model Features: {len(detector.feature_names)} features ({detector.feature_names})")

    sample_cases = [
        {
            "name": "Case 1: Standard Normal Telemetry (Patient Monitor)",
            "data": {
                "device_id": "DEV-MON-003",
                "heart_rate": 74.5,
                "systolic_bp": 116.0,
                "diastolic_bp": 74.0,
                "oxygen_saturation": 98.4,
                "body_temperature": 36.95,
                "device_activity_level": 24.2,
            },
        },
        {
            "name": "Case 2: Acute Cardiac Crisis / Severe Tachycardia",
            "data": {
                "device_id": "DEV-ECG-005",
                "heart_rate": 182.0,
                "systolic_bp": 185.0,
                "diastolic_bp": 118.0,
                "oxygen_saturation": 97.5,
                "body_temperature": 37.10,
                "device_activity_level": 26.0,
            },
        },
        {
            "name": "Case 3: Respiratory Failure / Severe Hypoxia",
            "data": {
                "device_id": "DEV-VENT-002",
                "heart_rate": 128.0,
                "systolic_bp": 114.0,
                "diastolic_bp": 72.0,
                "oxygen_saturation": 74.5,
                "body_temperature": 36.85,
                "device_activity_level": 25.5,
            },
        },
        {
            "name": "Case 4: Cyber Attack / Network Telemetry Flood (DoS)",
            "data": {
                "device_id": "DEV-PUMP-001",
                "heart_rate": 76.0,
                "systolic_bp": 118.0,
                "diastolic_bp": 76.0,
                "oxygen_saturation": 98.0,
                "body_temperature": 37.00,
                "device_activity_level": 850.0,
            },
        },
        {
            "name": "Case 5: Sensor Tampering / Flatline Spoofing",
            "data": {
                "device_id": "DEV-DIAL-004",
                "heart_rate": 0.0,
                "systolic_bp": 0.0,
                "diastolic_bp": 0.0,
                "oxygen_saturation": 0.0,
                "body_temperature": 36.80,
                "device_activity_level": 28.0,
            },
        },
    ]

    for case in sample_cases:
        print("\n" + "-" * 70)
        print(f"TESTING: {case['name']}")
        print("-" * 70)
        result = detector.predict_reading(case["data"])
        print(f"Device ID:        {result['device_id']}")
        print(f"Model Prediction: {result['status']} (is_anomaly = {result['is_anomaly']})")
        print(f"Severity Level:   {result['severity']}")
        print(f"Anomaly Score:    {result['anomaly_score']:.4f} (Threshold: {result['calibrated_threshold']:.4f})")
        print(f"Normalized Score: {result['normalized_score']:.2%}")
        print(f"Key Findings:     {', '.join(result['contributing_factors'])}")
    print("\n" + "=" * 80)
