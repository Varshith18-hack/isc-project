"""
Automated Test Suite for Streamlit Dashboard & Components (Stage 7)
===================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Comprehensive Test Suite (9 Tests):
------------------------------------
1. Data Ingestion: Verifies load_telemetry_dataset returns expected rows and columns.
2. Device Summarization: Verifies get_device_summary for all 5 IoMT devices.
3. Clinical Charting: Verifies create_vitals_time_series_chart generates valid Plotly figure.
4. Network Activity Charting: Verifies create_network_activity_chart generates valid Plotly figure.
5. Anomaly Gauge: Verifies create_anomaly_score_gauge correctly calibrates to threshold 0.5809.
6. Threat Badge: Verifies render_threat_badge differentiates medical vs cyber attacks.
7. AI Detector Integration: Verifies live inference pipeline integration.
8. Cryptography Workflow: Verifies AES-256-GCM AEAD encryption/decryption in dashboard context.
9. Isolated Sandbox Verification: Verifies destructive attacks run in sandbox without altering production chain.
"""

import sys
import unittest
import tempfile
import shutil
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import pandas as pd
import plotly.graph_objects as go
from dashboard.components import (
    load_telemetry_dataset,
    get_device_summary,
    create_vitals_time_series_chart,
    create_network_activity_chart,
    create_anomaly_score_gauge,
    render_threat_badge,
)
from models.anomaly_detection import MedicalDeviceAnomalyDetector
from security.encryption import (
    encrypt_telemetry_record,
    decrypt_telemetry_record,
    CryptoIntegrityError,
)
from audit.audit_logger import (
    append_audit_event,
    load_audit_chain,
    AUDIT_FILE_PATH,
)
from audit.integrity_checker import (
    verify_audit_chain,
    simulate_payload_tamper,
)


class TestDashboardComponents(unittest.TestCase):
    """Test suite for Streamlit dashboard helper components and integration."""

    @classmethod
    def setUpClass(cls):
        cls.df = load_telemetry_dataset()
        cls.detector = MedicalDeviceAnomalyDetector()

    def test_01_load_telemetry_dataset(self):
        """Verify load_telemetry_dataset loads 10,000 records with expected schema."""
        self.assertFalse(self.df.empty)
        self.assertEqual(len(self.df), 10000)
        self.assertIn("device_id", self.df.columns)
        self.assertIn("heart_rate", self.df.columns)
        self.assertIn("oxygen_saturation", self.df.columns)
        self.assertIn("is_anomaly", self.df.columns)

    def test_02_device_summary(self):
        """Verify get_device_summary computes statistics for all 5 connected devices."""
        for dev_id in config.DEVICE_PROFILES.keys():
            summary = get_device_summary(dev_id, self.df)
            self.assertEqual(summary["device_id"], dev_id)
            self.assertEqual(summary["total_records"], 2000)
            self.assertIn("latest_vitals", summary)
            self.assertIn("heart_rate", summary["latest_vitals"])

    def test_03_create_vitals_time_series_chart(self):
        """Verify clinical vitals time-series returns a valid Plotly Figure."""
        dev_df = self.df[self.df["device_id"] == "DEV-VENT-002"]
        fig = create_vitals_time_series_chart(dev_df, window=100)
        self.assertIsInstance(fig, go.Figure)
        # Should have traces for Heart Rate, Systolic BP, Diastolic BP, SpO2, and Anomalies
        trace_names = [t.name for t in fig.data]
        self.assertIn("Heart Rate (bpm)", trace_names)
        self.assertIn("Systolic BP (mmHg)", trace_names)
        self.assertIn("SpO2 (%)", trace_names)

    def test_04_create_network_activity_chart(self):
        """Verify network activity chart returns a valid Plotly Figure."""
        dev_df = self.df[self.df["device_id"] == "DEV-PUMP-001"]
        fig = create_network_activity_chart(dev_df, window=100)
        self.assertIsInstance(fig, go.Figure)
        self.assertEqual(fig.data[0].name, "Packets / Min")

    def test_05_create_anomaly_score_gauge(self):
        """Verify anomaly score gauge displays score relative to threshold 0.5809."""
        fig = create_anomaly_score_gauge(0.65, threshold=0.5809)
        self.assertIsInstance(fig, go.Figure)
        indicator = fig.data[0]
        self.assertEqual(indicator.value, 0.65)
        self.assertEqual(indicator.gauge.threshold.value, 0.5809)

    def test_06_render_threat_badge(self):
        """Verify threat badge distinguishes medical anomalies from cyber attacks."""
        badge_med = render_threat_badge("Abnormal_Heart_Rate")
        self.assertIn("Medical Anomaly", badge_med)
        self.assertIn("Abnormal_Heart_Rate", badge_med)

        badge_cyber = render_threat_badge("Network_Traffic_Burst")
        self.assertIn("Cyber Attack", badge_cyber)
        self.assertIn("Network_Traffic_Burst", badge_cyber)

    def test_07_ai_detector_inference_on_sample(self):
        """Verify AI detector inference on sample reading integrates with dashboard."""
        sample_normal = {
            "device_id": "DEV-VENT-002",
            "heart_rate": 72.0,
            "systolic_bp": 118.0,
            "diastolic_bp": 76.0,
            "oxygen_saturation": 98.5,
            "body_temperature": 36.8,
            "device_activity_level": 20.0,
        }
        res_normal = self.detector.predict_reading(sample_normal)
        self.assertEqual(res_normal["status"], "NORMAL")
        self.assertEqual(res_normal["is_anomaly"], 0)
        self.assertLess(res_normal["anomaly_score"], 0.5809)

        sample_anomaly = {
            "device_id": "DEV-VENT-002",
            "heart_rate": 185.0,
            "systolic_bp": 170.0,
            "diastolic_bp": 110.0,
            "oxygen_saturation": 75.0,
            "body_temperature": 40.5,
            "device_activity_level": 110.0,
        }
        res_anomaly = self.detector.predict_reading(sample_anomaly)
        self.assertEqual(res_anomaly["status"], "ANOMALY")
        self.assertEqual(res_anomaly["is_anomaly"], 1)
        self.assertGreater(res_anomaly["anomaly_score"], 0.5809)

    def test_08_aes_gcm_workflow_in_dashboard(self):
        """Verify AES-256-GCM AEAD encryption and decryption workflow."""
        payload = {"patient": "Alice", "hr": 75.0, "status": "STABLE"}
        aad = {"ward": "ICU-3"}
        env = encrypt_telemetry_record(payload, associated_data=aad)
        self.assertEqual(env["algorithm"], "AES-256-GCM")
        self.assertEqual(len(env["nonce"]), 24) # 12 bytes = 24 hex
        self.assertEqual(len(env["auth_tag"]), 32) # 16 bytes = 32 hex

        decrypted = decrypt_telemetry_record(env)
        self.assertEqual(decrypted["patient"], "Alice")
        self.assertEqual(decrypted["hr"], 75.0)

    def test_09_isolated_sandbox_tamper_detection(self):
        """Verify that destructive attack simulations run in sandbox without altering production chain."""
        temp_dir = tempfile.mkdtemp()
        try:
            sandbox_chain_file = Path(temp_dir) / "sandbox_audit_chain.json"
            # Seed 3 blocks in sandbox
            for i in range(1, 4):
                append_audit_event(f"DEV-00{i}", "READING", {"v": i}, file_path=sandbox_chain_file, sync_to_sqlite=False)

            # Baseline: sandbox is valid
            rep1 = verify_audit_chain(sandbox_chain_file)
            self.assertTrue(rep1["is_valid"])

            # Adversary tampers with Block #2 in sandbox ONLY
            sb_chain = load_audit_chain(sandbox_chain_file)
            tampered_sb = simulate_payload_tamper(sb_chain, target_event_id=2, key_to_modify="v", new_value=999)
            import json
            with open(sandbox_chain_file, "w", encoding="utf-8") as f:
                json.dump(tampered_sb, f)

            # Verify that sandbox detects tampering
            rep2 = verify_audit_chain(sandbox_chain_file)
            self.assertFalse(rep2["is_valid"])
            self.assertEqual(rep2["status"], "TAMPERED")

            # Crucial Check: Production audit file on disk remains completely untouched
            if AUDIT_FILE_PATH.exists():
                prod_rep = verify_audit_chain(AUDIT_FILE_PATH)
                self.assertTrue(prod_rep["is_valid"], "Production chain must remain pristine during sandbox attacks")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_10_hmac_authenticity_verification_lab(self):
        """Verify HMAC verification feature in SHA-256 & HMAC-SHA256 Authenticity Lab."""
        from streamlit.testing.v1 import AppTest

        at = AppTest.from_file(str(PROJECT_ROOT / "app.py"), default_timeout=30)
        at.run()

        # Switch to Cryptography and Security Lab
        nav_radio = [r for r in at.sidebar.radio if "Select Subsystem Page" in r.label][0]
        nav_radio.set_value("🔐 Cryptography and Security Lab").run()

        # Check for Original HMAC Signature text input and Verify Existing Signature button
        orig_input_list = [t for t in at.text_input if t.label == "Original HMAC Signature"]
        verify_btn_list = [b for b in at.button if b.label == "Verify Existing Signature"]
        self.assertTrue(len(orig_input_list) > 0, "Original HMAC Signature text input must exist.")
        self.assertTrue(len(verify_btn_list) > 0, "Verify Existing Signature button must exist.")

        orig_input = orig_input_list[0]
        verify_btn = verify_btn_list[0]
        initial_sig = orig_input.value
        self.assertEqual(len(initial_sig), 64, "Initial signature must be 64-character hexadecimal.")

        # 1. Verify authentic baseline signature
        verify_btn.click().run()
        success_msgs = [s.value for s in at.success]
        self.assertTrue(any("Signature Valid" in s for s in success_msgs), "Baseline verification must display 'Signature Valid'.")

        # 2. Tamper input text and verify tampering detection without overwriting original signature
        hash_area = [a for a in at.text_area if "Input Text or JSON" in a.label][0]
        hash_area.input("Connected Medical Device Mechanical Ventilator DEV-VENT-002 TAMPERED_PAYLOAD").run()

        orig_input_after_tamper = [t for t in at.text_input if t.label == "Original HMAC Signature"][0]
        self.assertEqual(
            orig_input_after_tamper.value,
            initial_sig,
            "Original HMAC Signature must not be automatically replaced or regenerated when text changes."
        )

        verify_btn = [b for b in at.button if b.label == "Verify Existing Signature"][0]
        verify_btn.click().run()
        error_msgs = [e.value for e in at.error]
        self.assertTrue(
            any("TAMPERING DETECTED \u2013 Signature Invalid" in e for e in error_msgs),
            "Tampered text must trigger 'TAMPERING DETECTED \u2013 Signature Invalid'."
        )

        orig_input_after_verify = [t for t in at.text_input if t.label == "Original HMAC Signature"][0]
        self.assertEqual(
            orig_input_after_verify.value,
            initial_sig,
            "Original HMAC Signature must not be replaced during verification."
        )

    def test_11_lockout_console_dynamic_target_users(self):
        """Verify Brute-Force Lockout Testing Console dynamically loads active registered users."""
        from security.authentication import register_user
        register_user("surya", "SuryaPass123!", "Surya Staff", "medical_staff")

        from streamlit.testing.v1 import AppTest

        at = AppTest.from_file(str(PROJECT_ROOT / "app.py"), default_timeout=30)
        at.run()

        # Switch to Admin persona so admin-only lockout testing console is active
        persona_select = [s for s in at.selectbox if "Persona" in s.label]
        if persona_select:
            admin_opt = [opt for opt in persona_select[0].options if "admin" in opt.lower()][0]
            persona_select[0].select(admin_opt).run()
            switch_btns = [b for b in at.button if "Apply Role Switch" in b.label]
            if switch_btns:
                switch_btns[0].click().run()

        # Switch to Authentication and RBAC Management
        nav_radio = [r for r in at.sidebar.radio if "Select Subsystem Page" in r.label][0]
        nav_radio.set_value("🛡️ Authentication and RBAC Management").run()

        # Locate Target Username selectbox
        target_boxes = [s for s in at.selectbox if s.label == "Target Username:"]
        self.assertTrue(len(target_boxes) > 0, "Target Username selectbox must exist.")

        target_box = target_boxes[0]
        options = target_box.options

        # Verify options are dynamically loaded from DB rather than hardcoded
        self.assertIn("surya", options, "Dynamically fetched users must include 'surya'.")
        self.assertIn("dr_smith", options, "Dynamically fetched users must include 'dr_smith'.")
        self.assertIn("admin", options, "Dynamically fetched users must include 'admin'.")

        # Verify selecting a user and attempting verification works
        target_box.select("surya").run()
        pwd_inputs = [t for t in at.text_input if t.label == "Enter Password:"]
        self.assertTrue(len(pwd_inputs) > 0)
        pwd_inputs[0].input("WrongPassword123!").run()

        submit_btns = [b for b in at.button if b.label == "Submit Login Attempt"]
        self.assertTrue(len(submit_btns) > 0)
        submit_btns[0].click().run()

        error_msgs = [e.value for e in at.error]
        self.assertTrue(
            any("Authentication Failed" in e for e in error_msgs),
            "Failed login attempt for selected target user must record authentication failure."
        )

    def test_12_session_inactivity_timeout_ui_simulation(self):
        """Verify Session Inactivity Timeout Testing console, simulation, expiration, and redirect."""
        from streamlit.testing.v1 import AppTest
        from database.database import get_security_events

        at = AppTest.from_file(str(PROJECT_ROOT / "app.py"), default_timeout=30)
        at.run()

        # Switch to Authentication and RBAC Management
        nav_radio = [r for r in at.sidebar.radio if "Select Subsystem Page" in r.label][0]
        nav_radio.set_value("🛡️ Authentication and RBAC Management").run()

        # Verify Configurable Timeout selectbox exists
        timeout_boxes = [s for s in at.selectbox if "Configurable Inactivity Timeout Duration" in s.label]
        self.assertTrue(len(timeout_boxes) > 0, "Configurable timeout selectbox must exist.")
        tb = timeout_boxes[0]
        self.assertTrue(any("1 Minute" in opt for opt in tb.options))
        self.assertTrue(any("2 Minutes" in opt for opt in tb.options))
        self.assertTrue(any("30 Minutes" in opt for opt in tb.options))

        # Test active renewal button
        renew_btns = [b for b in at.button if "Perform Authenticated Action (Renew)" in b.label]
        self.assertTrue(len(renew_btns) > 0, "Renewal button must exist.")
        renew_btns[0].click().run()
        self.assertTrue(at.session_state["authenticated"], "Session must remain authenticated after renewal.")

        # Test simulate inactivity & expire session
        expire_btns = [b for b in at.button if "Simulate Inactivity & Expire Session" in b.label]
        self.assertTrue(len(expire_btns) > 0, "Simulate Inactivity button must exist.")
        expire_btns[0].click().run()

        # Verify session is expired and redirected to login interface
        self.assertFalse(at.session_state.get("authenticated"), "Session must be unauthenticated after expiration.")
        error_msgs = [e.value for e in at.error]
        self.assertTrue(
            any("SESSION EXPIRED \u2013 Please authenticate again." in e for e in error_msgs),
            "Must display 'SESSION EXPIRED – Please authenticate again.' error message upon expiration."
        )

        # Verify SESSION_EXPIRED event recorded in SQLite
        expired_events = get_security_events(limit=5, event_type="SESSION_EXPIRED")
        self.assertGreaterEqual(len(expired_events), 1, "SESSION_EXPIRED event must be in SQLite database.")
        self.assertEqual(expired_events[0]["severity"], "WARNING")


if __name__ == "__main__":
    unittest.main()
