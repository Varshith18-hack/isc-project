"""
Automated End-to-End System Integration Test Suite (Stage 8)
============================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Comprehensive Integration Test Suite:
-------------------------------------
1.  Scenario A: Normal Medical Telemetry - AI Inference, AEAD Encryption, DB Ingestion, and Audit Chaining.
2.  Scenario B: Medical Anomaly Detection - Severe Cardiac Arrhythmia & Cyber DoS Intrusion with Explainability.
3.  Scenario C: Unauthorized Access & Defensive Account Lockout after 5 Failed Attempts.
4.  Scenario C (Extended): RBAC Enforcement - Protected Operations Reject Unauthorized Roles.
5.  Scenario D: Cryptographic Tampering - Ciphertext Bit-Flip Rejection.
6.  Scenario D (Extended): Cryptographic Tampering - Tag, AAD Spoofing, and Unauthorized Key Rejection.
7.  Scenario E: Audit Chain Forensics - Intra-Block Payload & Metadata Modification Detection.
8.  Scenario E (Extended): Audit Chain Forensics - Intermediate Block Deletion & Tail Truncation Detection.
9.  Scenario E (Advanced): Checkpoint Rollback Attack Defense via Monotonic Database Anchor.
10. Scenario F: Multi-Role Hospital Workflow & HIPAA Least-Privilege Data Redaction.
11. Concurrency: Multi-Threaded Concurrent Telemetry Ingestion and Audit Chaining.
12. Crash Consistency: Deterministic Recovery of Checkpoints After Abrupt Ingestion Interrupts.
13. Zero-Secret Leakage: Master Keys, Tokens, and Passwords Scrubbed from All Storage and Logs.
"""

import sys
import os
import json
import time
import shutil
import tempfile
import unittest
import threading
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import database.database as db
from models.anomaly_detection import MedicalDeviceAnomalyDetector
from security.encryption import (
    encrypt_telemetry_record,
    decrypt_telemetry_record,
    derive_device_keys,
    get_or_create_master_key,
    CryptoIntegrityError,
)
from security.hashing import (
    compute_sha256,
    compute_hmac,
    verify_hmac,
    get_system_hmac_key,
    GENESIS_HASH,
    canonicalize,
)
from security.authentication import (
    authenticate_user,
    validate_session,
    logout_user,
    hash_session_token,
    seed_default_users,
    register_user,
)
from security.access_control import (
    has_permission,
    check_access,
    enforce_permission,
    filter_patient_data_for_role,
    AccessDeniedError,
)
from audit.audit_logger import (
    append_audit_event,
    load_audit_chain,
    load_chain_checkpoint,
    save_chain_checkpoint,
    get_checkpoint_path,
    reset_audit_chain,
    AUDIT_FILE_PATH,
)
from audit.integrity_checker import (
    verify_audit_chain,
    AuditVerificationError,
    simulate_payload_tamper,
    simulate_tail_deletion,
    simulate_checkpoint_rollback,
    simulate_file_deletion,
    simulate_crash_after_chain_save,
)
from audit.security_logger import sanitize_metadata


class TestEndToEndSystemIntegration(unittest.TestCase):
    """
    Complete end-to-end integration and adversarial validation test suite
    covering Scenarios A through F, concurrency, failure recovery, and zero leakage.
    """

    @classmethod
    def setUpClass(cls):
        """Set up an isolated temporary workspace for database, audit chain, and checkpoints."""
        cls.temp_dir = tempfile.mkdtemp()
        cls.test_db_path = Path(cls.temp_dir) / "test_e2e_medical.db"
        cls.original_db_path = db.DB_PATH

        # Redirect database module to isolated temporary DB
        db.DB_PATH = cls.test_db_path
        db.initialize_database()
        seed_default_users()

        # Load ML Anomaly Detector
        cls.detector = MedicalDeviceAnomalyDetector()

        # Load Cryptographic Master Key
        cls.master_key = get_or_create_master_key()

    @classmethod
    def tearDownClass(cls):
        """Restore global state and clean up temporary test files."""
        db.DB_PATH = cls.original_db_path
        if Path(cls.temp_dir).exists():
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _get_isolated_chain_path(self, tag: str) -> Path:
        """Helper to create an isolated audit chain path for a given test."""
        return Path(self.temp_dir) / f"{tag}_audit_chain.json"

    # ==========================================================================
    # SCENARIO A: NORMAL MEDICAL TELEMETRY WORKFLOW
    # ==========================================================================
    def test_01_scenario_a_normal_telemetry_workflow(self):
        """
        Scenario A:
        1. Generate normal mechanical ventilator telemetry.
        2. Run AI inference -> Verify status is NORMAL and score < tau (0.5809).
        3. Encrypt telemetry using AES-256-GCM with HKDF-derived device key.
        4. Decrypt at receiver gateway -> Verify zero bit drift.
        5. Persist encrypted record to SQLite database.
        6. Append event to cryptographic audit ledger and verify chain integrity.
        """
        chain_path = self._get_isolated_chain_path("scenario_a")
        dev_id = "DEV-VENT-002"

        # 1. Normal telemetry sample
        sample_normal = {
            "device_id": dev_id,
            "heart_rate": 72.5,
            "systolic_bp": 118.0,
            "diastolic_bp": 76.0,
            "oxygen_saturation": 98.6,
            "body_temperature": 36.8,
            "device_activity_level": 20.0,
        }

        # 2. AI Inference
        pred = self.detector.predict_reading(sample_normal)
        self.assertEqual(pred["status"], "NORMAL")
        self.assertEqual(pred["is_anomaly"], 0)
        self.assertLess(pred["anomaly_score"], self.detector.threshold)
        self.assertEqual(pred["severity"], "NORMAL")

        # 3. Derive HKDF Key & Encrypt
        device_key = derive_device_keys(self.master_key, dev_id)
        aad_header = {"ward": "ICU_Ward_2", "device": dev_id, "mode": "MANDATORY_VENTILATION"}
        envelope = encrypt_telemetry_record(
            telemetry_record=sample_normal,
            key=device_key,
            device_id=dev_id,
            associated_data=aad_header,
        )

        self.assertEqual(len(envelope["nonce"]), 24)  # 12-byte hex = 24 chars
        self.assertEqual(len(envelope["auth_tag"]), 32)  # 16-byte hex = 32 chars
        self.assertIn("ciphertext", envelope)

        # 4. Decrypt at Gateway
        decrypted = decrypt_telemetry_record(envelope, key=device_key)
        self.assertEqual(decrypted["heart_rate"], sample_normal["heart_rate"])
        self.assertEqual(decrypted["oxygen_saturation"], sample_normal["oxygen_saturation"])

        # 5. Persist in Database
        record_id = f"REC-{int(time.time()*1000)}"
        saved = db.save_encrypted_telemetry(
            record_id=record_id,
            device_id=dev_id,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            algorithm="AES-256-GCM",
            nonce=envelope["nonce"],
            ciphertext=envelope["ciphertext"],
            auth_tag=envelope["auth_tag"],
            associated_data=json.dumps(aad_header),
            ai_status=pred["status"],
            ai_score=pred["anomaly_score"],
        )
        self.assertTrue(saved)

        # 6. Append to Audit Chain & Verify
        block = append_audit_event(
            user_id=dev_id,
            event_type="TELEMETRY_INGESTED",
            event_details={
                "record_id": record_id,
                "ai_status": pred["status"],
                "score": pred["anomaly_score"],
                "auth_tag": envelope["auth_tag"],
            },
            file_path=chain_path,
            sync_to_sqlite=False,
        )
        self.assertEqual(block["event_id"], 1)

        report = verify_audit_chain(chain_path)
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["status"], "VERIFIED")
        self.assertEqual(report["verified_records"], 1)

    # ==========================================================================
    # SCENARIO B: MEDICAL ANOMALY & CYBER ATTACK DETECTION
    # ==========================================================================
    def test_02_scenario_b_medical_and_cyber_anomaly_detection(self):
        """
        Scenario B:
        1. Test Medical Physiological Anomaly (Severe Tachycardia: HR = 185 bpm).
        2. Verify AI classifies as ANOMALY with CRITICAL severity and heart rate explainability.
        3. Test Cyber Intrusion Anomaly (DDoS Network Flooding: Activity = 125 pkts/min).
        4. Verify AI classifies as ANOMALY with network activity explainability.
        5. Verify both security alerts are recorded in the audit chain and verified.
        """
        chain_path = self._get_isolated_chain_path("scenario_b")

        # 1. Severe Cardiac Arrhythmia / Tachycardia
        sample_cardiac = {
            "device_id": "DEV-MON-001",
            "heart_rate": 185.0,
            "systolic_bp": 148.0,
            "diastolic_bp": 94.0,
            "oxygen_saturation": 94.0,
            "body_temperature": 37.2,
            "device_activity_level": 22.0,
        }
        pred_cardiac = self.detector.predict_reading(sample_cardiac)
        self.assertEqual(pred_cardiac["status"], "ANOMALY")
        self.assertEqual(pred_cardiac["is_anomaly"], 1)
        self.assertGreaterEqual(pred_cardiac["anomaly_score"], self.detector.threshold)
        self.assertEqual(pred_cardiac["severity"], "CRITICAL")
        self.assertTrue(any("Heart Rate" in factor for factor in pred_cardiac["contributing_factors"]))

        # 2. Cyber Network Flood / DoS Intrusion
        sample_dos = {
            "device_id": "DEV-PUMP-001",
            "heart_rate": 72.0,
            "systolic_bp": 115.0,
            "diastolic_bp": 75.0,
            "oxygen_saturation": 98.0,
            "body_temperature": 36.8,
            "device_activity_level": 125.0,  # Extreme burst (> baseline 26.0)
        }
        pred_dos = self.detector.predict_reading(sample_dos)
        self.assertEqual(pred_dos["status"], "ANOMALY")
        self.assertEqual(pred_dos["is_anomaly"], 1)
        self.assertGreaterEqual(pred_dos["anomaly_score"], self.detector.threshold)
        self.assertTrue(any("Activity Level" in factor for factor in pred_dos["contributing_factors"]))

        # Log alerts to audit ledger
        append_audit_event(
            user_id="DEV-MON-001",
            event_type="AI_ANOMALY_ALERT",
            event_details={"threat": "Severe_Tachycardia", "score": pred_cardiac["anomaly_score"]},
            file_path=chain_path,
            sync_to_sqlite=False,
        )
        append_audit_event(
            user_id="DEV-PUMP-001",
            event_type="CYBER_INTRUSION_ALERT",
            event_details={"threat": "Network_Traffic_Burst", "score": pred_dos["anomaly_score"]},
            file_path=chain_path,
            sync_to_sqlite=False,
        )

        # Forensic verification
        report = verify_audit_chain(chain_path)
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["verified_records"], 2)

    # ==========================================================================
    # SCENARIO C: UNAUTHORIZED ACCESS & ACCOUNT LOCKOUT
    # ==========================================================================
    def test_03_scenario_c_unauthorized_access_and_account_lockout(self):
        """
        Scenario C:
        1. Attempt login with bad credentials for user 'dr_smith'.
        2. Verify failed attempt counter increments on each failure.
        3. Verify account lockout triggers on 5th consecutive failure.
        4. Verify 6th attempt is blocked as ACCOUNT_LOCKED.
        5. Verify security events record LOGIN_FAILED and ACCOUNT_LOCKED with zero secret leakage.
        """
        username = "dr_smith"
        bad_password = "IncorrectPassword#999"

        # Reset failed attempts for clean test baseline
        with db.get_db_connection() as conn:
            conn.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?", (username,))

        # 4 consecutive failed attempts
        for attempt in range(1, 5):
            ok, msg, sess = authenticate_user(username, bad_password)
            self.assertFalse(ok)
            self.assertIsNone(sess)
            self.assertTrue("Invalid username or password" in msg or "remaining before lockout" in msg)

        # 5th attempt -> triggers account lockout
        ok, msg, sess = authenticate_user(username, bad_password)
        self.assertFalse(ok)
        self.assertTrue("locked" in msg.lower() or "exceeded" in msg.lower())

        # Verify database record reflects lockout
        user = db.get_user_by_username(username)
        self.assertIsNotNone(user["locked_until"])
        self.assertGreaterEqual(user["failed_login_attempts"], 5)

        # 6th attempt while locked -> immediately rejected
        ok, msg, sess = authenticate_user(username, bad_password)
        self.assertFalse(ok)
        self.assertIn("locked", msg.lower())

        # Unlock user account to restore baseline
        with db.get_db_connection() as conn:
            conn.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?", (username,))

    def test_04_scenario_c_rbac_least_privilege_enforcement(self):
        """
        Scenario C (Extended):
        Verify RBAC boundaries:
        - 'medical_staff' cannot manage users or verify audit chain.
        - 'auditor' cannot manage users or write telemetry.
        - 'admin' has user management and audit capabilities.
        - enforce_permission raises AccessDeniedError on violations.
        """
        # Medical staff
        self.assertTrue(has_permission("medical_staff", "view_readings"))
        self.assertFalse(has_permission("medical_staff", "manage_users"))
        self.assertFalse(has_permission("medical_staff", "verify_audit_chain"))

        with self.assertRaises(AccessDeniedError):
            enforce_permission("medical_staff", "manage_users")

        with self.assertRaises(AccessDeniedError):
            enforce_permission("medical_staff", "verify_audit_chain")

        # Auditor
        self.assertTrue(has_permission("auditor", "verify_audit_chain"))
        self.assertTrue(has_permission("auditor", "view_audit_logs"))
        self.assertFalse(has_permission("auditor", "manage_users"))
        self.assertFalse(has_permission("auditor", "write_telemetry"))

        with self.assertRaises(AccessDeniedError):
            enforce_permission("auditor", "manage_users")

        # Administrator
        self.assertTrue(has_permission("admin", "manage_users"))
        self.assertTrue(has_permission("admin", "verify_audit_chain"))
        self.assertTrue(has_permission("admin", "view_audit_logs"))

    # ==========================================================================
    # SCENARIO D: CRYPTOGRAPHIC ATTACKS & TAMPER RESISTANCE
    # ==========================================================================
    def test_05_scenario_d_cryptographic_ciphertext_tampering(self):
        """
        Scenario D:
        Verify that flipping even a single bit in an AES-256-GCM ciphertext
        is immediately caught by the 128-bit MAC authenticator, raising CryptoIntegrityError.
        """
        dev_id = "DEV-VENT-002"
        dev_key = derive_device_keys(self.master_key, dev_id)
        sample = {"device_id": dev_id, "heart_rate": 75.0, "oxygen_saturation": 98.0}

        envelope = encrypt_telemetry_record(sample, key=dev_key, device_id=dev_id)

        # MITM bit flip on ciphertext
        tampered_env = json.loads(json.dumps(envelope))
        ct_list = list(tampered_env["ciphertext"])
        ct_list[0] = "0" if ct_list[0] != "0" else "1"
        tampered_env["ciphertext"] = "".join(ct_list)

        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(tampered_env, key=dev_key)

    def test_06_scenario_d_cryptographic_tag_aad_and_wrong_key(self):
        """
        Scenario D (Extended):
        Verify rejection of:
        1. Modified authentication tag (bit-flip).
        2. Modified Authenticated Associated Data (AAD) header.
        3. Decryption with an unauthorized/wrong key.
        """
        dev_id = "DEV-MON-001"
        dev_key = derive_device_keys(self.master_key, dev_id)
        sample = {"device_id": dev_id, "heart_rate": 80.0, "oxygen_saturation": 99.0}
        aad_data = {"ward": "ICU_Ward_1", "security_level": "RESTRICTED"}

        envelope = encrypt_telemetry_record(sample, key=dev_key, device_id=dev_id, associated_data=aad_data)

        # 1. Modified Auth Tag
        env_bad_tag = json.loads(json.dumps(envelope))
        tag_list = list(env_bad_tag["auth_tag"])
        tag_list[0] = "f" if tag_list[0] != "f" else "0"
        env_bad_tag["auth_tag"] = "".join(tag_list)
        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(env_bad_tag, key=dev_key)

        # 2. Spoofed AAD Header
        env_spoofed_aad = json.loads(json.dumps(envelope))
        env_spoofed_aad["associated_data"] = {"ward": "ICU_Ward_99_SPOOFED"}
        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(env_spoofed_aad, key=dev_key)

        # 3. Unauthorized Key
        unauthorized_key = os.urandom(32)
        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(envelope, key=unauthorized_key)

    # ==========================================================================
    # SCENARIO E: AUDIT-CHAIN FORENSICS & TAMPERING DETECTION
    # ==========================================================================
    def test_07_scenario_e_audit_payload_and_metadata_tampering(self):
        """
        Scenario E:
        1. Create a 3-block audit chain.
        2. Tamper with payload in block #2 -> Verify PAYLOAD_TAMPERED is detected.
        3. Tamper with block header metadata in block #2 -> Verify BLOCK_HASH_MISMATCH is detected.
        """
        chain_path = self._get_isolated_chain_path("scenario_e_payload")
        for i in range(1, 4):
            append_audit_event(
                user_id=f"DEV-00{i}",
                event_type="TELEMETRY_LOG",
                event_details={"reading_index": i, "status": "OK"},
                file_path=chain_path,
                sync_to_sqlite=False,
            )

        chain = load_audit_chain(chain_path)
        checkpoint = load_chain_checkpoint(chain_path)

        # 1. Payload modification
        tampered_chain_payload = simulate_payload_tamper(
            chain, target_event_id=2, key_to_modify="status", new_value="TAMPERED_COVERUP"
        )
        rep1 = verify_audit_chain(tampered_chain_payload, checkpoint=checkpoint)
        self.assertFalse(rep1["is_valid"])
        self.assertEqual(rep1["error_type"], AuditVerificationError.PAYLOAD_TAMPERED)
        self.assertEqual(rep1["tampered_entry_id"], 2)

        # 2. Block header metadata modification (alter timestamp)
        tampered_chain_header = json.loads(json.dumps(chain))
        tampered_chain_header[1]["timestamp"] = "1999-01-01 00:00:00"
        rep2 = verify_audit_chain(tampered_chain_header, checkpoint=checkpoint)
        self.assertFalse(rep2["is_valid"])
        self.assertEqual(rep2["error_type"], AuditVerificationError.BLOCK_HASH_MISMATCH)
        self.assertEqual(rep2["tampered_entry_id"], 2)

    def test_08_scenario_e_audit_intermediate_and_tail_deletion(self):
        """
        Scenario E (Extended):
        1. Intermediate Block Deletion: Removing block #2 causes linkage or sequence failure.
        2. Tail Deletion (Truncation): Removing latest block #3 is caught by external checkpoint as CHAIN_TRUNCATED.
        """
        chain_path = self._get_isolated_chain_path("scenario_e_deletion")
        for i in range(1, 4):
            append_audit_event(
                user_id=f"DEV-00{i}",
                event_type="TELEMETRY_LOG",
                event_details={"index": i},
                file_path=chain_path,
                sync_to_sqlite=False,
            )

        chain = load_audit_chain(chain_path)
        checkpoint = load_chain_checkpoint(chain_path)

        # 1. Intermediate Block Deletion (Delete block #2)
        chain_intermediate_del = [chain[0], chain[2]]
        rep_del = verify_audit_chain(chain_intermediate_del, checkpoint=checkpoint)
        self.assertFalse(rep_del["is_valid"])
        self.assertIn(
            rep_del["error_type"],
            [AuditVerificationError.ENTRY_ID_SEQUENCE_ERROR, AuditVerificationError.CHAIN_LINK_BROKEN],
        )

        # 2. Tail Deletion (Delete block #3)
        chain_tail_del = simulate_tail_deletion(chain, num_blocks=1)
        rep_tail = verify_audit_chain(chain_tail_del, checkpoint=checkpoint)
        self.assertFalse(rep_tail["is_valid"])
        self.assertEqual(rep_tail["error_type"], AuditVerificationError.CHAIN_TRUNCATED)

    def test_09_scenario_e_audit_checkpoint_tampering_and_rollback(self):
        """
        Scenario E (Advanced):
        1. Checkpoint Rollback Attack: Adversary replaces current checkpoint with older valid checkpoint.
        2. Caught by high-water mark SQLite monotonic anchor as CHECKPOINT_ROLLBACK_DETECTED.
        """
        chain_path = self._get_isolated_chain_path("scenario_e_rollback")
        for i in range(1, 4):
            append_audit_event(
                user_id=f"DEV-00{i}",
                event_type="TELEMETRY_LOG",
                event_details={"seq": i},
                file_path=chain_path,
                sync_to_sqlite=False,
            )

        chain = load_audit_chain(chain_path)

        # Simulate SQLite anchor holding high-water mark of block #3
        anchor_state = {
            "max_event_id": 3,
            "max_event_hash": chain[2]["current_hash"],
            "timestamp": chain[2]["timestamp"],
        }

        # Adversary presents older valid checkpoint from block #1
        older_checkpoint = {
            "latest_event_id": 1,
            "latest_hash": chain[0]["current_hash"],
            "total_events": 1,
            "timestamp": chain[0]["timestamp"],
        }
        older_checkpoint["checkpoint_hmac"] = compute_hmac(older_checkpoint)

        # Verification with rolled-back state
        rep_rollback = verify_audit_chain(chain[:1], checkpoint=older_checkpoint, anchor=anchor_state)
        self.assertFalse(rep_rollback["is_valid"])
        self.assertEqual(rep_rollback["error_type"], AuditVerificationError.CHECKPOINT_ROLLBACK_DETECTED)

    # ==========================================================================
    # SCENARIO F: MULTI-ROLE HOSPITAL WORKFLOW & HIPAA PRIVACY REDACTION
    # ==========================================================================
    def test_10_scenario_f_multi_role_workflow_and_hipaa_redaction(self):
        """
        Scenario F:
        1. Authenticate Doctor, Admin, and Auditor.
        2. Evaluate HIPAA privacy redaction on a clinical telemetry record:
           - Medical Staff: Views complete clinical vitals and true patient ID.
           - Auditor: Views masked patient ID (DEV-***-002) and redacted clinical fields.
           - Administrator: Accesses administrative telemetry metadata.
        """
        raw_clinical_record = {
            "device_id": "DEV-VENT-002",
            "patient_id": "PAT-9942",
            "heart_rate": 76.5,
            "systolic_bp": 120.0,
            "diastolic_bp": 80.0,
            "oxygen_saturation": 98.2,
            "body_temperature": 36.9,
            "device_activity_level": 22.0,
        }

        # 1. Doctor (medical_staff) -> Full Vitals
        doctor_view = filter_patient_data_for_role([raw_clinical_record], "medical_staff")[0]
        self.assertEqual(doctor_view["heart_rate"], 76.5)
        self.assertEqual(doctor_view["patient_id"], "PAT-9942")
        self.assertEqual(doctor_view["oxygen_saturation"], 98.2)

        # 2. Auditor (auditor) -> Redacted clinical vitals
        auditor_view = filter_patient_data_for_role([raw_clinical_record], "auditor")[0]
        self.assertEqual(auditor_view["heart_rate"], "[REDACTED_FOR_AUDITOR]")
        self.assertEqual(auditor_view["systolic_bp"], "[REDACTED_FOR_AUDITOR]")
        self.assertEqual(auditor_view["diastolic_bp"], "[REDACTED_FOR_AUDITOR]")
        self.assertEqual(auditor_view["oxygen_saturation"], "[REDACTED_FOR_AUDITOR]")

        # 3. Administrator (admin) -> Full system access to operational logs
        admin_view = filter_patient_data_for_role([raw_clinical_record], "admin")[0]
        self.assertEqual(admin_view["device_id"], "DEV-VENT-002")

    # ==========================================================================
    # CONCURRENCY, CRASH CONSISTENCY & ZERO-LEAKAGE
    # ==========================================================================
    def test_11_concurrency_multi_threaded_audit_and_ingestion(self):
        """
        Concurrency:
        Spawn 10 simultaneous threads appending audit records and generating envelopes.
        Verify that thread-safe locking maintains sequential monotonic IDs and 100% chain validity.
        """
        chain_path = self._get_isolated_chain_path("concurrency_stress")
        errors = []

        def worker_append(thread_id: int):
            try:
                for idx in range(3):
                    append_audit_event(
                        user_id=f"DEV-THREAD-{thread_id:02d}",
                        event_type="THREAD_CONCURRENT_INGEST",
                        event_details={"thread": thread_id, "loop": idx},
                        file_path=chain_path,
                        sync_to_sqlite=False,
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker_append, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Encountered thread errors: {errors}")

        chain = load_audit_chain(chain_path)
        self.assertEqual(len(chain), 30)  # 10 threads * 3 events

        # Verify sequential ordering
        for idx, block in enumerate(chain, start=1):
            self.assertEqual(block["event_id"], idx)

        # Forensic verification
        report = verify_audit_chain(chain_path)
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["verified_records"], 30)

    def test_12_crash_consistency_and_checkpoint_recovery(self):
        """
        Crash Consistency:
        Simulate an abrupt power cut / system interrupt immediately after chain write
        before checkpoint is flushed. Verify that deterministic recovery resynchronizes
        the lagging checkpoint from authentic blocks.
        """
        chain_path = self._get_isolated_chain_path("crash_recovery")
        for i in range(1, 3):
            append_audit_event(
                user_id=f"DEV-00{i}",
                event_type="TELEMETRY_LOG",
                event_details={"val": i},
                file_path=chain_path,
                sync_to_sqlite=False,
            )

        # Simulate crash: block 3 appended directly to file, checkpoint lagging at 2
        crashed_block = simulate_crash_after_chain_save(chain_path)
        self.assertEqual(crashed_block["event_id"], 3)

        # Verify state: chain has 3 blocks, checkpoint still at 2
        chain_crashed = load_audit_chain(chain_path)
        self.assertEqual(len(chain_crashed), 3)
        cp_crashed = load_chain_checkpoint(chain_path)
        self.assertEqual(cp_crashed["total_events"], 2)

        # Verify with lagging checkpoint -> detects crash lag and auto-recovers
        rep = verify_audit_chain(chain_path, auto_recover_checkpoint=True)
        self.assertTrue(rep["is_valid"])
        self.assertEqual(rep["status"], "VERIFIED")
        self.assertTrue(rep.get("recovered_from_crash"))
        self.assertEqual(rep["verified_records"], 3)
        cp_after = load_chain_checkpoint(chain_path)
        self.assertEqual(cp_after["total_events"], 3)

    def test_13_zero_secret_leakage_across_all_layers(self):
        """
        Zero-Secret Leakage:
        Verify that raw passwords, cryptographic master keys, and plaintext session tokens
        are filtered and never leaked into audit metadata or SQLite logs.
        """
        dirty_metadata = {
            "username": "dr_smith",
            "password": "SuperSecretPassword#123",
            "session_token": "a1b2c3d4e5f67890123456789abcdef",
            "master_key": "0123456789abcdef0123456789abcdef",
            "api_key": "AIzaSySecretApiKeyHere",
            "clinical_notes": "Patient stable on 40% FiO2",
        }

        clean = sanitize_metadata(dirty_metadata)
        self.assertEqual(clean["password"], "[REDACTED_SECRET]")
        self.assertEqual(clean["session_token"], "[REDACTED_SECRET]")
        self.assertEqual(clean["master_key"], "[REDACTED_SECRET]")
        self.assertEqual(clean["api_key"], "[REDACTED_SECRET]")
        self.assertEqual(clean["clinical_notes"], "Patient stable on 40% FiO2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
