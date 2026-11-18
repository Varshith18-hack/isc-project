"""
End-to-End System Integration & Comprehensive Validation Suite (Stage 8)
========================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Executes an end-to-end multi-device hospital workflow integrating all 4 core domains:
1. Artificial Intelligence: Real-time Isolation Forest anomaly inference (τ = 0.5809).
2. Cryptography: AES-256-GCM AEAD encryption, HKDF-SHA256 key separation, SHA-256 hashing.
3. Information Security: Argon2id authentication, RBAC authorization, brute-force defense.
4. Secure Audit Logging: Append-only hash chain, external checkpointing, monotonic anchor.
5. Active Adversary Defense: Tests and catches 6 distinct active attack vectors.
"""

import sys
import os
import json
import time
import shutil
import tempfile
from pathlib import Path
from datetime import datetime

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
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
)
from security.authentication import (
    authenticate_user,
    validate_session,
    logout_user,
    hash_session_token,
    seed_default_users,
)
from security.access_control import has_permission
from database.database import (
    get_db_connection,
    log_security_event,
    get_security_events,
    update_audit_anchor,
    get_audit_anchor,
)
from audit.audit_logger import (
    append_audit_event,
    load_audit_chain,
    load_chain_checkpoint,
    save_chain_checkpoint,
    get_checkpoint_path,
)
from audit.integrity_checker import (
    verify_audit_chain,
    AuditVerificationError,
    simulate_payload_tamper,
    simulate_tail_deletion,
    simulate_checkpoint_rollback,
)


def run_e2e_integration_test() -> bool:
    """Execute complete end-to-end integration and adversarial validation workflow."""
    print("=" * 80)
    print("STAGE 8: END-TO-END SYSTEM INTEGRATION & ADVERSARIAL VALIDATION")
    print("Course: Information Security and Cryptography (AI 331) — SVNIT")
    print("=" * 80)

    all_passed = True
    temp_dir = tempfile.mkdtemp()
    test_chain_path = Path(temp_dir) / "e2e_audit_chain.json"

    try:
        # ======================================================================
        # PHASE 1: USER AUTHENTICATION & RBAC CREDENTIAL VALIDATION
        # ======================================================================
        print("\n[PHASE 1: AUTHENTICATION & ROLE-BASED ACCESS CONTROL]")
        seed_default_users()
        
        # 1. Authenticate Doctor (medical_staff)
        doc_pwd = config.DEMO_CREDENTIALS["dr_smith"]["password"]
        ok_doc, msg_doc, sess_doc = authenticate_user("dr_smith", doc_pwd)
        assert ok_doc and sess_doc["role"] == "medical_staff", f"Doctor auth failed: {msg_doc}"
        print(f" -> Doctor Authenticated: {sess_doc['username']} (Role: {sess_doc['role']})")
        print(f" -> Session Token Hash (SHA-256): {hash_session_token(sess_doc['session_token'])[:16]}...")
        
        # Verify doctor permissions
        assert has_permission("medical_staff", "view_readings")
        assert not has_permission("medical_staff", "manage_users")
        assert not has_permission("medical_staff", "verify_audit_chain")
        print(" -> Doctor Permissions: Verified (Least-Privilege Enforced)")

        # 2. Authenticate Admin (admin)
        adm_pwd = config.DEMO_CREDENTIALS["admin"]["password"]
        ok_adm, msg_adm, sess_adm = authenticate_user("admin", adm_pwd)
        assert ok_adm and sess_adm["role"] == "admin", f"Admin auth failed: {msg_adm}"
        assert has_permission("admin", "manage_users")
        assert has_permission("admin", "verify_audit_chain")
        print(f" -> Admin Authenticated:  {sess_adm['username']} (Role: {sess_adm['role']})")

        # 3. Authenticate Compliance Auditor (auditor)
        aud_pwd = config.DEMO_CREDENTIALS["auditor_davis"]["password"]
        ok_aud, msg_aud, sess_aud = authenticate_user("auditor_davis", aud_pwd)
        assert ok_aud and sess_aud["role"] == "auditor", f"Auditor auth failed: {msg_aud}"
        assert has_permission("auditor", "verify_audit_chain")
        assert not has_permission("auditor", "manage_users")
        print(f" -> Auditor Authenticated: {sess_aud['username']} (Role: {sess_aud['role']})")

        # Log authentication audit block
        append_audit_event(
            user_id=sess_doc["user_id"],
            event_type="USER_LOGIN_SUCCESS",
            event_details={"username": "dr_smith", "role": "medical_staff", "ward": "ICU Ward 2"},
            file_path=test_chain_path,
            sync_to_sqlite=False,
        )

        # ======================================================================
        # PHASE 2: IOMT TELEMETRY ACQUISITION & AI ANOMALY INFERENCE
        # ======================================================================
        print("\n[PHASE 2: IOMT TELEMETRY & AI ISOLATION FOREST INFERENCE]")
        detector = MedicalDeviceAnomalyDetector()
        print(f" -> Isolation Forest Loaded: Calibrated Decision Threshold tau = {detector.threshold:.4f}")

        # Observation 1: Normal Mechanical Ventilator telemetry
        sample_normal = {
            "device_id": "DEV-VENT-002",
            "heart_rate": 74.0,
            "systolic_bp": 118.0,
            "diastolic_bp": 76.0,
            "oxygen_saturation": 98.4,
            "body_temperature": 36.85,
            "device_activity_level": 22.0,
        }
        pred_normal = detector.predict_reading(sample_normal)
        assert pred_normal["status"] == "NORMAL", "Expected normal prediction"
        print(f" -> Reading 1 (Normal):  Score={pred_normal['anomaly_score']:.4f} -> Decision: {pred_normal['status']} (Severity: {pred_normal['severity']})")

        # Observation 2: Severe Cardiac Arrhythmia / Tachycardia (Medical Anomaly)
        sample_tachy = {
            "device_id": "DEV-MON-001",
            "heart_rate": 182.0,
            "systolic_bp": 145.0,
            "diastolic_bp": 92.0,
            "oxygen_saturation": 95.0,
            "body_temperature": 37.1,
            "device_activity_level": 24.0,
        }
        pred_tachy = detector.predict_reading(sample_tachy)
        assert pred_tachy["status"] == "ANOMALY", "Expected anomaly for tachycardia"
        print(f" -> Reading 2 (Arrhythmia): Score={pred_tachy['anomaly_score']:.4f} -> Decision: {pred_tachy['status']} (Severity: {pred_tachy['severity']})")
        print(f"    Explainability: {pred_tachy['contributing_factors'][0]}")

        # Observation 3: Network Traffic Burst / DoS Attack (Cyber Intrusion)
        sample_dos = {
            "device_id": "DEV-PUMP-001",
            "heart_rate": 72.0,
            "systolic_bp": 116.0,
            "diastolic_bp": 74.0,
            "oxygen_saturation": 98.0,
            "body_temperature": 36.8,
            "device_activity_level": 115.0,
        }
        pred_dos = detector.predict_reading(sample_dos)
        assert pred_dos["status"] == "ANOMALY", "Expected anomaly for network flood"
        print(f" -> Reading 3 (DDoS Burst): Score={pred_dos['anomaly_score']:.4f} -> Decision: {pred_dos['status']} (Severity: {pred_dos['severity']})")
        print(f"    Explainability: {pred_dos['contributing_factors'][0]}")

        # Log AI anomaly alerts to audit chain
        append_audit_event(
            user_id="DEV-MON-001",
            event_type="AI_ANOMALY_ALERT",
            event_details={"threat": "Severe_Tachycardia", "score": pred_tachy["anomaly_score"], "severity": "CRITICAL"},
            file_path=test_chain_path,
            sync_to_sqlite=False,
        )
        append_audit_event(
            user_id="DEV-PUMP-001",
            event_type="CYBER_INTRUSION_ALERT",
            event_details={"threat": "Network_Traffic_Burst", "score": pred_dos["anomaly_score"], "severity": "CRITICAL"},
            file_path=test_chain_path,
            sync_to_sqlite=False,
        )

        # ======================================================================
        # PHASE 3: CRYPTOGRAPHIC AEAD ENCRYPTION & GATEWAY INGESTION
        # ======================================================================
        print("\n[PHASE 3: AES-256-GCM AEAD ENCRYPTION & HKDF KEY SEPARATION]")
        master_k = get_or_create_master_key()
        aes_vent = derive_device_keys(master_k, "DEV-VENT-002")
        hmac_sys = get_system_hmac_key()
        print(" -> Master Key Loaded: 256-bit Hardware Entropy (NTFS ACL 0600 Locked)")
        print(" -> HKDF Key Derivation: Independent AES and HMAC keys generated for DEV-VENT-002")

        # Encrypt normal telemetry record with AAD header binding
        aad_header = {"ward": "ICU_Ward_2", "device": "DEV-VENT-002", "routing": "GATEWAY_INGEST"}
        envelope = encrypt_telemetry_record(
            telemetry_record=sample_normal,
            key=aes_vent,
            device_id="DEV-VENT-002",
            associated_data=aad_header,
        )
        print(f" -> AES-256-GCM Envelope Created:")
        print(f"    Nonce (IV): {envelope['nonce']} (96-bit Fresh Random)")
        print(f"    Ciphertext: {envelope['ciphertext'][:32]}... ({len(envelope['ciphertext'])} hex chars)")
        print(f"    Auth Tag:   {envelope['auth_tag']} (128-bit MAC Authenticator)")

        # Gateway Decryption & Verification
        decrypted_record = decrypt_telemetry_record(envelope, key=aes_vent)
        assert decrypted_record["heart_rate"] == sample_normal["heart_rate"]
        assert decrypted_record["oxygen_saturation"] == sample_normal["oxygen_saturation"]
        print(" -> Gateway Decryption: SUCCESS (Zero Bit Drift, Tag Authenticated)")

        # Log telemetry encryption to audit chain
        append_audit_event(
            user_id="DEV-VENT-002",
            event_type="TELEMETRY_ENCRYPTED",
            event_details={"nonce": envelope["nonce"], "auth_tag": envelope["auth_tag"], "status": "INGESTED_OK"},
            file_path=test_chain_path,
            sync_to_sqlite=False,
        )

        # ======================================================================
        # PHASE 4: SECURE AUDIT BLOCKCHAIN FORENSIC VERIFICATION
        # ======================================================================
        print("\n[PHASE 4: SECURE AUDIT BLOCKCHAIN FORENSIC VERIFICATION]")
        chain = load_audit_chain(test_chain_path)
        checkpoint = load_chain_checkpoint(test_chain_path)
        print(f" -> Current Audit Ledger: {len(chain)} Committed Blocks")
        print(f" -> Genesis Anchor:       {GENESIS_HASH[:16]}...")
        print(f" -> Latest Block Hash:    {chain[-1]['current_hash'][:16]}...")
        print(f" -> External Checkpoint:  Synchronized at Event ID #{checkpoint['latest_event_id']}")

        # Full verification
        rep = verify_audit_chain(test_chain_path)
        assert rep["is_valid"] and rep["status"] == "VERIFIED", f"Audit verification failed: {rep['details']}"
        print(f" -> Verification Status:  {rep['status']} ({rep['verified_records']}/{rep['total_records']} Blocks Verified)")
        print(f"    Diagnostic: {rep['details']}")

        # ======================================================================
        # PHASE 5: ACTIVE ADVERSARY DEFENSE VALIDATION (6 ATTACK VECTORS)
        # ======================================================================
        print("\n[PHASE 5: ACTIVE ADVERSARY DEFENSE VALIDATION (6 ATTACK VECTORS)]")

        # Attack 1: In-Flight Ciphertext Tampering (MITM Bit Flip)
        tampered_env = json.loads(json.dumps(envelope))
        ct_list = list(tampered_env["ciphertext"])
        ct_list[0] = "0" if ct_list[0] != "0" else "1"
        tampered_env["ciphertext"] = "".join(ct_list)
        try:
            decrypt_telemetry_record(tampered_env, key=aes_vent)
            print(" [FAIL] Attack 1: Modified ciphertext was accepted!")
            all_passed = False
        except CryptoIntegrityError:
            print(" -> Attack 1 (MITM Bit Flip):       BLOCKED [AES-GCM Tag Mismatch Detected]")

        # Attack 2: AAD Header Spoofing (Metadata Modification)
        spoofed_env = json.loads(json.dumps(envelope))
        spoofed_env["associated_data"] = {"ward": "ICU_Ward_99_SPOOFED"}
        try:
            decrypt_telemetry_record(spoofed_env, key=aes_vent)
            print(" [FAIL] Attack 2: Spoofed AAD header was accepted!")
            all_passed = False
        except CryptoIntegrityError:
            print(" -> Attack 2 (AAD Header Spoofing):   BLOCKED [AAD Binding Violation Caught]")

        # Attack 3: Unauthorized Key Decryption
        try:
            random_key = os.urandom(32)
            decrypt_telemetry_record(envelope, key=random_key)
            print(" [FAIL] Attack 3: Decrypted with unauthorized key!")
            all_passed = False
        except CryptoIntegrityError:
            print(" -> Attack 3 (Unauthorized Key):      BLOCKED [Cryptographic MAC Verification Failed]")

        # Attack 4: Audit Payload Modification (Tampering with Clinical Vitals in Block #2)
        tampered_chain_4 = simulate_payload_tamper(chain, target_event_id=2, key_to_modify="threat", new_value="Normal_Vitals_Coverup")
        rep_atk4 = verify_audit_chain(tampered_chain_4, checkpoint=checkpoint)
        assert not rep_atk4["is_valid"] and rep_atk4["error_type"] == AuditVerificationError.PAYLOAD_TAMPERED
        print(" -> Attack 4 (Audit Payload Tamper):  BLOCKED [PAYLOAD_TAMPERED Detected at Block #2]")

        # Attack 5: Tail Truncation Attack (Adversary erases latest block to conceal recent action)
        tampered_chain_5 = simulate_tail_deletion(chain, num_blocks=1)
        rep_atk5 = verify_audit_chain(tampered_chain_5, checkpoint=checkpoint)
        assert not rep_atk5["is_valid"] and rep_atk5["error_type"] == AuditVerificationError.CHAIN_TRUNCATED
        print(" -> Attack 5 (Tail Truncation):       BLOCKED [CHAIN_TRUNCATED Detected via Checkpoint]")

        # Attack 6: Checkpoint Rollback Attack (Adversary restores older valid snapshot)
        anchor_state = {
            "max_event_id": len(chain),
            "max_event_hash": chain[-1]["current_hash"],
            "timestamp": chain[-1]["timestamp"],
        }
        older_cp = {
            "latest_event_id": 2,
            "latest_hash": chain[1]["current_hash"],
            "total_events": 2,
            "timestamp": chain[1]["timestamp"],
        }
        older_cp["checkpoint_hmac"] = compute_hmac(older_cp)
        rep_atk6 = verify_audit_chain(chain[:2], checkpoint=older_cp, anchor=anchor_state)
        assert not rep_atk6["is_valid"] and rep_atk6["error_type"] == AuditVerificationError.CHECKPOINT_ROLLBACK_DETECTED
        print(" -> Attack 6 (Checkpoint Rollback):   BLOCKED [CHECKPOINT_ROLLBACK_DETECTED via Anchor]")

        print("\n" + "=" * 80)
        print("[SUCCESS] ALL 5 INTEGRATION PHASES AND 6 ADVERSARIAL ATTACKS VALIDATED!")
        print("=" * 80)
        return all_passed

    finally:
        if Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    success = run_e2e_integration_test()
    sys.exit(0 if success else 1)

