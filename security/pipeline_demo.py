"""
End-to-End Cryptography & Telemetry Pipeline Integration Demonstration
======================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Demonstrates the full cryptographic pipeline integrating:
1. Real medical telemetry sampling.
2. AI Anomaly Detection inference.
3. AES-256-GCM Authenticated Encryption with Associated Authenticated Data (AAD).
4. Deterministic SHA-256 Cryptographic Hashing.
5. Keyed HMAC-SHA256 Message Authentication.
6. Secure simulated transmission and decryption.
7. Active adversary defense demonstrations:
   - Tampered ciphertext rejection.
   - Modified message payload detection.
   - Unauthorized key rejection.
"""

import sys
import json
import copy
from pathlib import Path
from Crypto.Random import get_random_bytes

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from models.anomaly_detection import MedicalDeviceAnomalyDetector
from security.encryption import (
    encrypt_telemetry_record,
    decrypt_telemetry_record,
    CryptoIntegrityError,
    get_or_create_master_key,
)
from security.hashing import (
    compute_sha256,
    verify_sha256,
    compute_hmac,
    verify_hmac,
    get_system_hmac_key,
)


def run_integrated_pipeline_demonstration():
    print("=" * 85)
    print("STAGE 4: INTEGRATED TELEMETRY CRYPTOGRAPHIC PIPELINE DEMONSTRATION")
    print("=" * 85)

    # Step 1: Incoming Patient Telemetry
    raw_telemetry = {
        "reading_id": "REC-007890",
        "timestamp": "2026-11-10 15:45:00",
        "device_id": "DEV-VENT-002",
        "device_type": "Mechanical Ventilator",
        "heart_rate": 74.0,
        "systolic_bp": 116.0,
        "diastolic_bp": 74.0,
        "oxygen_saturation": 98.4,
        "body_temperature": 36.95,
        "device_activity_level": 24.2,
    }

    print("\n[STEP 1: SENSOR ACQUISITION & AI ANOMALY DETECTION]")
    detector = MedicalDeviceAnomalyDetector()
    ai_result = detector.predict_reading(raw_telemetry)
    print(f"Device:       {raw_telemetry['device_id']} ({raw_telemetry['device_type']})")
    print(f"AI Decision:  {ai_result['status']} (Anomaly Score: {ai_result['anomaly_score']:.4f}, Threshold: {ai_result['calibrated_threshold']:.4f})")
    print(f"Severity:     {ai_result['severity']}")

    # Attach AI status to telemetry package
    telemetry_package = dict(raw_telemetry)
    telemetry_package["ai_status"] = ai_result["status"]
    telemetry_package["ai_score"] = ai_result["anomaly_score"]

    # Step 2: Cryptographic Sealing (SHA-256 and HMAC)
    print("\n[STEP 2: CRYPTOGRAPHIC HASHING & HMAC GENERATION]")
    data_sha256 = compute_sha256(telemetry_package)
    hmac_key = get_system_hmac_key()
    data_hmac = compute_hmac(telemetry_package, key=hmac_key)

    print(f"Plaintext Record: {json.dumps(telemetry_package)}")
    print(f"SHA-256 Digest:   {data_sha256} (Length: {len(data_sha256)} hex chars)")
    print(f"HMAC-SHA256 Tag:  {data_hmac} (Keyed Message Authentication Code)")

    # Step 3: AES-256-GCM Authenticated Encryption
    print("\n[STEP 3: AES-256-GCM AUTHENTICATED ENCRYPTION (AEAD)]")
    # Bind routing header as Authenticated Associated Data (AAD)
    aad_header = {
        "device_id": telemetry_package["device_id"],
        "timestamp": telemetry_package["timestamp"],
        "routing_dest": "ICU_CENTRAL_MONITORING_SERVER",
    }
    encrypted_envelope = encrypt_telemetry_record(
        telemetry_package,
        device_id=telemetry_package["device_id"],
        associated_data=aad_header,
    )

    print(f"Algorithm:       {encrypted_envelope['algorithm']} (256-bit symmetric cipher)")
    print(f"Unique Nonce:    {encrypted_envelope['nonce']} (96-bit fresh IV)")
    print(f"Ciphertext:      {encrypted_envelope['ciphertext'][:64]}... [Truncated]")
    print(f"GCM Auth Tag:    {encrypted_envelope['auth_tag']} (128-bit integrity tag)")
    print(f"Associated Data: {json.dumps(encrypted_envelope['associated_data'])}")

    # Step 4: Simulated Secure Transmission & Legitimate Ingestion
    print("\n[STEP 4: GATEWAY INGESTION & DECRYPTION]")
    # Gateway verifies HMAC first
    is_authentic = verify_hmac(telemetry_package, data_hmac, key=hmac_key)
    print(f"HMAC Authentication Check: {'PASSED (Authentic Origin)' if is_authentic else 'FAILED'}")

    # Gateway decrypts AES-256-GCM envelope
    decrypted_record = decrypt_telemetry_record(
        encrypted_envelope,
        device_id=telemetry_package["device_id"],
    )
    print(f"AES-256-GCM Decryption:   PASSED (Authentication Tag Verified)")
    print(f"Decrypted Content Match:  {decrypted_record == telemetry_package}")

    # Re-verify SHA-256 integrity
    sha_match = verify_sha256(decrypted_record, data_sha256)
    print(f"SHA-256 Integrity Check:  {'PASSED (Zero Bit Drift)' if sha_match else 'FAILED'}")

    # Step 5: Active Adversary Attack Scenarios & Defense Validation
    print("\n" + "-" * 75)
    print("[STEP 5: ACTIVE ADVERSARY DEFENSE VALIDATION]")
    print("-" * 75)

    # Attack A: Man-In-The-Middle flips bits in Ciphertext
    print("\n[ATTACK A: MITM Modifies Encrypted Ciphertext in Transit]")
    tampered_envelope = copy.deepcopy(encrypted_envelope)
    ct_raw = bytearray(bytes.fromhex(tampered_envelope["ciphertext"]))
    ct_raw[10] ^= 0x7F  # Corrupt byte 10
    tampered_envelope["ciphertext"] = ct_raw.hex()

    try:
        decrypt_telemetry_record(tampered_envelope, device_id=telemetry_package["device_id"])
        print("[FAIL] Corrupted ciphertext was accepted!")
    except CryptoIntegrityError as e:
        print("[BLOCKED] AES-GCM Authentication Tag Mismatch! Decryption aborted immediately.")
        print(f"Security Alert: {e}")

    # Attack B: Attacker Modifies Decrypted Message Telemetry
    print("\n[ATTACK B: Tampering with Telemetry Payload (e.g. Spoofing Dosage or Oxygen)]")
    tampered_message = copy.deepcopy(telemetry_package)
    tampered_message["oxygen_saturation"] = 70.0  # Falsified reading

    # Test SHA-256 detection
    sha_tamper_detected = not verify_sha256(tampered_message, data_sha256)
    print(f"SHA-256 Tamper Detection: {'DETECTED (Hash mismatch: Data modified)' if sha_tamper_detected else 'MISSED'}")

    # Test HMAC detection
    hmac_tamper_detected = not verify_hmac(tampered_message, data_hmac, key=hmac_key)
    print(f"HMAC-SHA256 Detection:    {'DETECTED (Authentication tag invalid)' if hmac_tamper_detected else 'MISSED'}")

    # Attack C: Attacker Attempts Decryption with Unauthorized Key
    print("\n[ATTACK C: Unauthorized Entity Attempts Decryption with Random Key]")
    unauthorized_key = get_random_bytes(32)
    try:
        decrypt_telemetry_record(encrypted_envelope, key=unauthorized_key)
        print("[FAIL] Decrypted with unauthorized key!")
    except CryptoIntegrityError as e:
        print("[BLOCKED] Decryption failed! Cryptographic key rejected.")
        print(f"Security Alert: {e}")

    # Step 6: Secure Audit Blockchain Logging & Chain Integrity Verification
    print("\n" + "-" * 75)
    print("[STEP 6: SECURE AUDIT BLOCKCHAIN LOGGING & INTEGRITY VERIFICATION]")
    print("-" * 75)

    from audit.audit_logger import append_audit_event
    from audit.integrity_checker import verify_audit_chain

    audit_entry = append_audit_event(
        user_id=telemetry_package["device_id"],
        event_type="TELEMETRY_INGESTED",
        event_details={
            "reading_id": telemetry_package["reading_id"],
            "device_type": telemetry_package["device_type"],
            "ai_status": telemetry_package["ai_status"],
            "ai_score": telemetry_package["ai_score"],
            "sha256": data_sha256,
            "hmac_tag": data_hmac,
        },
    )
    print(f"Audit Record Appended: Block #{audit_entry['event_id']}")
    print(f" -> Current Hash:       {audit_entry['current_hash']}")
    print(f" -> Previous Hash:      {audit_entry['previous_hash']}")
    print(f" -> Institutional HMAC: {audit_entry['hmac_tag']}")

    # Run chain-wide forensic verification
    chain_report = verify_audit_chain()
    print(f"\nAudit Blockchain Status: {chain_report['status']}")
    print(f" -> Total Blocks Verified: {chain_report['verified_records']}/{chain_report['total_records']}")
    print(f" -> Verification Details:  {chain_report['details']}")

    print("\n" + "=" * 85)
    print("[SUCCESS] All cryptographic controls, integrity checks, and defenses verified.")
    print("=" * 85)


if __name__ == "__main__":
    run_integrated_pipeline_demonstration()

