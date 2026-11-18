"""
Automated Test Suite for Secure Audit System & Hash-Chain Integrity (Stages 6 & 6.1)
=====================================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Comprehensive Test Suite (24 Tests):
------------------------------------
1.  Genesis block initialization and initial chain state.
2.  Sequential monotonic event ID increment.
3.  Cryptographic previous-hash linkage across records.
4.  Intra-block payload SHA-256 integrity verification.
5.  Block header current_hash computation.
6.  Institutional HMAC-SHA256 signature verification.
7.  Clean untampered blockchain forensic verification.
8.  Empty audit log chain handling.
9.  Adversarial Test: Detection of intra-block payload tampering.
10. Adversarial Test: Detection of block header metadata tampering.
11. Adversarial Test: Detection of block deletion (covering tracks).
12. Adversarial Test: Detection of block reordering (chronological tampering).
13. Adversarial Test: Detection of rogue block insertion.
14. Adversarial Test: Detection of forged HMAC signature.
15. Adversarial Test: Detection of invalid initial Genesis state.
16. Zero secret leakage policy: automatic sanitization of sensitive fields.
17. Concurrency & thread safety of atomic chain writes.
18. RBAC protection: verify audit log access restricted to admin and auditor.
19. Adversarial Test (6.1): Detection of complete audit log file deletion via external checkpoint.
20. Adversarial Test (6.1): Detection of single-block tail deletion (chain truncation).
21. Adversarial Test (6.1): Detection of multi-block tail deletion (chain truncation).
22. Adversarial Test (6.1): Detection of external checkpoint tampering and forgery.
23. Concurrency Stress Test (6.1): Multi-process concurrent appending with OS-level lockfile.
24. Zero Leakage Stress Test (6.1): Deeply nested structures, mixed casing, and raw secret detection.
"""

import sys
import unittest
import tempfile
import shutil
import json
import subprocess
import concurrent.futures
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from security.hashing import (
    compute_sha256,
    verify_hmac,
    GENESIS_HASH,
)
from audit.audit_logger import (
    append_audit_event,
    load_audit_chain,
    reset_audit_chain,
    get_audit_chain_summary,
    construct_block_header,
    load_chain_checkpoint,
    get_checkpoint_path,
)
from audit.integrity_checker import (
    verify_audit_chain,
    verify_single_record,
    AuditVerificationError,
    simulate_payload_tamper,
    simulate_header_tamper,
    simulate_block_deletion,
    simulate_block_reordering,
    simulate_block_insertion,
    simulate_hmac_forgery,
    simulate_invalid_genesis,
    simulate_tail_deletion,
    simulate_file_deletion,
    simulate_checkpoint_tamper,
)
from security.access_control import has_permission


class TestSecureAuditSystem(unittest.TestCase):
    """Automated unit and adversarial tests for Stage 6 Secure Audit System."""

    def setUp(self):
        """Create a dedicated temporary directory and chain file for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_chain_path = Path(self.temp_dir) / "test_audit_chain.json"

    def tearDown(self):
        """Clean up temporary test artifacts."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ==========================================================================
    # 1. HASH-CHAIN CONSTRUCTION & CRYPTOGRAPHIC PRIMITIVES
    # ==========================================================================

    def test_01_genesis_block_creation(self):
        """Verify Genesis block starts at event_id=1 with 64-zero Genesis hash."""
        b1 = append_audit_event(
            user_id="DEV-VENT-002",
            event_type="TELEMETRY_INITIALIZED",
            event_details={"status": "device_boot_ok"},
            file_path=self.test_chain_path,
            sync_to_sqlite=False,
        )

        self.assertEqual(b1["event_id"], 1)
        self.assertEqual(b1["previous_hash"], GENESIS_HASH)
        self.assertEqual(len(b1["previous_hash"]), 64)
        self.assertEqual(len(b1["current_hash"]), 64)
        self.assertEqual(len(b1["hmac_tag"]), 64)

    def test_02_sequential_event_id_increment(self):
        """Verify sequential appending strictly increments event_id monotonically."""
        for i in range(1, 6):
            b = append_audit_event(
                user_id=f"DEV-PUMP-{i:03d}",
                event_type="TEST_EVENT",
                event_details={"step": i},
                file_path=self.test_chain_path,
                sync_to_sqlite=False,
            )
            self.assertEqual(b["event_id"], i)

        chain = load_audit_chain(self.test_chain_path)
        self.assertEqual(len(chain), 5)
        self.assertEqual([b["event_id"] for b in chain], [1, 2, 3, 4, 5])

    def test_03_cryptographic_hash_chain_linkage(self):
        """Verify each block's previous_hash strictly equals the previous block's current_hash."""
        b1 = append_audit_event("DEV-01", "INIT", {"val": 1}, file_path=self.test_chain_path, sync_to_sqlite=False)
        b2 = append_audit_event("DEV-02", "READING", {"val": 2}, file_path=self.test_chain_path, sync_to_sqlite=False)
        b3 = append_audit_event("DEV-03", "ALERT", {"val": 3}, file_path=self.test_chain_path, sync_to_sqlite=False)

        self.assertEqual(b1["previous_hash"], GENESIS_HASH)
        self.assertEqual(b2["previous_hash"], b1["current_hash"])
        self.assertEqual(b3["previous_hash"], b2["current_hash"])

    def test_04_intra_block_payload_integrity(self):
        """Verify payload_hash is deterministic SHA-256 of canonical event details."""
        details = {"heart_rate": 72.5, "spo2": 99.0, "device": "Ventilator"}
        b = append_audit_event("DEV-VENT-002", "VITALS", details, file_path=self.test_chain_path, sync_to_sqlite=False)

        expected_payload_hash = compute_sha256(details)
        self.assertEqual(b["payload_hash"], expected_payload_hash)

    def test_05_block_header_hash_integrity(self):
        """Verify current_hash is SHA-256 of the canonical block header."""
        b = append_audit_event(
            user_id="USR-ADMIN-01",
            event_type="USER_LOGIN",
            event_details={"action": "login"},
            file_path=self.test_chain_path,
            sync_to_sqlite=False,
        )

        header = construct_block_header(
            event_id=b["event_id"],
            timestamp=b["timestamp"],
            user_id=b["user_id"],
            event_type=b["event_type"],
            payload_hash=b["payload_hash"],
            previous_hash=b["previous_hash"],
        )
        self.assertEqual(b["current_hash"], compute_sha256(header))

    def test_06_hmac_authenticity_verification(self):
        """Verify each block has a valid HMAC-SHA256 signature under the system key."""
        b = append_audit_event("USR-ADMIN-01", "KEY_ROTATED", {"kid": "v2"}, file_path=self.test_chain_path, sync_to_sqlite=False)
        self.assertTrue(verify_hmac(b["current_hash"], b["hmac_tag"]))

    # ==========================================================================
    # 2. FORENSIC VERIFICATION & TAMPER DETECTION TESTS
    # ==========================================================================

    def test_07_clean_chain_verification_passes(self):
        """Verify an untampered multi-block audit chain passes forensic verification."""
        for i in range(5):
            append_audit_event(f"DEV-00{i}", f"EVENT_{i}", {"data": i * 10}, file_path=self.test_chain_path, sync_to_sqlite=False)

        report = verify_audit_chain(self.test_chain_path)
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["status"], "VERIFIED")
        self.assertEqual(report["total_records"], 5)
        self.assertEqual(report["verified_records"], 5)
        self.assertIsNone(report["tampered_entry_id"])

    def test_08_empty_chain_verification(self):
        """Verify empty audit log chain returns status EMPTY."""
        report = verify_audit_chain(self.test_chain_path)
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["status"], "EMPTY")
        self.assertEqual(report["total_records"], 0)

    def test_09_detect_payload_tampering(self):
        """Adversarial Test: Modifying payload inside a block is caught by PAYLOAD_TAMPERED."""
        for i in range(3):
            append_audit_event(f"DEV-00{i}", "READING", {"heart_rate": 70.0 + i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        chain = load_audit_chain(self.test_chain_path)
        tampered = simulate_payload_tamper(chain, target_event_id=2, key_to_modify="heart_rate", new_value=180.0)

        report = verify_audit_chain(tampered)
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["status"], "TAMPERED")
        self.assertEqual(report["tampered_entry_id"], 2)
        self.assertEqual(report["error_type"], AuditVerificationError.PAYLOAD_TAMPERED)
        self.assertIn("Intra-block payload tampering detected", report["details"])

    def test_10_detect_header_metadata_tampering(self):
        """Adversarial Test: Modifying timestamp or user_id is caught by BLOCK_HASH_MISMATCH."""
        for i in range(3):
            append_audit_event(f"DEV-00{i}", "READING", {"ok": True}, file_path=self.test_chain_path, sync_to_sqlite=False)

        chain = load_audit_chain(self.test_chain_path)
        tampered = simulate_header_tamper(chain, target_event_id=1, field_to_modify="timestamp", new_value="1999-01-01 00:00:00")

        report = verify_audit_chain(tampered)
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["status"], "TAMPERED")
        self.assertEqual(report["tampered_entry_id"], 1)
        self.assertEqual(report["error_type"], AuditVerificationError.BLOCK_HASH_MISMATCH)
        self.assertIn("Block header integrity violation", report["details"])

    def test_11_detect_block_deletion(self):
        """Adversarial Test: Deleting an intermediate block is caught immediately."""
        for i in range(4):
            append_audit_event(f"DEV-00{i}", "READING", {"idx": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        chain = load_audit_chain(self.test_chain_path)
        # Adversary deletes block #2
        tampered = simulate_block_deletion(chain, target_event_id=2)

        report = verify_audit_chain(tampered)
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["status"], "TAMPERED")
        # Detected via sequence check at index 1 (expected 2, found 3)
        self.assertEqual(report["error_type"], AuditVerificationError.ENTRY_ID_SEQUENCE_ERROR)
        self.assertIn("sequence disruption", report["details"])

    def test_12_detect_block_reordering(self):
        """Adversarial Test: Swapping two blocks is caught immediately."""
        for i in range(4):
            append_audit_event(f"DEV-00{i}", "READING", {"idx": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        chain = load_audit_chain(self.test_chain_path)
        # Swap block 2 and block 3
        tampered = simulate_block_reordering(chain, event_id_1=2, event_id_2=3)

        report = verify_audit_chain(tampered)
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["status"], "TAMPERED")
        self.assertEqual(report["error_type"], AuditVerificationError.ENTRY_ID_SEQUENCE_ERROR)

    def test_13_detect_block_insertion(self):
        """Adversarial Test: Inserting a rogue block breaks the sequence and chain."""
        for i in range(3):
            append_audit_event(f"DEV-00{i}", "READING", {"idx": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        chain = load_audit_chain(self.test_chain_path)
        rogue_block = {
            "event_id": 99,
            "timestamp": "2026-11-10 12:00:00",
            "user_id": "ROGUE-ACTOR",
            "event_type": "FORGED_EVENT",
            "event_details": {"hack": True},
            "payload_hash": "deadbeef" * 8,
            "previous_hash": "cafebabe" * 8,
            "current_hash": "feedface" * 8,
            "hmac_tag": "12345678" * 8,
        }
        tampered = simulate_block_insertion(chain, after_event_id=1, rogue_block=rogue_block)

        report = verify_audit_chain(tampered)
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["status"], "TAMPERED")

    def test_14_detect_hmac_forgery(self):
        """Adversarial Test: Altering HMAC signature is caught by HMAC_VERIFICATION_FAILED."""
        for i in range(3):
            append_audit_event(f"DEV-00{i}", "READING", {"idx": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        chain = load_audit_chain(self.test_chain_path)
        tampered = simulate_hmac_forgery(chain, target_event_id=2)

        report = verify_audit_chain(tampered)
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["status"], "TAMPERED")
        self.assertEqual(report["tampered_entry_id"], 2)
        self.assertEqual(report["error_type"], AuditVerificationError.HMAC_VERIFICATION_FAILED)
        self.assertIn("Institutional HMAC signature invalid", report["details"])

    def test_15_detect_invalid_genesis_state(self):
        """Adversarial Test: Tampering with Genesis block previous_hash is detected."""
        append_audit_event("DEV-01", "READING", {"idx": 1}, file_path=self.test_chain_path, sync_to_sqlite=False)
        chain = load_audit_chain(self.test_chain_path)

        tampered = simulate_invalid_genesis(chain)
        report = verify_audit_chain(tampered)
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["status"], "TAMPERED")
        self.assertEqual(report["error_type"], AuditVerificationError.INVALID_INITIAL_STATE)

    # ==========================================================================
    # 3. SECURITY POLICY & CONCURRENCY TESTS
    # ==========================================================================

    def test_16_zero_secret_leakage_in_audit_records(self):
        """Verify passwords, tokens, and secret keys are automatically scrubbed from event details."""
        dirty_payload = {
            "user_id": "USR-ADMIN-01",
            "password": "ClearTextPassword@123",
            "session_token": "SecretSessionTokenValue",
            "master_key": "MasterKeyBytes",
            "safe_field": "Hospital ICU Ward 3",
        }
        b = append_audit_event(
            user_id="USR-ADMIN-01",
            event_type="TEST_LEAKAGE",
            event_details=dirty_payload,
            file_path=self.test_chain_path,
            sync_to_sqlite=False,
        )

        details = b["event_details"]
        self.assertEqual(details["password"], "[REDACTED_SECRET]")
        self.assertEqual(details["session_token"], "[REDACTED_SECRET]")
        self.assertEqual(details["master_key"], "[REDACTED_SECRET]")
        self.assertEqual(details["safe_field"], "Hospital ICU Ward 3")

    def test_17_concurrency_atomic_append_safety(self):
        """Verify 10 concurrent threads appending simultaneously preserve valid hash-chain linkage."""
        def worker_append(worker_id):
            return append_audit_event(
                user_id=f"THREAD-{worker_id:02d}",
                event_type="CONCURRENT_LOG",
                event_details={"worker": worker_id},
                file_path=self.test_chain_path,
                sync_to_sqlite=False,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(worker_append, range(10)))

        self.assertEqual(len(results), 10)

        # Entire chain must be 100% cryptographically valid
        report = verify_audit_chain(self.test_chain_path)
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["status"], "VERIFIED")
        self.assertEqual(report["total_records"], 10)
        self.assertEqual(report["verified_records"], 10)

    def test_18_rbac_protection_on_audit_chain(self):
        """Verify RBAC policy: only auditor and admin can inspect and verify audit chain."""
        self.assertTrue(has_permission("admin", "view_audit_logs"))
        self.assertTrue(has_permission("admin", "verify_audit_chain"))

        self.assertTrue(has_permission("auditor", "view_audit_logs"))
        self.assertTrue(has_permission("auditor", "verify_audit_chain"))

        # Medical staff must NOT have audit log viewing or verification rights
        self.assertFalse(has_permission("medical_staff", "view_audit_logs"))
        self.assertFalse(has_permission("medical_staff", "verify_audit_chain"))

    # ==========================================================================
    # 4. STAGE 6.1 ADVANCED FORENSIC HARDENING & ADVERSARIAL TESTS
    # ==========================================================================

    def test_19_detect_complete_audit_file_deletion(self):
        """Adversarial Test: Wiping entire audit_chain.json is caught via external checkpoint."""
        for i in range(3):
            append_audit_event(f"DEV-00{i}", "READING", {"val": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        # Baseline: chain is valid
        rep_before = verify_audit_chain(self.test_chain_path)
        self.assertTrue(rep_before["is_valid"])

        # Adversary deletes audit file from disk
        simulate_file_deletion(self.test_chain_path)
        self.assertFalse(self.test_chain_path.exists())

        # Verification must catch deletion
        rep_after = verify_audit_chain(self.test_chain_path)
        self.assertFalse(rep_after["is_valid"])
        self.assertEqual(rep_after["status"], "TAMPERED")
        self.assertEqual(rep_after["error_type"], AuditVerificationError.AUDIT_FILE_DELETED)
        self.assertIn("Complete audit log deletion detected", rep_after["details"])

    def test_20_detect_single_block_tail_deletion(self):
        """Adversarial Test: Truncating the final block to erase recent activity is detected."""
        for i in range(4):
            append_audit_event(f"DEV-00{i}", "READING", {"val": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        # Load chain, remove last block, save back to file without updating external checkpoint
        chain = load_audit_chain(self.test_chain_path)
        truncated_chain = simulate_tail_deletion(chain, num_blocks=1)
        self.assertEqual(len(truncated_chain), 3)

        with open(self.test_chain_path, "w", encoding="utf-8") as f:
            json.dump(truncated_chain, f)

        # Verification against checkpoint must detect tail truncation
        rep = verify_audit_chain(self.test_chain_path)
        self.assertFalse(rep["is_valid"])
        self.assertEqual(rep["status"], "TAMPERED")
        self.assertEqual(rep["error_type"], AuditVerificationError.CHAIN_TRUNCATED)
        self.assertIn("Tail deletion / chain truncation detected", rep["details"])
        self.assertIn("The final 1 block(s) were deleted", rep["details"])

    def test_21_detect_multi_block_tail_deletion(self):
        """Adversarial Test: Truncating multiple final blocks is detected with accurate count."""
        for i in range(6):
            append_audit_event(f"DEV-00{i}", "READING", {"val": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        chain = load_audit_chain(self.test_chain_path)
        truncated_chain = simulate_tail_deletion(chain, num_blocks=3)
        self.assertEqual(len(truncated_chain), 3)

        with open(self.test_chain_path, "w", encoding="utf-8") as f:
            json.dump(truncated_chain, f)

        rep = verify_audit_chain(self.test_chain_path)
        self.assertFalse(rep["is_valid"])
        self.assertEqual(rep["status"], "TAMPERED")
        self.assertEqual(rep["error_type"], AuditVerificationError.CHAIN_TRUNCATED)
        self.assertIn("The final 3 block(s) were deleted", rep["details"])

    def test_22_detect_checkpoint_tampering_and_forgery(self):
        """Adversarial Test: Tampering with the external checkpoint is caught by HMAC verification."""
        for i in range(3):
            append_audit_event(f"DEV-00{i}", "READING", {"val": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        simulate_checkpoint_tamper(self.test_chain_path)

        rep = verify_audit_chain(self.test_chain_path)
        self.assertFalse(rep["is_valid"])
        self.assertEqual(rep["status"], "TAMPERED")
        self.assertEqual(rep["error_type"], AuditVerificationError.CHECKPOINT_CORRUPTED)
        self.assertIn("External trusted checkpoint HMAC signature verification failed", rep["details"])

    def test_23_multiprocess_concurrency_lock_safety(self):
        """Adversarial / Stress Test: Simultaneous writes from multiple independent OS processes."""
        worker_code = (
            "import sys\n"
            "from pathlib import Path\n"
            "from audit.audit_logger import append_audit_event\n"
            "target = Path(sys.argv[1])\n"
            "pid = sys.argv[2]\n"
            "for i in range(2):\n"
            "    append_audit_event(f'PROC-{pid}', 'MP_EVENT', {'p': pid, 'i': i}, file_path=target, sync_to_sqlite=False)\n"
        )

        processes = []
        num_processes = 5
        for p_id in range(num_processes):
            p = subprocess.Popen([
                sys.executable,
                "-c",
                worker_code,
                str(self.test_chain_path),
                str(p_id),
            ])
            processes.append(p)

        # Wait for all processes to complete
        exit_codes = [p.wait(timeout=15.0) for p in processes]
        self.assertTrue(all(code == 0 for code in exit_codes), f"Process failure: {exit_codes}")

        # Check total records: 5 processes * 2 events = 10 events
        chain = load_audit_chain(self.test_chain_path)
        self.assertEqual(len(chain), 10)

        # Verify monotonic sequential IDs without gaps or duplicates
        event_ids = [b["event_id"] for b in chain]
        self.assertEqual(event_ids, list(range(1, 11)))

        # Verify cryptographic integrity of entire multi-process chain
        rep = verify_audit_chain(self.test_chain_path)
        self.assertTrue(rep["is_valid"])
        self.assertEqual(rep["status"], "VERIFIED")
        self.assertEqual(rep["verified_records"], 10)

    def test_24_deeply_nested_secret_and_credential_sanitization(self):
        """Verify deep sanitization of nested dictionaries, lists, mixed casing, and raw key/token strings."""
        dirty_payload = {
            "device_id": "DEV-INFUSION-001",
            "telemetry": {
                "flow_rate_ml_hr": 25.0,
                "diagnostics": {
                    "PASS_PHRASE": "AdminSuperSecretKey!",
                    "access_token": "Bearer abc.def.ghi",
                    "auth_tag": "tag123456",
                    "safe_metric": 99.4,
                },
            },
            "user_profiles": [
                {"UserName": "admin", "PASSWORD": "plaintextPassword"},
                {"ApiKey": "sk-1234567890abcdef", "level": "HIGH"},
            ],
            "unlabeled_pem_blob": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
            "generic_signature_string": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_jwt",
        }

        b = append_audit_event(
            user_id="DEV-INFUSION-001",
            event_type="NESTED_DIAGNOSTIC",
            event_details=dirty_payload,
            file_path=self.test_chain_path,
            sync_to_sqlite=False,
        )

        details = b["event_details"]
        # Nested dict check
        diag = details["telemetry"]["diagnostics"]
        self.assertEqual(diag["PASS_PHRASE"], "[REDACTED_SECRET]")
        self.assertEqual(diag["access_token"], "[REDACTED_SECRET]")
        self.assertEqual(diag["auth_tag"], "[REDACTED_SECRET]")
        self.assertEqual(diag["safe_metric"], 99.4)

        # List of dicts check
        profiles = details["user_profiles"]
        self.assertEqual(profiles[0]["PASSWORD"], "[REDACTED_SECRET]")
        self.assertEqual(profiles[0]["UserName"], "admin")
        self.assertEqual(profiles[1]["ApiKey"], "[REDACTED_SECRET]")
        self.assertEqual(profiles[1]["level"], "HIGH")

        # Value-inspection check (raw private key and jwt strings in non-sensitive keys)
        self.assertEqual(details["unlabeled_pem_blob"], "[REDACTED_PRIVATE_KEY]")
        self.assertEqual(details["generic_signature_string"], "[REDACTED_JWT]")


if __name__ == "__main__":
    unittest.main()

