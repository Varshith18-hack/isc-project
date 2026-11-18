"""
Automated Test Suite for Stage 6.2 Forensic Security Hardening
=============================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Comprehensive Test Suite (8 Tests):
------------------------------------
1. Checkpoint Independence: Independent directory storage prevents simultaneous deletion.
2. Dual-Anchoring Independence: Relational database anchor catches dual file deletion.
3. Kernel Lock Safety: Abrupt child process termination (os._exit) immediately releases kernel lock.
4. Permanent Lockfile: Lockfile is never unlinked, eliminating file deletion race conditions.
5. Crash Consistency: Deterministic recovery of authentic lagging checkpoint after crash between chain and checkpoint.
6. Crash Consistency: Forged unauthenticated lagging block is rejected and never recovered.
7. Checkpoint Rollback: Attempt to restore an older valid checkpoint is caught via monotonic high-water mark.
8. Anchor Integrity: Tampering with SQLite audit anchor HMAC tag is detected as ANCHOR_CORRUPTED.
"""

import sys
import os
import json
import time
import shutil
import tempfile
import unittest
import subprocess
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from security.hashing import (
    compute_sha256,
    compute_hmac,
    verify_hmac,
    GENESIS_HASH,
)
from audit.audit_logger import (
    append_audit_event,
    load_audit_chain,
    reset_audit_chain,
    construct_block_header,
    load_chain_checkpoint,
    save_chain_checkpoint,
    get_checkpoint_path,
    interprocess_chain_lock,
)
from audit.integrity_checker import (
    verify_audit_chain,
    AuditVerificationError,
    simulate_file_deletion,
    simulate_crash_after_chain_save,
    simulate_checkpoint_rollback,
)
from database.database import (
    update_audit_anchor,
    get_audit_anchor,
    reset_audit_anchor,
)


class TestStage62ForensicHardening(unittest.TestCase):
    """Forensic verification test suite for Stage 6.2 hardening requirements."""

    def setUp(self):
        """Create dedicated isolated temp directories for chain and independent checkpoint."""
        self.temp_dir = tempfile.mkdtemp()
        self.audit_dir = Path(self.temp_dir) / "audit_store"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.test_chain_path = self.audit_dir / "test_audit_chain.json"

        # Independent checkpoint directory simulating separate privilege domain
        self.secure_cp_dir = Path(self.temp_dir) / "secure_cp_root"
        self.secure_cp_dir.mkdir(parents=True, exist_ok=True)
        self.test_cp_path = self.secure_cp_dir / ".independent_checkpoint.json"

    def tearDown(self):
        """Clean up temporary test artifacts."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_audit_anchor()

    # ==========================================================================
    # 1. CHECKPOINT INDEPENDENCE & SEPARATE DIRECTORY STORAGE
    # ==========================================================================

    def test_01_checkpoint_separate_directory_independence(self):
        """Verify that checkpoint placed in independent directory survives audit directory wiping."""
        # Append 3 events and store checkpoint in separate secure directory
        for i in range(3):
            b = append_audit_event(
                user_id=f"DEV-00{i}",
                event_type="READING",
                event_details={"v": i},
                file_path=self.test_chain_path,
                sync_to_sqlite=False,
            )

        # Manually mirror checkpoint into independent secure directory
        chain = load_audit_chain(self.test_chain_path)
        last_b = chain[-1]
        save_chain_checkpoint(
            latest_event_id=last_b["event_id"],
            latest_hash=last_b["current_hash"],
            total_events=len(chain),
            timestamp=last_b["timestamp"],
            file_path=self.test_cp_path,
        )

        # Adversary wipes the entire audit directory
        shutil.rmtree(self.audit_dir, ignore_errors=True)
        self.assertFalse(self.test_chain_path.exists())

        # Load independent checkpoint from separate secure root
        independent_cp = load_chain_checkpoint(file_path=self.test_cp_path)
        self.assertIsNotNone(independent_cp)
        self.assertEqual(independent_cp["total_events"], 3)

        # Verification using independent checkpoint detects complete audit deletion
        rep = verify_audit_chain(
            chain_or_path=self.test_chain_path,
            checkpoint=independent_cp,
        )
        self.assertFalse(rep["is_valid"])
        self.assertEqual(rep["status"], "TAMPERED")
        self.assertEqual(rep["error_type"], AuditVerificationError.AUDIT_FILE_DELETED)
        self.assertIn("Complete audit log deletion detected", rep["details"])

    def test_02_database_anchor_detects_dual_file_deletion(self):
        """Verify that persistent relational anchor detects deletion even if both chain and checkpoint are wiped."""
        for i in range(3):
            append_audit_event(
                user_id=f"DEV-00{i}",
                event_type="READING",
                event_details={"v": i},
                file_path=self.test_chain_path,
                sync_to_sqlite=False,
            )

        # Record anchor state in database
        chain = load_audit_chain(self.test_chain_path)
        last_b = chain[-1]
        anchor = update_audit_anchor(
            max_event_id=last_b["event_id"],
            max_event_hash=last_b["current_hash"],
            timestamp=last_b["timestamp"],
        )

        # Adversary deletes both the audit chain AND the local checkpoint file
        cp_path = get_checkpoint_path(self.test_chain_path)
        simulate_file_deletion(self.test_chain_path)
        simulate_file_deletion(cp_path)
        self.assertFalse(self.test_chain_path.exists())
        self.assertFalse(cp_path.exists())

        # Verification with anchor rejects the "empty" directory and catches deletion
        rep = verify_audit_chain(
            chain_or_path=self.test_chain_path,
            anchor=anchor,
        )
        self.assertFalse(rep["is_valid"])
        self.assertEqual(rep["status"], "TAMPERED")
        self.assertEqual(rep["error_type"], AuditVerificationError.AUDIT_FILE_DELETED)
        self.assertIn("persistent records confirm committed blocks", rep["details"])

    # ==========================================================================
    # 2. INTER-PROCESS LOCK SAFETY & KERNEL FILE LOCKING
    # ==========================================================================

    def test_03_kernel_lock_abrupt_process_termination_recovery(self):
        """Verify that when a process terminates abruptly (os._exit), OS kernel immediately frees lock."""
        child_code = f"""
import sys, os, time
from pathlib import Path
from audit.audit_logger import interprocess_chain_lock
target = Path(r'{self.test_chain_path}')
with interprocess_chain_lock(target):
    print("CHILD_LOCKED", flush=True)
    time.sleep(0.3)
    os._exit(99) # Abrupt termination without executing finally blocks
"""
        p = subprocess.Popen(
            [sys.executable, "-c", child_code],
            stdout=subprocess.PIPE,
            text=True,
        )
        line = p.stdout.readline().strip()
        self.assertEqual(line, "CHILD_LOCKED")
        p.stdout.close()

        # Child is holding lock; parent attempt with zero timeout should fail or block
        start_t = time.time()
        p.wait() # Wait for abrupt exit
        self.assertEqual(p.returncode, 99)

        # Parent must acquire lock immediately after child abrupt exit without waiting 30s
        acquired_immediately = False
        with interprocess_chain_lock(self.test_chain_path, timeout=2.0):
            acquired_immediately = True
        elapsed = time.time() - start_t
        self.assertTrue(acquired_immediately)
        self.assertLess(elapsed, 2.0, "Kernel lock should release instantly on process death")

    def test_04_kernel_lock_permanent_handle_no_unlinking_race(self):
        """Verify lockfile is permanent and never unlinked, preventing file deletion race conditions."""
        with interprocess_chain_lock(self.test_chain_path):
            pass

        lock_file = self.test_chain_path.with_suffix(".lock")
        self.assertTrue(lock_file.exists(), "Lockfile must remain permanently on disk to prevent unlinking races")

    # ==========================================================================
    # 3. CRASH CONSISTENCY & DETERMINISTIC RECONCILIATION
    # ==========================================================================

    def test_05_crash_consistency_deterministic_checkpoint_reconciliation(self):
        """Verify deterministic recovery when a crash occurs after chain write but before checkpoint write."""
        # 1. Append 2 normal events
        for i in range(2):
            append_audit_event("DEV-01", "READING", {"step": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        # Baseline: Checkpoint and chain are at 2
        chain_before = load_audit_chain(self.test_chain_path)
        self.assertEqual(len(chain_before), 2)
        cp_before = load_chain_checkpoint(self.test_chain_path)
        self.assertEqual(cp_before["total_events"], 2)

        # 2. Simulate crash: Block #3 is committed to chain, but process dies before checkpoint update
        crashed_block = simulate_crash_after_chain_save(self.test_chain_path)
        self.assertEqual(crashed_block["event_id"], 3)

        # Verify state: chain has 3 blocks, checkpoint still at 2 blocks
        chain_crashed = load_audit_chain(self.test_chain_path)
        self.assertEqual(len(chain_crashed), 3)
        cp_crashed = load_chain_checkpoint(self.test_chain_path)
        self.assertEqual(cp_crashed["total_events"], 2)

        # 3. Run verifier with auto_recover_checkpoint=True
        rep = verify_audit_chain(self.test_chain_path, auto_recover_checkpoint=True)
        self.assertTrue(rep["is_valid"])
        self.assertEqual(rep["status"], "VERIFIED")
        self.assertTrue(rep.get("recovered_from_crash"))
        self.assertIn("CRASH RECOVERY: Deterministically recovered", rep["details"])

        # 4. Checkpoint must now be reconciled to Block #3
        cp_after = load_chain_checkpoint(self.test_chain_path)
        self.assertEqual(cp_after["total_events"], 3)
        self.assertEqual(cp_after["latest_event_id"], 3)
        self.assertEqual(cp_after["latest_hash"], crashed_block["current_hash"])

    def test_06_crash_consistency_rejects_forged_lagging_block(self):
        """Verify that an unauthenticated / forged lagging block is rejected and NOT auto-recovered."""
        for i in range(2):
            append_audit_event("DEV-01", "READING", {"step": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        chain = load_audit_chain(self.test_chain_path)
        last_block = chain[-1]

        # Adversary attempts to append a forged block #3 with fake HMAC
        fake_block = {
            "event_id": 3,
            "entry_id": 3,
            "timestamp": "2026-11-10 19:00:00",
            "user_id": "ROGUE",
            "entity_id": "ROGUE",
            "event_type": "FORGED",
            "event_details": {"hack": True},
            "payload": {"hack": True},
            "payload_hash": compute_sha256({"hack": True}),
            "previous_hash": last_block["current_hash"],
            "current_hash": "a" * 64,
            "hmac_tag": "badcafe0" * 8, # Forged invalid HMAC
        }
        chain.append(fake_block)
        with open(self.test_chain_path, "w", encoding="utf-8") as f:
            json.dump(chain, f)

        rep = verify_audit_chain(self.test_chain_path, auto_recover_checkpoint=True)
        self.assertFalse(rep["is_valid"])
        self.assertEqual(rep["status"], "TAMPERED")
        self.assertEqual(rep["error_type"], AuditVerificationError.BLOCK_HASH_MISMATCH)

    # ==========================================================================
    # 4. CHECKPOINT ROLLBACK DETECTION
    # ==========================================================================

    def test_07_detect_checkpoint_rollback_against_monotonic_anchor(self):
        """Adversarial Test: Restoring an older valid checkpoint is caught via persistent monotonic anchor."""
        # Append blocks 1 to 3
        for i in range(3):
            append_audit_event("DEV-01", "INIT", {"v": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        cp3 = load_chain_checkpoint(self.test_chain_path)
        self.assertEqual(cp3["latest_event_id"], 3)

        # Append blocks 4 to 5
        for i in range(3, 5):
            append_audit_event("DEV-01", "READING", {"v": i}, file_path=self.test_chain_path, sync_to_sqlite=False)

        cp5 = load_chain_checkpoint(self.test_chain_path)
        self.assertEqual(cp5["latest_event_id"], 5)

        # Record anchor state at Event ID #5
        anchor = update_audit_anchor(
            max_event_id=5,
            max_event_hash=cp5["latest_hash"],
            timestamp=cp5["timestamp"],
        )

        # Adversary rolls back checkpoint to older valid snapshot (Event ID #3)
        simulate_checkpoint_rollback(self.test_chain_path, rolled_back_event_id=3, rolled_back_hash=cp3["latest_hash"])

        # Verification against monotonic anchor must detect rollback
        rep = verify_audit_chain(self.test_chain_path, anchor=anchor)
        self.assertFalse(rep["is_valid"])
        self.assertEqual(rep["status"], "TAMPERED")
        self.assertEqual(rep["error_type"], AuditVerificationError.CHECKPOINT_ROLLBACK_DETECTED)
        self.assertIn("Checkpoint rollback attack detected", rep["details"])

    def test_08_detect_tampered_anchor_hmac_corruption(self):
        """Verify that tampering with the persistent audit anchor in database triggers ANCHOR_CORRUPTED."""
        anchor = update_audit_anchor(
            max_event_id=10,
            max_event_hash="0" * 64,
            timestamp="2026-11-10 12:00:00",
        )

        # Adversary modifies anchor HMAC in database
        from database.database import get_db_connection
        with get_db_connection() as conn:
            conn.execute("UPDATE audit_anchor SET anchor_hmac = 'forged_hmac_tag' WHERE anchor_id = 1")

        corrupted_anchor = get_audit_anchor()
        self.assertTrue(corrupted_anchor.get("is_corrupted"))

        rep = verify_audit_chain(self.test_chain_path, anchor=corrupted_anchor)
        self.assertFalse(rep["is_valid"])
        self.assertEqual(rep["status"], "TAMPERED")
        self.assertEqual(rep["error_type"], "ANCHOR_CORRUPTED")
        self.assertIn("Persistent database audit anchor HMAC signature verification failed", rep["details"])


if __name__ == "__main__":
    unittest.main()
