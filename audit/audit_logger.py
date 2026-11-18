"""
Cryptographic Secure Audit Logger
=================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Implements an append-only, tamper-evident cryptographic hash chain for security and medical audit logging:
1. Immutable Hash-Chaining:
   - Each audit record cryptographically binds to the previous record's hash digest:
     Hash_0 = 0000000000000000000000000000000000000000000000000000000000000000 (Genesis)
     Hash_i = SHA-256( Canonical(Header_i) ) where Header_i contains Hash_{i-1}
2. Intra-Block Data Integrity:
   - Internal SHA-256 hash of canonical event details guarantees intra-block tamper evidence.
3. Institutional HMAC Authenticity:
   - Each block is sealed with an HMAC-SHA256 signature using the system authentication key.
   - Prevents unkeyed adversaries from rewriting or regenerating a fraudulent blockchain.
4. Privacy & Zero-Leakage Policy:
   - Automatically sanitizes metadata to ensure passwords, session tokens, and keys never enter audit records.
5. Concurrency Safety:
   - Thread-safe, atomic file writes prevent race conditions and file corruption.
6. Dual Auditing:
   - Synchronizes audit entries with the relational SQLite security_events table for high-speed indexing.
"""

import sys
import os
import json
import time
import random
import threading
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from security.hashing import (
    canonicalize,
    compute_sha256,
    compute_hmac,
    verify_hmac,
    GENESIS_HASH,
)
from database.database import log_security_event
from audit.security_logger import sanitize_metadata

_chain_lock = threading.Lock()
AUDIT_FILE_PATH = config.AUDIT_LOG_FILE_PATH
CHECKPOINT_FILE_PATH = getattr(config, "CHECKPOINT_FILE_PATH", config.SECURITY_DIR / ".chain_checkpoint.json")


@contextmanager
def interprocess_chain_lock(file_path: Path, timeout: float = 15.0):
    """
    Robust OS-level kernel file locking context manager (Stage 6.2 Hardening).
    Uses kernel file locks (msvcrt on Windows, fcntl on Unix/POSIX).
    The lockfile is permanent and NEVER unlinked, completely eliminating
    file-deletion race conditions.
    If a process terminates abruptly (even via os._exit() or SIGKILL),
    the OS kernel automatically and immediately releases all locks.
    """
    lock_file = file_path.with_suffix(".lock")
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    start_time = time.time()
    fd = None

    with _chain_lock:
        # Open permanent lockfile (read/write, create if not exist, never unlink)
        fd = os.open(str(lock_file), os.O_RDWR | os.O_CREAT)
        locked = False
        try:
            while True:
                try:
                    if sys.platform == "win32":
                        import msvcrt
                        # Seek to byte 0 and lock 1 byte non-blocking
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except (OSError, IOError):
                    if time.time() - start_time > timeout:
                        raise TimeoutError(f"Could not acquire kernel lock on {file_path} within {timeout}s.")
                    # Exponential jitter backoff (5ms to 20ms)
                    time.sleep(0.005 + 0.015 * random.random())

            yield
        finally:
            if locked:
                try:
                    if sys.platform == "win32":
                        import msvcrt
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_UN)
                except (OSError, IOError):
                    pass
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def get_checkpoint_path(file_path: Path = None) -> Path:
    """Return the corresponding independent external checkpoint path for a given audit chain file."""
    if file_path is None or file_path == AUDIT_FILE_PATH:
        return CHECKPOINT_FILE_PATH
    return file_path.parent / (f".{file_path.stem}_checkpoint.json")


def save_chain_checkpoint(
    latest_event_id: int,
    latest_hash: str,
    total_events: int,
    timestamp: str,
    file_path: Path = None,
) -> dict:
    """
    Persist an independently protected external chain checkpoint sealed with HMAC-SHA256.
    Used to detect complete file deletion and tail truncation attacks.
    """
    cp_path = get_checkpoint_path(file_path)
    cp_path.parent.mkdir(parents=True, exist_ok=True)

    header = {
        "latest_event_id": latest_event_id,
        "latest_hash": latest_hash,
        "total_events": total_events,
        "timestamp": timestamp,
    }
    checkpoint_hmac = compute_hmac(header)

    checkpoint_record = {
        **header,
        "checkpoint_hmac": checkpoint_hmac,
    }

    temp_cp = cp_path.with_suffix(".tmp")
    with open(temp_cp, "w", encoding="utf-8") as f:
        json.dump(checkpoint_record, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())

    os.replace(temp_cp, cp_path)
    return checkpoint_record


def load_chain_checkpoint(file_path: Path = None) -> dict | None:
    """
    Load and verify the independent external chain checkpoint.
    Returns None if missing or if HMAC authentication fails.
    """
    cp_path = get_checkpoint_path(file_path)
    if not cp_path.exists():
        return None

    try:
        with open(cp_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return None

        # Verify HMAC tag of checkpoint record
        header = {
            "latest_event_id": data.get("latest_event_id"),
            "latest_hash": data.get("latest_hash"),
            "total_events": data.get("total_events"),
            "timestamp": data.get("timestamp"),
        }
        stored_hmac = data.get("checkpoint_hmac", "")
        if not verify_hmac(header, stored_hmac):
            # Checkpoint was tampered with!
            return {"is_corrupted": True, **data}

        return data
    except (json.JSONDecodeError, OSError):
        return None


def _ensure_audit_directory(file_path: Path = None):
    """Ensure parent directory for audit file exists."""
    target_path = file_path or AUDIT_FILE_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)


def load_audit_chain(file_path: Path = None) -> list[dict]:
    """
    Load the complete cryptographic audit chain from persistent JSON storage.
    Returns an empty list if the file does not exist or is empty.
    """
    target_path = file_path or AUDIT_FILE_PATH
    if not target_path.exists():
        return []

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_audit_chain_atomically(chain: list[dict], file_path: Path = None):
    """
    Persist audit chain atomically using temporary file replacement
    to avoid file truncation or corruption during system interrupts.
    """
    target_path = file_path or AUDIT_FILE_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = target_path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(chain, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())

    # Atomic replace
    os.replace(temp_path, target_path)


def construct_block_header(
    event_id: int,
    timestamp: str,
    user_id: str,
    event_type: str,
    payload_hash: str,
    previous_hash: str,
) -> dict:
    """Construct deterministic block header dictionary for current_hash computation."""
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "user_id": user_id,
        "event_type": event_type,
        "payload_hash": payload_hash,
        "previous_hash": previous_hash,
    }


def append_audit_event(
    user_id: str,
    event_type: str,
    event_details: dict | str,
    timestamp: str = None,
    file_path: Path = None,
    sync_to_sqlite: bool = True,
    entity_id: str = None,  # Backward-compatibility alias
    payload: dict | str = None,  # Backward-compatibility alias
) -> dict:
    """
    Append an immutable, cryptographically chained audit record.

    Parameters:
    -----------
    user_id: str
        User ID (e.g. 'USR-ADMIN-01') or Medical Device ID (e.g. 'DEV-VENT-002').
    event_type: str
        Event classification (e.g. 'TELEMETRY_ENCRYPTED', 'ANOMALY_DETECTED', 'USER_LOGIN').
    event_details: dict or str
        The event details and metadata (automatically sanitized for zero secret leakage).
    timestamp: str (optional)
        Timestamp in 'YYYY-MM-DD HH:MM:SS' format. Defaults to current wall clock.
    file_path: Path (optional)
        Alternative file path (used for testing and isolated experiments).
    sync_to_sqlite: bool
        Whether to synchronize this audit record to the SQLite security_events table.

    Returns:
    --------
    dict
        The complete signed audit block containing:
        - event_id
        - timestamp
        - user_id
        - event_type
        - event_details
        - previous_hash
        - current_hash
        - hmac_tag
    """
    target_path = file_path or AUDIT_FILE_PATH
    _ensure_audit_directory(target_path)
    now_str = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Resolve aliases
    effective_user_id = user_id or entity_id or "SYSTEM"
    raw_details = event_details if event_details is not None else (payload if payload is not None else {})

    # Standardize and sanitize details for zero secret leakage
    if isinstance(raw_details, dict):
        sanitized_details = sanitize_metadata(raw_details)
    else:
        sanitized_details = {"message": str(raw_details)}

    # Compute payload integrity hash
    payload_hash = compute_sha256(sanitized_details)

    with interprocess_chain_lock(target_path):
        chain = load_audit_chain(file_path=target_path)

        # 1. Determine event ID and link to previous record's hash
        if not chain:
            event_id = 1
            previous_hash = GENESIS_HASH
        else:
            last_entry = chain[-1]
            event_id = last_entry.get("event_id", last_entry.get("entry_id", len(chain))) + 1
            previous_hash = last_entry.get("current_hash", GENESIS_HASH)

        # 2. Construct canonical block header and compute current block hash
        header = construct_block_header(
            event_id=event_id,
            timestamp=now_str,
            user_id=effective_user_id,
            event_type=event_type,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
        )
        current_hash = compute_sha256(header)

        # 3. Seal the block with an HMAC-SHA256 institutional signature
        hmac_tag = compute_hmac(current_hash)

        # 4. Form complete audit record with standard and compatibility keys
        new_record = {
            "event_id": event_id,
            "entry_id": event_id,          # Backward-compatibility alias
            "timestamp": now_str,
            "user_id": effective_user_id,
            "entity_id": effective_user_id,# Backward-compatibility alias
            "event_type": event_type,
            "event_details": sanitized_details,
            "payload": sanitized_details,  # Backward-compatibility alias
            "payload_hash": payload_hash,
            "previous_hash": previous_hash,
            "current_hash": current_hash,
            "hmac_tag": hmac_tag,
        }

        # 5. Append and persist atomically
        chain.append(new_record)
        _save_audit_chain_atomically(chain, file_path=target_path)

        # 6. Update independent external chain checkpoint
        save_chain_checkpoint(
            latest_event_id=event_id,
            latest_hash=current_hash,
            total_events=len(chain),
            timestamp=now_str,
            file_path=target_path,
        )

    # 7. Synchronize with SQLite security_events and persistent audit anchor (optional)
    if sync_to_sqlite:
        try:
            from database.database import update_audit_anchor
            update_audit_anchor(
                max_event_id=event_id,
                max_event_hash=current_hash,
                timestamp=now_str,
            )
        except Exception:
            pass  # Do not fail audit logging if SQLite is locked

        try:
            log_security_event(
                event_type=event_type,
                severity="INFO",
                description=f"Audit Block #{event_id} logged for user/device '{effective_user_id}'. Hash: {current_hash[:16]}...",
                user_id=effective_user_id if effective_user_id.startswith("USR") else None,
                device_id=effective_user_id if effective_user_id.startswith("DEV") else None,
                status="SUCCESS",
                metadata={"audit_event_id": event_id, "current_hash": current_hash, "hmac_tag": hmac_tag},
            )
        except Exception:
            pass  # Do not fail audit logging if SQLite is locked

    return new_record


def reset_audit_chain(file_path: Path = None):
    """Reset the audit chain file, its independent external checkpoint, and persistent anchor."""
    target_path = file_path or AUDIT_FILE_PATH
    cp_path = get_checkpoint_path(target_path)
    with interprocess_chain_lock(target_path):
        if target_path.exists():
            target_path.unlink()
        if cp_path.exists():
            cp_path.unlink()
        if target_path == AUDIT_FILE_PATH:
            try:
                from database.database import reset_audit_anchor
                reset_audit_anchor()
            except Exception:
                pass


def get_audit_chain_summary(file_path: Path = None) -> dict:
    """Retrieve summary statistics of the current audit blockchain."""
    chain = load_audit_chain(file_path=file_path)
    if not chain:
        return {
            "total_blocks": 0,
            "genesis_hash": GENESIS_HASH,
            "latest_hash": None,
            "latest_timestamp": None,
            "entities": [],
        }

    entities = sorted(list(set(e.get("user_id", e.get("entity_id", "")) for e in chain)))
    return {
        "total_blocks": len(chain),
        "genesis_hash": chain[0].get("previous_hash"),
        "latest_hash": chain[-1].get("current_hash"),
        "latest_timestamp": chain[-1].get("timestamp"),
        "first_timestamp": chain[0].get("timestamp"),
        "entities": entities,
    }


if __name__ == "__main__":
    print("=" * 75)
    print("DEMONSTRATION: CRYPTOGRAPHIC AUDIT LOG CHAIN")
    print("=" * 75)

    # Log 3 sample events
    b1 = append_audit_event(
        user_id="DEV-VENT-002",
        event_type="TELEMETRY_ENCRYPTED",
        event_details={"heart_rate": 74.0, "oxygen_saturation": 98.4, "ai_decision": "NORMAL"},
    )
    print(f"Block #1 Appended: Hash={b1['current_hash'][:16]}... Prev={b1['previous_hash'][:16]}...")

    b2 = append_audit_event(
        user_id="DEV-PUMP-001",
        event_type="ANOMALY_DETECTED",
        event_details={"anomaly_type": "Rapid_Battery_Drain", "ai_score": 0.6521, "severity": "CRITICAL"},
    )
    print(f"Block #2 Appended: Hash={b2['current_hash'][:16]}... Prev={b2['previous_hash'][:16]}...")

    b3 = append_audit_event(
        user_id="USR-DOC-02",
        event_type="ANOMALY_ALERT_VIEWED",
        event_details={"action": "Doctor acknowledged infusion pump anomaly alert", "doctor": "Dr. Sarah Smith"},
    )
    print(f"Block #3 Appended: Hash={b3['current_hash'][:16]}... Prev={b3['previous_hash'][:16]}...")

    summary = get_audit_chain_summary()
    print("\nAudit Chain Summary:")
    print(f" -> Total Blocks:     {summary['total_blocks']}")
    print(f" -> Latest Hash:      {summary['latest_hash']}")
    print(f" -> Active Entities:  {summary['entities']}")
    print("=" * 75)
