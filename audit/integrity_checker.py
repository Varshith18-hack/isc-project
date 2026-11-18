"""
Cryptographic Audit Chain Integrity Verification Engine
======================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Provides comprehensive forensic verification of the immutable audit hash-chain:
1. Intra-Block Data Integrity:
   - Validates SHA-256 payload/details hash to detect modifications to patient vitals or security details.
2. Inter-Block Cryptographic Linkage:
   - Traverses sequential previous_hash links from Genesis (Hash_0 = 0*64) to the latest block.
   - Detects block deletion, insertion, truncation, or reordering.
3. Block Header Integrity:
   - Recalculates current_hash across event_id, timestamp, user_id, event_type, payload_hash, and previous_hash.
4. Institutional HMAC Authenticity:
   - Verifies HMAC-SHA256 signature against system key using constant-time comparison (hmac.compare_digest).
   - Detects forged or regenerated chains created by unauthorized adversaries.
5. Forensic Reporting:
   - Pinpoints exact index, event ID, expected vs actual values, and corruption type.
6. Adversarial Demonstration Utilities:
   - Simulates attacks (payload modification, deletion, reordering, forgery, invalid genesis) for testing and viva defense.
"""

import sys
import copy
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
    load_audit_chain,
    construct_block_header,
    load_chain_checkpoint,
    save_chain_checkpoint,
    get_checkpoint_path,
    AUDIT_FILE_PATH,
)


class AuditVerificationError:
    PAYLOAD_TAMPERED = "PAYLOAD_TAMPERED"
    BLOCK_HASH_MISMATCH = "BLOCK_HASH_MISMATCH"
    CHAIN_LINK_BROKEN = "CHAIN_LINK_BROKEN"
    HMAC_VERIFICATION_FAILED = "HMAC_VERIFICATION_FAILED"
    ENTRY_ID_SEQUENCE_ERROR = "ENTRY_ID_SEQUENCE_ERROR"
    INVALID_INITIAL_STATE = "INVALID_INITIAL_STATE"
    AUDIT_FILE_DELETED = "AUDIT_FILE_DELETED"
    CHAIN_TRUNCATED = "CHAIN_TRUNCATED"
    CHECKPOINT_CORRUPTED = "CHECKPOINT_CORRUPTED"
    LATEST_HASH_MISMATCH = "LATEST_HASH_MISMATCH"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    CHECKPOINT_ROLLBACK_DETECTED = "CHECKPOINT_ROLLBACK_DETECTED"
    ANCHOR_HASH_MISMATCH = "ANCHOR_HASH_MISMATCH"
    LAGGING_CHECKPOINT_DETECTED = "LAGGING_CHECKPOINT_DETECTED"


REQUIRED_BLOCK_KEYS = {
    "timestamp",
    "event_type",
    "previous_hash",
    "current_hash",
    "hmac_tag",
}


def verify_single_record(
    record: dict,
    expected_previous_hash: str,
    key: bytes = None,
) -> tuple[bool, str | None, str]:
    """
    Forensically verify a single audit block against expected cryptographic properties.

    Returns:
    --------
    tuple: (is_valid: bool, error_type: str | None, description: str)
    """
    if not isinstance(record, dict):
        return False, AuditVerificationError.MALFORMED_RECORD, "Record is not a valid JSON dictionary."

    # 1. Structural schema verification
    missing_keys = REQUIRED_BLOCK_KEYS - set(record.keys())
    if missing_keys:
        return (
            False,
            AuditVerificationError.MALFORMED_RECORD,
            f"Record missing required fields: {list(missing_keys)}",
        )

    # Standardize field access (support both standard and compatibility aliases)
    event_id = record.get("event_id", record.get("entry_id"))
    user_id = record.get("user_id", record.get("entity_id", "UNKNOWN"))
    details = record.get("event_details", record.get("payload", {}))
    payload_hash = record.get("payload_hash")

    if event_id is None:
        return False, AuditVerificationError.MALFORMED_RECORD, "Record missing event_id."
    if payload_hash is None:
        return False, AuditVerificationError.MALFORMED_RECORD, "Record missing payload_hash."

    # 2. Sequential Hash-Chain Linkage Verification
    if record["previous_hash"] != expected_previous_hash:
        error_type = (
            AuditVerificationError.INVALID_INITIAL_STATE
            if expected_previous_hash == GENESIS_HASH
            else AuditVerificationError.CHAIN_LINK_BROKEN
        )
        return (
            False,
            error_type,
            (
                f"Broken cryptographic hash-chain link at Block #{event_id}: "
                f"expected previous_hash '{expected_previous_hash}', "
                f"but found '{record['previous_hash']}'."
            ),
        )

    # 3. Intra-Block Payload/Details Integrity Verification
    recomputed_payload_hash = compute_sha256(details)
    if recomputed_payload_hash != payload_hash:
        return (
            False,
            AuditVerificationError.PAYLOAD_TAMPERED,
            (
                f"Intra-block payload tampering detected at Block #{event_id}: "
                f"recomputed details hash '{recomputed_payload_hash}' "
                f"does not match stored payload_hash '{payload_hash}'."
            ),
        )

    # 4. Block Header & Current Hash Verification
    header = construct_block_header(
        event_id=event_id,
        timestamp=record["timestamp"],
        user_id=user_id,
        event_type=record["event_type"],
        payload_hash=payload_hash,
        previous_hash=record["previous_hash"],
    )
    recomputed_current_hash = compute_sha256(header)
    if recomputed_current_hash != record["current_hash"]:
        return (
            False,
            AuditVerificationError.BLOCK_HASH_MISMATCH,
            (
                f"Block header integrity violation at Block #{event_id}: "
                f"recomputed block hash '{recomputed_current_hash}' "
                f"does not match stored current_hash '{record['current_hash']}'."
            ),
        )

    # 5. Institutional HMAC Authenticity Verification
    is_authentic = verify_hmac(record["current_hash"], record["hmac_tag"], key=key)
    if not is_authentic:
        return (
            False,
            AuditVerificationError.HMAC_VERIFICATION_FAILED,
            (
                f"Institutional HMAC signature invalid at Block #{event_id}: "
                f"The block hash does not authenticate with the system cryptographic key. "
                f"Possible rogue block insertion or unauthorized signature tampering."
            ),
        )

    return True, None, f"Block #{event_id} successfully verified."


def verify_audit_chain(
    chain_or_path: list[dict] | Path | str = None,
    key: bytes = None,
    checkpoint: dict = None,
    enforce_checkpoint: bool = True,
    anchor: dict = None,
    enforce_anchor: bool = True,
    auto_recover_checkpoint: bool = True,
    min_expected_event_id: int = None,
) -> dict:
    """
    Forensically verify the entire audit blockchain from Genesis to latest block,
    validating internal cryptographic properties, cross-checking against the independent
    external trusted checkpoint, and validating against persistent monotonic database anchors.

    Parameters:
    -----------
    chain_or_path: list[dict], Path, or str (optional)
        Either a list of audit records or a file path. Defaults to config.AUDIT_LOG_FILE_PATH.
    key: bytes (optional)
        HMAC key to verify signatures against. Defaults to system HMAC key.
    checkpoint: dict (optional)
        Explicit checkpoint record. If omitted, loaded from independent checkpoint file.
    enforce_checkpoint: bool
        Whether to enforce tail deletion and file deletion checks against checkpoint.
    anchor: dict (optional)
        Explicit persistent state anchor. If omitted and path is default, loaded from SQLite.
    enforce_anchor: bool
        Whether to cross-verify against persistent monotonic anchor in database.
    auto_recover_checkpoint: bool
        Whether to deterministically reconcile authentic lagging checkpoints caused by crash.
    min_expected_event_id: int (optional)
        Enforce monotonic sequence minimum to detect state rollback attacks.

    Returns:
    --------
    dict
        Comprehensive forensic verification report:
        - is_valid: bool
        - status: 'VERIFIED' | 'TAMPERED' | 'EMPTY'
        - total_records: int
        - verified_records: int
        - tampered_entry_id: int | None
        - tampered_index: int | None
        - error_type: str | None
        - details: str
        - block_audit_trail: list[dict]
    """
    source_path = None
    if isinstance(chain_or_path, (str, Path)):
        source_path = Path(chain_or_path)
        chain = load_audit_chain(file_path=source_path)
    elif isinstance(chain_or_path, list):
        chain = chain_or_path
    else:
        source_path = AUDIT_FILE_PATH
        chain = load_audit_chain()

    # 0. Load and verify independent relational database anchor
    if anchor is None and source_path == AUDIT_FILE_PATH and enforce_anchor:
        try:
            from database.database import get_audit_anchor
            anchor = get_audit_anchor()
        except Exception:
            anchor = None

    if anchor is not None and anchor.get("is_corrupted"):
        return {
            "is_valid": False,
            "status": "TAMPERED",
            "total_records": len(chain) if chain else 0,
            "verified_records": 0,
            "tampered_entry_id": None,
            "tampered_index": None,
            "error_type": "ANCHOR_CORRUPTED",
            "details": (
                "CRITICAL FORENSIC ALERT: Persistent database audit anchor HMAC signature verification failed! "
                "The database anchor has been tampered with or modified without the institutional secret key."
            ),
            "block_audit_trail": [],
        }

    # 1. Load and verify independent external checkpoint
    if checkpoint is None and source_path is not None and enforce_checkpoint:
        checkpoint = load_chain_checkpoint(file_path=source_path)

    # 2. Check for checkpoint corruption / forgery
    if checkpoint is not None and checkpoint.get("is_corrupted"):
        return {
            "is_valid": False,
            "status": "TAMPERED",
            "total_records": len(chain) if chain else 0,
            "verified_records": 0,
            "tampered_entry_id": None,
            "tampered_index": None,
            "error_type": AuditVerificationError.CHECKPOINT_CORRUPTED,
            "details": (
                "CRITICAL FORENSIC ALERT: External trusted checkpoint HMAC signature verification failed! "
                "The checkpoint file has been altered or forged without possessing the institutional secret key."
            ),
            "block_audit_trail": [],
        }

    # 3. Complete Audit File Deletion Detection (cross-checked against checkpoint and anchor)
    if source_path is not None and not source_path.exists():
        has_checkpoint_history = checkpoint is not None and checkpoint.get("total_events", 0) > 0
        has_anchor_history = anchor is not None and anchor.get("max_event_id", 0) > 0
        if has_checkpoint_history or has_anchor_history:
            recorded_id = checkpoint.get("latest_event_id") if has_checkpoint_history else anchor.get("max_event_id")
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": 0,
                "verified_records": 0,
                "tampered_entry_id": None,
                "tampered_index": None,
                "error_type": AuditVerificationError.AUDIT_FILE_DELETED,
                "details": (
                    f"CRITICAL FORENSIC ALERT: Complete audit log deletion detected! "
                    f"Audit log file '{source_path.name}' does not exist on disk, but persistent records "
                    f"confirm committed blocks (Latest Event ID: #{recorded_id})."
                ),
                "block_audit_trail": [],
            }

    # 3b. Checkpoint Rollback Detection (cross-checked against monotonic anchor or min_expected_event_id)
    if anchor is not None and checkpoint is not None and not checkpoint.get("is_corrupted"):
        anchor_max_id = anchor.get("max_event_id", 0)
        cp_latest_id = checkpoint.get("latest_event_id", 0)
        if cp_latest_id < anchor_max_id:
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain) if chain else 0,
                "verified_records": 0,
                "tampered_entry_id": cp_latest_id,
                "tampered_index": None,
                "error_type": AuditVerificationError.CHECKPOINT_ROLLBACK_DETECTED,
                "details": (
                    f"CRITICAL FORENSIC ALERT: Checkpoint rollback attack detected! "
                    f"Checkpoint records latest Event ID #{cp_latest_id}, but persistent database anchor records Event ID #{anchor_max_id}. "
                    f"An older state was restored to conceal recent events!"
                ),
                "block_audit_trail": [],
            }
        elif cp_latest_id == anchor_max_id and checkpoint.get("latest_hash") != anchor.get("max_event_hash"):
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain) if chain else 0,
                "verified_records": 0,
                "tampered_entry_id": cp_latest_id,
                "tampered_index": None,
                "error_type": AuditVerificationError.ANCHOR_HASH_MISMATCH,
                "details": (
                    f"Hash mismatch between checkpoint and persistent database anchor at Event ID #{cp_latest_id}."
                ),
                "block_audit_trail": [],
            }

    if min_expected_event_id is not None:
        if checkpoint is not None and checkpoint.get("latest_event_id", 0) < min_expected_event_id:
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain) if chain else 0,
                "verified_records": 0,
                "tampered_entry_id": checkpoint.get("latest_event_id"),
                "tampered_index": None,
                "error_type": AuditVerificationError.CHECKPOINT_ROLLBACK_DETECTED,
                "details": (
                    f"CRITICAL FORENSIC ALERT: Monotonic rollback detected! "
                    f"Checkpoint records Event ID #{checkpoint.get('latest_event_id')}, below expected minimum #{min_expected_event_id}."
                ),
                "block_audit_trail": [],
            }
        if chain and chain[-1].get("event_id", chain[-1].get("entry_id", 0)) < min_expected_event_id:
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain),
                "verified_records": len(chain),
                "tampered_entry_id": chain[-1].get("event_id"),
                "tampered_index": len(chain) - 1,
                "error_type": AuditVerificationError.CHECKPOINT_ROLLBACK_DETECTED,
                "details": (
                    f"CRITICAL FORENSIC ALERT: Audit chain rollback attack detected! "
                    f"Chain latest Event ID #{chain[-1].get('event_id')}, below expected minimum #{min_expected_event_id}."
                ),
                "block_audit_trail": [],
            }

    # 4. Empty Chain Check
    if not chain:
        if checkpoint is not None and checkpoint.get("total_events", 0) > 0:
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": 0,
                "verified_records": 0,
                "tampered_entry_id": None,
                "tampered_index": None,
                "error_type": AuditVerificationError.AUDIT_FILE_DELETED,
                "details": (
                    f"CRITICAL FORENSIC ALERT: Audit log file has been truncated to 0 records! "
                    f"External trusted checkpoint records {checkpoint['total_events']} committed blocks."
                ),
                "block_audit_trail": [],
            }
        return {
            "is_valid": True,
            "status": "EMPTY",
            "total_records": 0,
            "verified_records": 0,
            "tampered_entry_id": None,
            "tampered_index": None,
            "error_type": None,
            "details": "Audit chain is empty. No records to verify.",
            "block_audit_trail": [],
        }

    expected_previous_hash = GENESIS_HASH
    block_audit_trail = []

    # 5. Internal Blockchain Invariants Verification
    for index, record in enumerate(chain):
        event_id = record.get("event_id", record.get("entry_id"))

        # Monotonic Event ID sequence check (detects intermediate deletions, reordering, insertions)
        expected_event_id = index + 1
        if event_id != expected_event_id:
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain),
                "verified_records": index,
                "tampered_entry_id": event_id,
                "tampered_index": index,
                "error_type": AuditVerificationError.ENTRY_ID_SEQUENCE_ERROR,
                "details": (
                    f"Event ID sequence disruption at index {index}: "
                    f"expected Event ID #{expected_event_id}, but found Event ID #{event_id}. "
                    f"Indicates block insertion, deletion, or reordering."
                ),
                "block_audit_trail": block_audit_trail,
            }

        # Cryptographic and HMAC verification
        is_valid, error_type, msg = verify_single_record(
            record=record,
            expected_previous_hash=expected_previous_hash,
            key=key,
        )

        user_id = record.get("user_id", record.get("entity_id", "UNKNOWN"))

        if not is_valid:
            block_audit_trail.append({
                "event_id": event_id,
                "timestamp": record.get("timestamp"),
                "user_id": user_id,
                "event_type": record.get("event_type"),
                "current_hash": record.get("current_hash"),
                "status": "CORRUPTED",
                "error_type": error_type,
            })

            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain),
                "verified_records": index,
                "tampered_entry_id": event_id,
                "tampered_index": index,
                "error_type": error_type,
                "details": msg,
                "block_audit_trail": block_audit_trail,
            }

        block_audit_trail.append({
            "event_id": event_id,
            "timestamp": record.get("timestamp"),
            "user_id": user_id,
            "event_type": record.get("event_type"),
            "current_hash": record.get("current_hash"),
            "status": "VERIFIED",
            "error_type": None,
        })

        expected_previous_hash = record["current_hash"]

    # 6. Tail Deletion, Crash Consistency & Checkpoint Cross-Verification (Stages 6.1 & 6.2 Hardening)
    if checkpoint is not None and not checkpoint.get("is_corrupted"):
        expected_total = checkpoint.get("total_events", 0)
        expected_latest_id = checkpoint.get("latest_event_id")
        expected_latest_hash = checkpoint.get("latest_hash")

        # Crash Consistency Check: Chain was committed with Block N, but process crashed before writing checkpoint
        if len(chain) == expected_total + 1 and chain[-1].get("previous_hash") == expected_latest_hash:
            last_block = chain[-1]
            last_valid, _, _ = verify_single_record(last_block, expected_previous_hash=expected_latest_hash, key=key)
            if last_valid:
                if auto_recover_checkpoint and source_path is not None:
                    save_chain_checkpoint(
                        latest_event_id=last_block.get("event_id", last_block.get("entry_id")),
                        latest_hash=last_block["current_hash"],
                        total_events=len(chain),
                        timestamp=last_block["timestamp"],
                        file_path=source_path,
                    )
                    return {
                        "is_valid": True,
                        "status": "VERIFIED",
                        "recovered_from_crash": True,
                        "total_records": len(chain),
                        "verified_records": len(chain),
                        "tampered_entry_id": None,
                        "tampered_index": None,
                        "error_type": None,
                        "details": (
                            f"CRASH RECOVERY: Deterministically recovered from interrupted append at Block #{last_block.get('event_id')}. "
                            f"Block has valid cryptographic linkage and institutional HMAC signature; external checkpoint reconciled."
                        ),
                        "block_audit_trail": block_audit_trail,
                    }
                else:
                    return {
                        "is_valid": False,
                        "status": "LAGGING_CHECKPOINT",
                        "total_records": len(chain),
                        "verified_records": len(chain) - 1,
                        "tampered_entry_id": last_block.get("event_id"),
                        "tampered_index": len(chain) - 1,
                        "error_type": AuditVerificationError.LAGGING_CHECKPOINT_DETECTED,
                        "details": (
                            f"Crash boundary detected: Block #{last_block.get('event_id')} is cryptographically valid and signed, "
                            f"but checkpoint lags at Block #{expected_latest_id}. Auto-recovery required."
                        ),
                        "block_audit_trail": block_audit_trail,
                    }

        if len(chain) < expected_total:
            deleted_count = expected_total - len(chain)
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain),
                "verified_records": len(chain),
                "tampered_entry_id": expected_latest_id,
                "tampered_index": len(chain),
                "error_type": AuditVerificationError.CHAIN_TRUNCATED,
                "details": (
                    f"CRITICAL FORENSIC ALERT: Tail deletion / chain truncation detected! "
                    f"External trusted checkpoint records {expected_total} committed blocks "
                    f"(Latest Event ID: #{expected_latest_id}), but the audit log contains only {len(chain)} blocks. "
                    f"The final {deleted_count} block(s) were deleted to conceal recent activity!"
                ),
                "block_audit_trail": block_audit_trail,
            }

        if chain[-1].get("event_id", chain[-1].get("entry_id")) != expected_latest_id:
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain),
                "verified_records": len(chain),
                "tampered_entry_id": expected_latest_id,
                "tampered_index": len(chain) - 1,
                "error_type": AuditVerificationError.CHAIN_TRUNCATED,
                "details": (
                    f"Latest Event ID mismatch against trusted checkpoint: "
                    f"expected #{expected_latest_id}, but found #{chain[-1].get('event_id')}."
                ),
                "block_audit_trail": block_audit_trail,
            }

        if chain[-1].get("current_hash") != expected_latest_hash:
            return {
                "is_valid": False,
                "status": "TAMPERED",
                "total_records": len(chain),
                "verified_records": len(chain),
                "tampered_entry_id": expected_latest_id,
                "tampered_index": len(chain) - 1,
                "error_type": AuditVerificationError.LATEST_HASH_MISMATCH,
                "details": (
                    f"Latest block hash mismatch against trusted checkpoint: "
                    f"expected '{expected_latest_hash}', but found '{chain[-1].get('current_hash')}'."
                ),
                "block_audit_trail": block_audit_trail,
            }

    return {
        "is_valid": True,
        "status": "VERIFIED",
        "total_records": len(chain),
        "verified_records": len(chain),
        "tampered_entry_id": None,
        "tampered_index": None,
        "error_type": None,
        "details": f"All {len(chain)} audit blocks cryptographically verified with zero bit drift, valid chain linkage, and verified against external trusted checkpoint.",
        "block_audit_trail": block_audit_trail,
    }


# ==============================================================================
# ADVERSARIAL ATTACK SIMULATION UTILITIES (FOR DEMO & TESTING)
# ==============================================================================

def simulate_payload_tamper(
    chain: list[dict],
    target_event_id: int,
    key_to_modify: str,
    new_value: any,
) -> list[dict]:
    """Simulate an attacker secretly altering patient vitals or event details inside a block."""
    tampered_chain = copy.deepcopy(chain)
    for block in tampered_chain:
        eid = block.get("event_id", block.get("entry_id"))
        if eid == target_event_id:
            details = block.get("event_details", block.get("payload"))
            if isinstance(details, dict):
                details[key_to_modify] = new_value
            break
    return tampered_chain


def simulate_header_tamper(
    chain: list[dict],
    target_event_id: int,
    field_to_modify: str,
    new_value: any,
) -> list[dict]:
    """Simulate an attacker altering metadata (e.g. timestamp or user_id) in a block."""
    tampered_chain = copy.deepcopy(chain)
    for block in tampered_chain:
        eid = block.get("event_id", block.get("entry_id"))
        if eid == target_event_id:
            block[field_to_modify] = new_value
            break
    return tampered_chain


def simulate_block_deletion(
    chain: list[dict],
    target_event_id: int,
) -> list[dict]:
    """Simulate an attacker deleting an incriminating audit block (e.g. unauthorized access event)."""
    tampered_chain = copy.deepcopy(chain)
    return [b for b in tampered_chain if b.get("event_id", b.get("entry_id")) != target_event_id]


def simulate_block_reordering(
    chain: list[dict],
    event_id_1: int,
    event_id_2: int,
) -> list[dict]:
    """Simulate an attacker swapping two blocks to manipulate chronological sequence."""
    tampered_chain = copy.deepcopy(chain)
    idx1 = next((i for i, b in enumerate(tampered_chain) if b.get("event_id", b.get("entry_id")) == event_id_1), None)
    idx2 = next((i for i, b in enumerate(tampered_chain) if b.get("event_id", b.get("entry_id")) == event_id_2), None)
    if idx1 is not None and idx2 is not None:
        tampered_chain[idx1], tampered_chain[idx2] = tampered_chain[idx2], tampered_chain[idx1]
    return tampered_chain


def simulate_block_insertion(
    chain: list[dict],
    after_event_id: int,
    rogue_block: dict,
) -> list[dict]:
    """Simulate an attacker inserting an unauthorized / forged block into the chain."""
    tampered_chain = copy.deepcopy(chain)
    idx = next((i for i, b in enumerate(tampered_chain) if b.get("event_id", b.get("entry_id")) == after_event_id), None)
    if idx is not None:
        tampered_chain.insert(idx + 1, copy.deepcopy(rogue_block))
    else:
        tampered_chain.append(copy.deepcopy(rogue_block))
    return tampered_chain


def simulate_hmac_forgery(
    chain: list[dict],
    target_event_id: int,
) -> list[dict]:
    """Simulate an attacker altering a block and replacing the HMAC tag with a forged tag."""
    tampered_chain = copy.deepcopy(chain)
    for block in tampered_chain:
        eid = block.get("event_id", block.get("entry_id"))
        if eid == target_event_id:
            block["hmac_tag"] = "deadbeef" * 8
            break
    return tampered_chain


def simulate_invalid_genesis(
    chain: list[dict],
) -> list[dict]:
    """Simulate tampering with the Genesis block's initial state."""
    tampered_chain = copy.deepcopy(chain)
    if tampered_chain:
        tampered_chain[0]["previous_hash"] = "ffffffff" * 8
    return tampered_chain


def simulate_tail_deletion(
    chain: list[dict],
    num_blocks: int = 1,
) -> list[dict]:
    """Simulate tail deletion / chain truncation by removing the final N blocks."""
    tampered_chain = copy.deepcopy(chain)
    if len(tampered_chain) > num_blocks:
        return tampered_chain[:-num_blocks]
    return []


def simulate_file_deletion(file_path: Path):
    """Simulate an attacker wiping or deleting the entire audit log file from disk."""
    if file_path.exists():
        file_path.unlink()


def simulate_checkpoint_tamper(file_path: Path):
    """Simulate an attacker modifying or corrupting the external checkpoint file."""
    import json
    cp_path = get_checkpoint_path(file_path)
    if cp_path.exists():
        with open(cp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Forged hash and corrupted HMAC
        data["latest_hash"] = "00000000" * 8
        data["checkpoint_hmac"] = "badcafe0" * 8
        with open(cp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def simulate_crash_after_chain_save(file_path: Path) -> dict:
    """
    Simulate a power failure / process crash occurring immediately after
    the chain file is written and flushed, but before the checkpoint is updated.
    Appends an authentic, validly chained and HMAC-signed block directly to chain file.
    """
    from audit.audit_logger import _save_audit_chain_atomically
    from security.hashing import compute_hmac
    chain = load_audit_chain(file_path)
    last_block = chain[-1] if chain else None
    event_id = (last_block["event_id"] + 1) if last_block else 1
    prev_hash = last_block["current_hash"] if last_block else GENESIS_HASH
    details = {"crash_sim": True, "event": "UNCHECKPOINTED_COMMITTED_BLOCK"}
    p_hash = compute_sha256(details)
    now_str = "2026-11-10 18:00:00"
    header = construct_block_header(event_id, now_str, "DEV-SIM-CRASH", "CRASH_EVENT", p_hash, prev_hash)
    c_hash = compute_sha256(header)
    hmac_tag = compute_hmac(c_hash)

    new_block = {
        "event_id": event_id,
        "entry_id": event_id,
        "timestamp": now_str,
        "user_id": "DEV-SIM-CRASH",
        "entity_id": "DEV-SIM-CRASH",
        "event_type": "CRASH_EVENT",
        "event_details": details,
        "payload": details,
        "payload_hash": p_hash,
        "previous_hash": prev_hash,
        "current_hash": c_hash,
        "hmac_tag": hmac_tag,
    }
    chain.append(new_block)
    _save_audit_chain_atomically(chain, file_path=file_path)
    return new_block


def simulate_checkpoint_rollback(file_path: Path, rolled_back_event_id: int, rolled_back_hash: str):
    """
    Simulate an attacker replacing the external checkpoint with an older genuine snapshot
    to rollback the visible state of the system.
    """
    import json
    from security.hashing import compute_hmac
    cp_path = get_checkpoint_path(file_path)
    header = {
        "latest_event_id": rolled_back_event_id,
        "latest_hash": rolled_back_hash,
        "total_events": rolled_back_event_id,
        "timestamp": "2026-11-10 00:00:00",
    }
    header["checkpoint_hmac"] = compute_hmac(header)
    with open(cp_path, "w", encoding="utf-8") as f:
        json.dump(header, f, indent=2)


if __name__ == "__main__":
    print("=" * 80)
    print("DEMONSTRATION: AUDIT CHAIN INTEGRITY CHECKER & ADVERSARIAL TAMPER DETECTION")
    print("=" * 80)

    # 1. Load and verify clean chain
    report = verify_audit_chain()
    print(f"\n1. Baseline Audit Verification:\n -> Status: {report['status']}")
    print(f" -> Total Blocks: {report['total_records']}, Verified: {report['verified_records']}")
    print(f" -> Details: {report['details']}")

    # 2. Simulate Adversary Attack A: Payload modification
    chain = load_audit_chain()
    if chain:
        print("\n2. Attack Simulation: Modifying vital signs in Block #1:")
        tampered_a = simulate_payload_tamper(chain, target_event_id=1, key_to_modify="heart_rate", new_value=195.0)
        report_a = verify_audit_chain(tampered_a)
        print(f" -> Detected Status: {report_a['status']} ({report_a['error_type']})")
        print(f" -> Diagnostic: {report_a['details']}")

        print("\n3. Attack Simulation: Deleting Block #2 (Covering tracks):")
        tampered_b = simulate_block_deletion(chain, target_event_id=2)
        report_b = verify_audit_chain(tampered_b)
        print(f" -> Detected Status: {report_b['status']} ({report_b['error_type']})")
        print(f" -> Diagnostic: {report_b['details']}")
    print("=" * 80)
