"""
Cryptographic Hashing & HMAC Authentication Module (Stage 4.1 Hardened)
=======================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Implements cryptographic data integrity and message authentication primitives:
1. Canonical Data Serialization: Guarantees deterministic cryptographic hashes regardless of dictionary key ordering or whitespace.
2. SHA-256 Hashing: One-way cryptographic digest generation with collision resistance.
3. HMAC-SHA256 Authentication: Keyed Message Authentication Codes verifying both data integrity and origin authenticity.
4. HKDF-SHA256 Domain Separation: Dedicated 256-bit authentication key strictly separated from AES encryption keys.
5. Hash Chaining Primitive: Cryptographic chaining linking sequential records for immutable audit logging.
6. Timing-Attack Safe Verification: Uses constant-time comparison (hmac.compare_digest) to prevent side-channel timing attacks.
"""

import sys
import os
import json
import hashlib
import hmac
from pathlib import Path
from datetime import datetime
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from security.encryption import get_or_create_master_key


# ==============================================================================
# 1. CANONICAL DATA SERIALIZATION
# ==============================================================================

def canonicalize(data: dict | list | str | bytes | int | float) -> bytes:
    """
    Convert data into deterministic canonical bytes.

    Why Canonicalization Matters:
    -----------------------------
    In Python dictionaries, key iteration order or whitespace formatting differences
    (e.g. '{"a": 1, "b": 2}' vs '{"b": 2, "a": 1}') produce different raw byte strings.
    If serialized naively, identical data would produce completely different hashes!
    Sorting keys and enforcing standard compact separators (',', ':') guarantees
    identical inputs always yield identical cryptographic digests.
    """
    if isinstance(data, (dict, list)):
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    elif isinstance(data, str):
        return data.encode("utf-8")
    elif isinstance(data, bytes):
        return data
    else:
        return str(data).encode("utf-8")


# Alias for canonical JSON serialization
canonical_json_bytes = canonicalize


# ==============================================================================
# 2. SHA-256 CRYPTOGRAPHIC HASHING
# ==============================================================================

def compute_sha256(data: dict | list | str | bytes) -> str:
    """
    Compute 256-bit cryptographic digest using SHA-256.

    Parameters:
    -----------
    data: dict, list, str, or bytes
        The data to be hashed.

    Returns:
    --------
    str
        64-character lowercase hexadecimal string representing the SHA-256 digest.
    """
    data_bytes = canonicalize(data)
    hasher = hashlib.sha256(data_bytes)
    return hasher.hexdigest()


def verify_sha256(data: dict | list | str | bytes, expected_hash: str) -> bool:
    """
    Verify whether the computed SHA-256 hash matches the expected hash.

    Security Note:
    --------------
    Uses hmac.compare_digest() to execute constant-time string comparison,
    preventing side-channel timing attacks that exploit early-exit string comparisons.
    """
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        return False
    actual_hash = compute_sha256(data)
    return hmac.compare_digest(actual_hash.lower(), expected_hash.lower())


# ==============================================================================
# 3. HMAC-SHA256 MESSAGE AUTHENTICATION & KEY DERIVATION
# ==============================================================================

def get_system_hmac_key() -> bytes:
    """
    Retrieve or derive a dedicated 256-bit HMAC authentication key using HKDF-SHA256.

    Cryptographic Domain Separation (RFC 5869):
    -------------------------------------------
    Ensures K_HMAC is mathematically independent of K_AES and per-device keys:
    K_HMAC = HKDF(Master_Key, salt="svnit-iomt-hmac-salt-v1", context="svnit-iomt-hmac-auth:global")
    """
    env_key = os.environ.get(config.SYSTEM_HMAC_KEY_ENV)
    if env_key:
        try:
            key_bytes = bytes.fromhex(env_key.strip())
            if len(key_bytes) == config.HMAC_KEY_SIZE_BYTES:
                return key_bytes
        except ValueError:
            pass

    master_key = get_or_create_master_key()
    salt = b"svnit-iomt-hmac-salt-v1"
    context = b"svnit-iomt-hmac-authentication-key:global"
    return HKDF(
        master=master_key,
        key_len=config.HMAC_KEY_SIZE_BYTES,
        salt=salt,
        hashmod=SHA256,
        context=context,
    )


def compute_hmac(data: dict | list | str | bytes, key: bytes = None) -> str:
    """
    Compute a Keyed-Hash Message Authentication Code using HMAC-SHA256.

    Why HMAC Over Pure Hashing?
    ---------------------------
    A plain hash (SHA-256) proves data hasn't been accidentally corrupted.
    However, an active Man-in-the-Middle attacker can alter telemetry AND recalculate
    a new valid SHA-256 hash.
    HMAC requires a secret cryptographic key:
    HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
    Without the secret key K, an adversary cannot forge a valid HMAC tag for modified data.
    """
    if key is None:
        key = get_system_hmac_key()

    data_bytes = canonicalize(data)
    hmac_tag = hmac.new(key, data_bytes, hashlib.sha256).hexdigest()
    return hmac_tag


def verify_hmac(data: dict | list | str | bytes, expected_tag: str, key: bytes = None) -> bool:
    """
    Verify an HMAC-SHA256 tag using timing-attack safe constant-time comparison.
    """
    if not isinstance(expected_tag, str) or len(expected_tag) != 64:
        return False
    actual_tag = compute_hmac(data, key=key)
    return hmac.compare_digest(actual_tag.lower(), expected_tag.lower())


# ==============================================================================
# 4. HASH-CHAINING PRIMITIVE (AUDIT TRAIL FOUNDATION)
# ==============================================================================

GENESIS_HASH = "0" * 64  # Standard 64-zero initial seed for the audit blockchain


def compute_chained_hash(record_data: dict, previous_hash: str = None) -> str:
    """
    Compute a chained cryptographic hash linking sequential audit/telemetry records.

    Mathematical Formulation:
    -------------------------
    Hash_0 = 0000000000000000000000000000000000000000000000000000000000000000 (Genesis)
    Hash_i = SHA-256( Canonical(Record_i) || Hash_{i-1} )

    Tamper-Evident Property:
    ------------------------
    If an attacker modifies, deletes, or inserts a record at position k:
    Hash_k becomes invalid, and every subsequent hash Hash_{k+1}, Hash_{k+2}, ... breaks.
    """
    prev = previous_hash if previous_hash else GENESIS_HASH
    payload = {
        "previous_hash": prev,
        "record": record_data,
    }
    return compute_sha256(payload)


# ==============================================================================
# 5. DEMONSTRATION & VERIFICATION HARNESS
# ==============================================================================

def demonstrate_hashing_and_hmac():
    """Demonstrate SHA-256, Avalanche Effect, HMAC authentication, and hash chaining."""
    print("=" * 80)
    print("DEMONSTRATION: SHA-256, AVALANCHE EFFECT, HMAC & HASH-CHAINING (STAGE 4.1)")
    print("=" * 80)

    sample_record = {
        "reading_id": "REC-000501",
        "device_id": "DEV-VENT-002",
        "timestamp": "2026-11-10 14:00:00",
        "heart_rate": 74.0,
        "oxygen_saturation": 98.5,
    }

    # 1. Deterministic SHA-256
    hash_original = compute_sha256(sample_record)
    print("\n1. DETERMINISTIC SHA-256 HASHING:")
    print(f"Record: {sample_record}")
    print(f"SHA-256: {hash_original}")

    # Verify identical data with different dictionary key order
    reordered_record = {
        "oxygen_saturation": 98.5,
        "heart_rate": 74.0,
        "timestamp": "2026-11-10 14:00:00",
        "device_id": "DEV-VENT-002",
        "reading_id": "REC-000501",
    }
    hash_reordered = compute_sha256(reordered_record)
    assert hash_original == hash_reordered
    print("[PASS] Canonical serialization verified: Dictionary key order does not alter the digest.")

    # 2. Avalanche Effect Demonstration
    print("\n2. AVALANCHE EFFECT DEMONSTRATION (Strict Diffusion Property):")
    tampered_record = dict(sample_record)
    tampered_record["heart_rate"] = 74.1  # 0.1 bpm modification

    hash_tampered = compute_sha256(tampered_record)
    print(f"Original Record Hash: {hash_original}")
    print(f"Tampered Record Hash: {hash_tampered}")

    bits_orig = bin(int(hash_original, 16))[2:].zfill(256)
    bits_tamp = bin(int(hash_tampered, 16))[2:].zfill(256)
    diff_bits = sum(c1 != c2 for c1, c2 in zip(bits_orig, bits_tamp))
    pct_diff = (diff_bits / 256) * 100

    print(f"Hamming Distance: {diff_bits} / 256 bits changed ({pct_diff:.2f}% diffusion)")
    assert diff_bits > 100, "Avalanche effect test failed: Insufficient diffusion."
    print("[PASS] Avalanche effect confirmed: A 0.1 bpm shift completely randomizes the 256-bit output.")

    # 3. HMAC Data Origin Authentication with HKDF-Derived Key
    print("\n3. HMAC-SHA256 MESSAGE AUTHENTICATION & TAMPER DETECTION:")
    secret_key = get_system_hmac_key()
    hmac_tag = compute_hmac(sample_record, key=secret_key)
    print(f"HKDF-Derived HMAC Tag: {hmac_tag}")

    is_valid = verify_hmac(sample_record, hmac_tag, key=secret_key)
    assert is_valid is True
    print("[PASS] HMAC verification on authentic record: VALID (Verified Authenticity).")

    # Attacker modifies the data without knowing the key
    is_tamper_valid = verify_hmac(tampered_record, hmac_tag, key=secret_key)
    assert is_tamper_valid is False
    print("[PASS] HMAC verification on tampered record: REJECTED (Integrity violation detected).")

    # Attacker tries using an unauthorized / wrong key
    wrong_key = hashlib.sha256(b"ATTACKER_UNAUTHORIZED_KEY").digest()
    is_wrong_key_valid = verify_hmac(sample_record, hmac_tag, key=wrong_key)
    assert is_wrong_key_valid is False
    print("[PASS] HMAC verification with unauthorized key: REJECTED (Unauthorized origin blocked).")

    # 4. Hash Chaining Verification
    print("\n4. CRYPTOGRAPHIC HASH CHAINING (IMMUTABLE AUDIT LOG):")
    record_1 = {"id": 1, "action": "DEVICE_LOGIN", "user": "admin"}
    record_2 = {"id": 2, "action": "TELEMETRY_RECORD", "device": "DEV-PUMP-001"}
    record_3 = {"id": 3, "action": "ANOMALY_ALERT", "severity": "CRITICAL"}

    h0 = GENESIS_HASH
    h1 = compute_chained_hash(record_1, h0)
    h2 = compute_chained_hash(record_2, h1)
    h3 = compute_chained_hash(record_3, h2)

    print(f"Block 0 (Genesis): {h0}")
    print(f"Block 1 Hash:      {h1}")
    print(f"Block 2 Hash:      {h2}")
    print(f"Block 3 Hash:      {h3}")

    assert compute_chained_hash(record_1, h0) == h1
    assert compute_chained_hash(record_2, h1) == h2
    assert compute_chained_hash(record_3, h2) == h3
    print("[PASS] Sequential hash chain verified successfully.")

    # Attacker alters Block 2 post-facto
    tampered_record_2 = {"id": 2, "action": "TELEMETRY_RECORD", "device": "DEV-SPOOFED-999"}
    broken_h2 = compute_chained_hash(tampered_record_2, h1)
    assert broken_h2 != h2
    print("[PASS] Hash-chain tamper detection: Modifying Block 2 breaks the cryptographic link to Block 3.")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    demonstrate_hashing_and_hmac()
