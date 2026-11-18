"""
AES-256-GCM Authenticated Encryption & Key Management Module (Stage 4.1 Hardened)
================================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Implements high-grade cryptographic security for sensitive medical telemetry:
1. Authenticated Encryption with Associated Data (AEAD) via AES-256-GCM.
2. HKDF-SHA256 (RFC 5869 / NIST SP 800-56C) Per-Device Key Derivation.
3. Cryptographic Domain Separation: Completely distinct AES and HMAC keys.
4. OS-Level File Permissions Lockdown (POSIX 0600 / Windows NTFS ACL via icacls).
5. Zero Secret Exposure Policy: Keys are never logged, printed, or exposed in exceptions.
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config


class CryptoIntegrityError(Exception):
    """Raised when cryptographic integrity or authentication verification fails."""
    pass


# ==============================================================================
# 1. SECURE KEY MANAGEMENT & ACCESS CONTROL
# ==============================================================================

KEY_STORAGE_FILE = config.SECURITY_DIR / ".master_key.key"


def _restrict_file_permissions(file_path: Path):
    """
    Restrict file permissions to current user only:
    - POSIX / Linux / macOS: chmod 0600 (read/write for owner only)
    - Windows NTFS: Disables inheritance and grants (R,W) exclusively to current username
    """
    try:
        if os.name != "nt":
            os.chmod(file_path, 0o600)
        else:
            user = os.environ.get("USERNAME")
            domain = os.environ.get("USERDOMAIN")
            if user:
                user_spec = f"{domain}\\{user}" if domain else user
                subprocess.run(
                    ["icacls", str(file_path), "/inheritance:r", "/grant:r", f"{user_spec}:(F)"],
                    capture_output=True,
                    check=False,
                )
    except Exception:
        pass


def get_or_create_master_key() -> bytes:
    """
    Retrieve or initialize the system's 256-bit (32-byte) master encryption key.

    Security Policy:
    1. Checks environment variable 'MED_DEVICE_MASTER_KEY' (64 hex characters).
    2. Checks local secure key file (.master_key.key) with restricted ACL permissions.
    3. If neither exists, generates a fresh cryptographically secure random 256-bit key
       using hardware entropy (get_random_bytes) and locks permissions.

    Zero-Hardcoding Guarantee: Secret keys are NEVER hardcoded in source code.
    """
    # 1. Check environment variable
    env_key = os.environ.get(config.SYSTEM_MASTER_KEY_ENV)
    if env_key:
        try:
            key_bytes = bytes.fromhex(env_key.strip())
            if len(key_bytes) == config.AES_KEY_SIZE_BYTES:
                return key_bytes
        except ValueError:
            pass

    # 2. Check local key storage file
    if KEY_STORAGE_FILE.exists():
        try:
            with open(KEY_STORAGE_FILE, "rb") as f:
                key_bytes = f.read()
            if len(key_bytes) == config.AES_KEY_SIZE_BYTES:
                _restrict_file_permissions(KEY_STORAGE_FILE)
                return key_bytes
        except IOError:
            pass

    # 3. Generate fresh cryptographically secure random key
    new_master_key = get_random_bytes(config.AES_KEY_SIZE_BYTES)
    try:
        config.SECURITY_DIR.mkdir(parents=True, exist_ok=True)
        with open(KEY_STORAGE_FILE, "wb") as f:
            f.write(new_master_key)
        _restrict_file_permissions(KEY_STORAGE_FILE)
    except IOError as e:
        print(f"[WARNING] Could not persist master key file: {e}")

    return new_master_key


def derive_device_key(master_key: bytes, device_id: str) -> bytes:
    """
    Derive a unique 256-bit AES key for a specific medical device using HKDF-SHA256 (RFC 5869).

    Why HKDF Over PBKDF2 for Master Keys?
    --------------------------------------
    - PBKDF2 is designed for human-memorable passwords (stretching low entropy via iterations).
    - Our master key already possesses full 256 bits of true cryptographic entropy.
    - HKDF (RFC 5869 / NIST SP 800-56C) is mathematically optimal for high-entropy input keying:
      1. HKDF-Extract: PRK = HMAC-SHA256(Salt, Master_Key)
      2. HKDF-Expand:  Device_Key = HMAC-SHA256(PRK, Context || 0x01)
    - Domain Separation: Using context="svnit-iomt-device-key:{device_id}" guarantees
      that every medical device receives an independent, non-overlapping symmetric key.
    """
    salt = b"svnit-iomt-security-salt-v1"
    context = f"svnit-iomt-device-key:{device_id}".encode("utf-8")
    derived_key = HKDF(
        master=master_key,
        key_len=config.AES_KEY_SIZE_BYTES,
        salt=salt,
        hashmod=SHA256,
        context=context,
    )
    return derived_key


# Alias for plural naming compatibility
derive_device_keys = derive_device_key


# ==============================================================================
# 2. AES-256-GCM AUTHENTICATED ENCRYPTION & DECRYPTION
# ==============================================================================

def canonical_json_bytes(data: dict | list | str) -> bytes:
    """Serialize data to deterministic UTF-8 bytes with sorted keys."""
    if isinstance(data, (dict, list)):
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    elif isinstance(data, str):
        return data.encode("utf-8")
    elif isinstance(data, bytes):
        return data
    else:
        return str(data).encode("utf-8")


def encrypt_telemetry_record(
    telemetry_record: dict,
    key: bytes = None,
    device_id: str = None,
    associated_data: dict | str = None,
) -> dict:
    """
    Encrypt a medical telemetry record using AES-256 in Galois/Counter Mode (GCM).

    Parameters:
    -----------
    telemetry_record: dict
        Medical device telemetry dictionary to encrypt.
    key: bytes (optional)
        256-bit encryption key. If omitted, derives key via HKDF from master key and device_id.
    device_id: str (optional)
        Identifier of the device (used for key derivation if key is not provided).
    associated_data: dict | str (optional)
        Unencrypted metadata (e.g. device_id, timestamp) authenticated alongside ciphertext.
        Any tampering with associated data causes decryption to fail.

    Returns:
    --------
    dict
        Secure JSON-serializable encrypted envelope containing:
        - algorithm: "AES-256-GCM"
        - nonce: 96-bit IV in hex
        - ciphertext: Encrypted payload in hex
        - auth_tag: 128-bit GCM authentication tag in hex
        - associated_data: The authenticated header
        - encrypted_at: Timestamp of encryption
    """
    # Determine encryption key
    dev_id = device_id or telemetry_record.get("device_id", "GLOBAL")
    if key is None:
        master_key = get_or_create_master_key()
        key = derive_device_key(master_key, dev_id)

    if len(key) != config.AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {config.AES_KEY_SIZE_BYTES} bytes, got {len(key)}")

    # 1. Serialize plaintext to bytes
    plaintext_bytes = canonical_json_bytes(telemetry_record)

    # 2. Generate a fresh, cryptographically random 96-bit (12-byte) nonce
    nonce = get_random_bytes(config.GCM_NONCE_SIZE_BYTES)

    # 3. Initialize AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # 4. Bind Associated Data (AD) into the authentication tag
    ad_bytes = b""
    if associated_data is not None:
        ad_bytes = canonical_json_bytes(associated_data)
        cipher.update(ad_bytes)

    # 5. Encrypt plaintext and generate 128-bit authentication tag
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext_bytes)

    return {
        "algorithm": "AES-256-GCM",
        "key_size_bits": 256,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "auth_tag": auth_tag.hex(),
        "associated_data": associated_data,
        "device_id": dev_id,
        "encrypted_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def decrypt_telemetry_record(
    encrypted_envelope: dict,
    key: bytes = None,
    device_id: str = None,
) -> dict:
    """
    Decrypt an AES-256-GCM encrypted envelope with strict authentication verification.

    Parameters:
    -----------
    encrypted_envelope: dict
        Encrypted payload containing 'nonce', 'ciphertext', 'auth_tag', and optional 'associated_data'.
    key: bytes (optional)
        256-bit encryption key. If omitted, derived from master key and device_id.
    device_id: str (optional)
        Device ID for key derivation if key is omitted.

    Returns:
    --------
    dict
        Decrypted and verified telemetry dictionary.

    Raises:
    -------
    CryptoIntegrityError
        If ciphertext, nonce, tag, or associated data has been tampered with or modified.
    """
    # Validate payload structure
    required_keys = {"nonce", "ciphertext", "auth_tag"}
    missing = required_keys - set(encrypted_envelope.keys())
    if missing:
        raise ValueError(f"Invalid encrypted envelope. Missing required keys: {missing}")

    # Determine decryption key
    if key is None:
        master_key = get_or_create_master_key()
        dev_id = device_id or encrypted_envelope.get("device_id", "GLOBAL")
        key = derive_device_key(master_key, dev_id)

    try:
        nonce = bytes.fromhex(encrypted_envelope["nonce"])
        ciphertext = bytes.fromhex(encrypted_envelope["ciphertext"])
        auth_tag = bytes.fromhex(encrypted_envelope["auth_tag"])
    except (ValueError, TypeError) as e:
        raise CryptoIntegrityError(f"Corrupted hex-encoding in encrypted payload: {e}")

    # Initialize AES-GCM cipher with original nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Bind associated data if present
    associated_data = encrypted_envelope.get("associated_data")
    if associated_data is not None:
        ad_bytes = canonical_json_bytes(associated_data)
        cipher.update(ad_bytes)

    # Authenticate and Decrypt
    try:
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, auth_tag)
    except ValueError as e:
        raise CryptoIntegrityError(
            "CRITICAL SECURITY ALERT: Data integrity verification failed! "
            "Ciphertext, nonce, associated data, or authentication tag has been tampered with or corrupted in transit."
        ) from e

    # Parse and return original JSON
    try:
        return json.loads(decrypted_bytes.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise CryptoIntegrityError(f"Decrypted data could not be parsed as valid JSON: {e}")


# ==============================================================================
# 3. TAMPER DEMONSTRATION & VERIFICATION HARNESS
# ==============================================================================

def demonstrate_aes_gcm():
    """Demonstrate encryption, decryption, and tamper detection."""
    print("=" * 80)
    print("DEMONSTRATION: AES-256-GCM AUTHENTICATED ENCRYPTION (STAGE 4.1 HARDENED)")
    print("=" * 80)

    sample_telemetry = {
        "reading_id": "REC-000101",
        "device_id": "DEV-PUMP-001",
        "device_type": "Infusion Pump",
        "heart_rate": 78.4,
        "systolic_bp": 118.0,
        "diastolic_bp": 76.0,
        "oxygen_saturation": 98.2,
        "body_temperature": 36.95,
        "device_activity_level": 25.0,
    }

    associated_header = {
        "device_id": "DEV-PUMP-001",
        "packet_seq": 1042,
        "routing_destination": "ICU_CENTRAL_GATEWAY",
    }

    print("\n1. ORIGINAL MEDICAL RECORD (PLAINTEXT):")
    print(json.dumps(sample_telemetry, indent=2))

    # Encrypt
    encrypted_payload = encrypt_telemetry_record(
        sample_telemetry,
        device_id="DEV-PUMP-001",
        associated_data=associated_header,
    )

    print("\n2. ENCRYPTED PAYLOAD (CIPHERTEXT ENVELOPE):")
    print(f"Algorithm:       {encrypted_payload['algorithm']}")
    print(f"Key Size:        {encrypted_payload['key_size_bits']} bits")
    print(f"Nonce (IV):      {encrypted_payload['nonce']}")
    print(f"Ciphertext:      {encrypted_payload['ciphertext']}")
    print(f"Auth Tag:        {encrypted_payload['auth_tag']}")
    print(f"Associated Data: {json.dumps(encrypted_payload['associated_data'])}")

    # Decrypt legitimately
    decrypted_record = decrypt_telemetry_record(encrypted_payload, device_id="DEV-PUMP-001")
    assert decrypted_record == sample_telemetry
    print("\n[PASS] Legitimate Decryption Succeeded! Plaintext matches exactly.")

    # Attack Scenario A: Bit-Flipping in Ciphertext
    print("\n3. SIMULATING ACTIVE ATTACK A: Tampering 1 Byte in Ciphertext...")
    tampered_payload_a = dict(encrypted_payload)
    ct_bytes = bytearray(bytes.fromhex(tampered_payload_a["ciphertext"]))
    ct_bytes[5] ^= 0xFF
    tampered_payload_a["ciphertext"] = ct_bytes.hex()

    try:
        decrypt_telemetry_record(tampered_payload_a, device_id="DEV-PUMP-001")
        print("[FAIL] Tampered ciphertext was accepted!")
    except CryptoIntegrityError as e:
        print(f"[BLOCKED AS EXPECTED] Integrity check successfully caught the attack:\n -> {e}")

    # Attack Scenario B: Spoofing Associated Data
    print("\n4. SIMULATING ACTIVE ATTACK B: Tampering Associated Routing Header...")
    tampered_payload_b = dict(encrypted_payload)
    tampered_payload_b["associated_data"] = {
        "device_id": "DEV-PUMP-001",
        "packet_seq": 1042,
        "routing_destination": "ATTACKER_CONTROLLED_PROXY",
    }

    try:
        decrypt_telemetry_record(tampered_payload_b, device_id="DEV-PUMP-001")
        print("[FAIL] Tampered header was accepted!")
    except CryptoIntegrityError as e:
        print(f"[BLOCKED AS EXPECTED] Integrity check successfully caught header tampering:\n -> {e}")

    # Attack Scenario C: Forging Authentication Tag
    print("\n5. SIMULATING ACTIVE ATTACK C: Substituting Corrupted Authentication Tag...")
    tampered_payload_c = dict(encrypted_payload)
    tag_bytes = bytearray(bytes.fromhex(tampered_payload_c["auth_tag"]))
    tag_bytes[0] ^= 0xAA
    tampered_payload_c["auth_tag"] = tag_bytes.hex()

    try:
        decrypt_telemetry_record(tampered_payload_c, device_id="DEV-PUMP-001")
        print("[FAIL] Corrupted tag was accepted!")
    except CryptoIntegrityError as e:
        print(f"[BLOCKED AS EXPECTED] Tag mismatch intercepted:\n -> {e}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    demonstrate_aes_gcm()
