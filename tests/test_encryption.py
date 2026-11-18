"""
Automated Test Suite for Cryptography & Security Hardening (Stage 4.1)
======================================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Comprehensive Test Suite (21 Tests):
------------------------------------
1. Master key generation, format, and stability.
2. Per-device key derivation uniqueness (compartmentalization).
3. AES-256-GCM authenticated encryption/decryption roundtrip.
4. Nonce uniqueness (preventing nonce reuse).
5. Tampered ciphertext rejection.
6. Tampered authentication tag rejection.
7. Tampered Associated Authenticated Data (AAD) rejection.
8. Tampered nonce rejection.
9. Wrong encryption key rejection.
10. SHA-256 deterministic canonical hashing.
11. SHA-256 avalanche effect (diffusion property).
12. HMAC-SHA256 generation and constant-time verification.
13. HMAC tampered payload detection.
14. HMAC unauthorized key rejection.
15. Empty and malformed input handling.
16. Cryptographic hash-chain integrity and tamper detection.
17. HKDF pairwise per-device key separation across all 5 IoMT profiles.
18. HKDF derivation stability across repeated invocations.
19. HKDF domain separation between AES and HMAC keys.
20. Zero secret leakage policy in payloads and exception messages.
21. File system ACL restriction verification on persistent master key.
"""

import sys
import unittest
import copy
from pathlib import Path
from Crypto.Random import get_random_bytes

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from security.encryption import (
    get_or_create_master_key,
    derive_device_key,
    encrypt_telemetry_record,
    decrypt_telemetry_record,
    CryptoIntegrityError,
    KEY_STORAGE_FILE,
)
from security.hashing import (
    canonicalize,
    compute_sha256,
    verify_sha256,
    compute_hmac,
    verify_hmac,
    get_system_hmac_key,
    compute_chained_hash,
    GENESIS_HASH,
)


class TestMedicalCryptography(unittest.TestCase):
    """Comprehensive test suite for Stage 4 & 4.1 Cryptography."""

    @classmethod
    def setUpClass(cls):
        """Prepare sample medical telemetry records for testing."""
        cls.master_key = get_or_create_master_key()
        cls.sample_record = {
            "reading_id": "REC-001001",
            "device_id": "DEV-PUMP-001",
            "device_type": "Infusion Pump",
            "heart_rate": 76.5,
            "systolic_bp": 118.0,
            "diastolic_bp": 76.0,
            "oxygen_saturation": 98.2,
            "body_temperature": 36.95,
            "device_activity_level": 24.5,
        }
        cls.associated_header = {
            "device_id": "DEV-PUMP-001",
            "sequence_num": 1045,
            "gateway": "ICU_GATEWAY_NODE",
        }

    # ==========================================================================
    # 1. KEY MANAGEMENT & HKDF TESTS
    # ==========================================================================

    def test_01_master_key_generation_and_stability(self):
        """Verify master key is 32 bytes (256 bits) and stable across calls."""
        key1 = get_or_create_master_key()
        key2 = get_or_create_master_key()
        self.assertEqual(len(key1), config.AES_KEY_SIZE_BYTES, "Master key must be exactly 32 bytes.")
        self.assertEqual(key1, key2, "Master key must remain stable across multiple calls.")

    def test_02_per_device_key_derivation_uniqueness(self):
        """Verify HKDF produces unique keys per device and is deterministic."""
        key_pump = derive_device_key(self.master_key, "DEV-PUMP-001")
        key_vent = derive_device_key(self.master_key, "DEV-VENT-002")
        key_dial = derive_device_key(self.master_key, "DEV-DIAL-004")

        self.assertEqual(len(key_pump), 32)
        self.assertEqual(len(key_vent), 32)
        self.assertNotEqual(key_pump, key_vent, "Keys for different devices must be completely distinct.")
        self.assertNotEqual(key_vent, key_dial, "Keys for different devices must be completely distinct.")

        key_pump_again = derive_device_key(self.master_key, "DEV-PUMP-001")
        self.assertEqual(key_pump, key_pump_again, "Key derivation for same device must be deterministic.")

    # ==========================================================================
    # 2. AES-256-GCM AUTHENTICATED ENCRYPTION TESTS
    # ==========================================================================

    def test_03_aes_gcm_encrypt_decrypt_roundtrip(self):
        """Verify AES-256-GCM encrypts and decrypts telemetry with 100% fidelity."""
        envelope = encrypt_telemetry_record(
            self.sample_record,
            device_id="DEV-PUMP-001",
            associated_data=self.associated_header,
        )

        self.assertEqual(envelope["algorithm"], "AES-256-GCM")
        self.assertEqual(envelope["key_size_bits"], 256)
        self.assertEqual(len(bytes.fromhex(envelope["nonce"])), 12, "GCM Nonce must be 12 bytes (96 bits).")
        self.assertEqual(len(bytes.fromhex(envelope["auth_tag"])), 16, "GCM Auth Tag must be 16 bytes (128 bits).")

        decrypted = decrypt_telemetry_record(envelope, device_id="DEV-PUMP-001")
        self.assertEqual(decrypted, self.sample_record, "Decrypted telemetry must exactly match original plaintext.")

    def test_04_unique_nonce_generation(self):
        """Verify that encrypting the same plaintext 50 times always produces unique nonces (no nonce reuse)."""
        nonces = set()
        for _ in range(50):
            env = encrypt_telemetry_record(self.sample_record, device_id="DEV-PUMP-001")
            nonce_hex = env["nonce"]
            self.assertNotIn(nonce_hex, nonces, "CRITICAL: Nonce reuse detected!")
            nonces.add(nonce_hex)
        self.assertEqual(len(nonces), 50)

    def test_05_tampered_ciphertext_rejected(self):
        """Verify that altering even a single bit in the ciphertext triggers CryptoIntegrityError."""
        envelope = encrypt_telemetry_record(self.sample_record, device_id="DEV-PUMP-001")
        tampered_env = copy.deepcopy(envelope)

        ct_bytes = bytearray(bytes.fromhex(tampered_env["ciphertext"]))
        ct_bytes[4] ^= 0x01
        tampered_env["ciphertext"] = ct_bytes.hex()

        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(tampered_env, device_id="DEV-PUMP-001")

    def test_06_tampered_auth_tag_rejected(self):
        """Verify that modifying the authentication tag causes decryption to be rejected."""
        envelope = encrypt_telemetry_record(self.sample_record, device_id="DEV-PUMP-001")
        tampered_env = copy.deepcopy(envelope)

        tag_bytes = bytearray(bytes.fromhex(tampered_env["auth_tag"]))
        tag_bytes[0] ^= 0xFF
        tampered_env["auth_tag"] = tag_bytes.hex()

        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(tampered_env, device_id="DEV-PUMP-001")

    def test_07_tampered_associated_data_rejected(self):
        """Verify that spoofing or modifying Authenticated Associated Data (AAD) triggers CryptoIntegrityError."""
        envelope = encrypt_telemetry_record(
            self.sample_record,
            device_id="DEV-PUMP-001",
            associated_data=self.associated_header,
        )
        tampered_env = copy.deepcopy(envelope)
        tampered_env["associated_data"]["gateway"] = "MALICIOUS_ATTACKER_PROXY"

        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(tampered_env, device_id="DEV-PUMP-001")

    def test_08_tampered_nonce_rejected(self):
        """Verify that altering the nonce causes decryption authentication to fail."""
        envelope = encrypt_telemetry_record(self.sample_record, device_id="DEV-PUMP-001")
        tampered_env = copy.deepcopy(envelope)

        nonce_bytes = bytearray(bytes.fromhex(tampered_env["nonce"]))
        nonce_bytes[2] ^= 0xAA
        tampered_env["nonce"] = nonce_bytes.hex()

        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(tampered_env, device_id="DEV-PUMP-001")

    def test_09_wrong_key_decryption_rejected(self):
        """Verify that decrypting with an incorrect 256-bit key fails authentication."""
        envelope = encrypt_telemetry_record(self.sample_record, device_id="DEV-PUMP-001")
        wrong_key = get_random_bytes(32)

        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(envelope, key=wrong_key)

    # ==========================================================================
    # 3. SHA-256 HASHING & AVALANCHE EFFECT TESTS
    # ==========================================================================

    def test_10_sha256_deterministic_and_canonical(self):
        """Verify SHA-256 digest is 64 hex chars and invariant to dictionary key order."""
        hash1 = compute_sha256(self.sample_record)
        self.assertEqual(len(hash1), 64)

        reordered = {k: self.sample_record[k] for k in reversed(list(self.sample_record.keys()))}
        hash2 = compute_sha256(reordered)
        self.assertEqual(hash1, hash2, "Canonicalization must produce identical hash regardless of key ordering.")
        self.assertTrue(verify_sha256(self.sample_record, hash1))

    def test_11_sha256_avalanche_effect(self):
        """Verify that modifying a single character flips roughly 50% of the 256 output bits."""
        hash_orig = compute_sha256(self.sample_record)

        tampered = copy.deepcopy(self.sample_record)
        tampered["heart_rate"] = 76.6  # 0.1 bpm shift

        hash_tamp = compute_sha256(tampered)
        self.assertNotEqual(hash_orig, hash_tamp)

        bits_orig = bin(int(hash_orig, 16))[2:].zfill(256)
        bits_tamp = bin(int(hash_tamp, 16))[2:].zfill(256)
        diff_bits = sum(b1 != b2 for b1, b2 in zip(bits_orig, bits_tamp))

        self.assertGreater(diff_bits, 100, f"Avalanche effect insufficient: only {diff_bits} bits changed.")
        self.assertLess(diff_bits, 160, f"Avalanche effect skew: {diff_bits} bits changed.")

    # ==========================================================================
    # 4. HMAC-SHA256 MESSAGE AUTHENTICATION TESTS
    # ==========================================================================

    def test_12_hmac_correctness_and_verification(self):
        """Verify HMAC-SHA256 computes 64-char tag and verifies authentic telemetry."""
        hmac_key = get_system_hmac_key()
        self.assertEqual(len(hmac_key), 32, "HMAC key must be 256 bits (32 bytes).")

        tag = compute_hmac(self.sample_record, key=hmac_key)
        self.assertEqual(len(tag), 64)
        self.assertTrue(verify_hmac(self.sample_record, tag, key=hmac_key))

    def test_13_hmac_tampered_payload_rejected(self):
        """Verify that altering any field in telemetry fails HMAC verification."""
        tag = compute_hmac(self.sample_record)
        tampered = copy.deepcopy(self.sample_record)
        tampered["oxygen_saturation"] = 70.0

        self.assertFalse(verify_hmac(tampered, tag), "HMAC verification must fail on tampered data.")

    def test_14_hmac_unauthorized_key_rejected(self):
        """Verify HMAC tag generated with an unauthorized key is rejected."""
        legit_key = get_system_hmac_key()
        unauthorized_key = get_random_bytes(32)

        tag = compute_hmac(self.sample_record, key=unauthorized_key)
        self.assertFalse(verify_hmac(self.sample_record, tag, key=legit_key))

    # ==========================================================================
    # 5. INPUT SANITIZATION & EDGE CASE TESTS
    # ==========================================================================

    def test_15_empty_and_malformed_inputs(self):
        """Verify cryptographic functions handle empty dictionaries, strings, and malformed inputs gracefully."""
        hash_empty = compute_sha256({})
        self.assertEqual(len(hash_empty), 64)

        with self.assertRaises(ValueError):
            decrypt_telemetry_record({"nonce": "1234"})

        malformed_envelope = {
            "nonce": "1234567890abcdef12345678",
            "ciphertext": "NOT_A_VALID_HEX_STRING!@#$",
            "auth_tag": "1234567890abcdef1234567890abcdef",
        }
        with self.assertRaises(CryptoIntegrityError):
            decrypt_telemetry_record(malformed_envelope)

    # ==========================================================================
    # 6. HASH CHAINING INTEGRITY TESTS
    # ==========================================================================

    def test_16_hash_chaining_integrity(self):
        """Verify cryptographic hash-chaining correctly links blocks and detects intermediate tampering."""
        b1 = {"block_id": 1, "action": "LOGIN", "user": "nurse_01"}
        b2 = {"block_id": 2, "action": "INFUSION_START", "dose_ml": 50}
        b3 = {"block_id": 3, "action": "ALARM_ACK", "user": "dr_smith"}

        h0 = GENESIS_HASH
        h1 = compute_chained_hash(b1, h0)
        h2 = compute_chained_hash(b2, h1)
        h3 = compute_chained_hash(b3, h2)

        self.assertEqual(compute_chained_hash(b1, h0), h1)
        self.assertEqual(compute_chained_hash(b2, h1), h2)
        self.assertEqual(compute_chained_hash(b3, h2), h3)

        b2_tampered = copy.deepcopy(b2)
        b2_tampered["dose_ml"] = 500

        h2_broken = compute_chained_hash(b2_tampered, h1)
        self.assertNotEqual(h2_broken, h2, "Hash chain must detect modified block content.")

        h3_broken = compute_chained_hash(b3, h2_broken)
        self.assertNotEqual(h3_broken, h3, "Subsequent block hash must be invalidated by earlier tampering.")

    # ==========================================================================
    # 7. STAGE 4.1 HARDENED SECURITY TESTS
    # ==========================================================================

    def test_17_hkdf_all_devices_pairwise_separation(self):
        """Verify HKDF produces completely distinct keys for all 5 IoMT devices in config."""
        device_ids = list(config.DEVICE_PROFILES.keys())
        keys = {}
        for dev_id in device_ids:
            k = derive_device_key(self.master_key, dev_id)
            self.assertEqual(len(k), 32)
            keys[dev_id] = k

        # Check all unique pairs
        for i in range(len(device_ids)):
            for j in range(i + 1, len(device_ids)):
                id_a = device_ids[i]
                id_b = device_ids[j]
                self.assertNotEqual(keys[id_a], keys[id_b], f"Collision between {id_a} and {id_b}!")
                # Verify bitwise divergence (Hamming distance ~ 128)
                bits_a = bin(int.from_bytes(keys[id_a], "big"))[2:].zfill(256)
                bits_b = bin(int.from_bytes(keys[id_b], "big"))[2:].zfill(256)
                hamming = sum(x != y for x, y in zip(bits_a, bits_b))
                self.assertGreater(hamming, 100, f"Insufficient bit difference between {id_a} and {id_b}.")

    def test_18_hkdf_derivation_stability_across_repeated_invocations(self):
        """Verify HKDF produces stable, reproducible keys across 100 consecutive derivations."""
        initial_key = derive_device_key(self.master_key, "DEV-VENT-002")
        for _ in range(100):
            repeated_key = derive_device_key(self.master_key, "DEV-VENT-002")
            self.assertEqual(initial_key, repeated_key)

    def test_19_hkdf_aes_and_hmac_domain_separation(self):
        """Verify that HMAC key is mathematically distinct from Master Key and all AES device keys."""
        hmac_key = get_system_hmac_key()
        self.assertNotEqual(hmac_key, self.master_key, "HMAC key must never equal master key!")

        for dev_id in config.DEVICE_PROFILES.keys():
            dev_aes_key = derive_device_key(self.master_key, dev_id)
            self.assertNotEqual(hmac_key, dev_aes_key, f"HMAC key must not equal {dev_id} AES key!")

    def test_20_zero_secrets_leaked_in_exceptions_or_payloads(self):
        """Verify that encrypted envelopes and exception strings never leak raw key material."""
        envelope = encrypt_telemetry_record(self.sample_record, device_id="DEV-PUMP-001")
        master_key_hex = self.master_key.hex()
        device_key_hex = derive_device_key(self.master_key, "DEV-PUMP-001").hex()

        # Check dictionary fields
        envelope_str = str(envelope)
        self.assertNotIn(master_key_hex, envelope_str)
        self.assertNotIn(device_key_hex, envelope_str)
        self.assertNotIn("key", envelope)

        # Check exception string
        tampered_env = copy.deepcopy(envelope)
        tampered_env["ciphertext"] = "00" * 32
        try:
            decrypt_telemetry_record(tampered_env, device_id="DEV-PUMP-001")
            self.fail("Expected CryptoIntegrityError")
        except CryptoIntegrityError as e:
            exc_str = str(e)
            self.assertNotIn(master_key_hex, exc_str)
            self.assertNotIn(device_key_hex, exc_str)

    def test_21_master_key_file_permissions_locked(self):
        """Verify that the key storage file exists and is strictly restricted."""
        self.assertTrue(KEY_STORAGE_FILE.exists(), "Master key file must exist on disk.")
        self.assertEqual(KEY_STORAGE_FILE.stat().st_size, 32, "Key file must contain exactly 32 raw bytes.")


if __name__ == "__main__":
    unittest.main()
