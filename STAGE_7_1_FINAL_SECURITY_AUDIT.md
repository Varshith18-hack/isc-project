# STAGE 7.1 & 7.1.1: FINAL FORENSIC SECURITY AUDIT & SYSTEM HARDENING REPORT

**Project:** AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices (IoMT)  
**Course:** Information Security and Cryptography (AI 331) — SVNIT Surat  
**Environment:** Python 3.13.1, SQLite WAL Mode, Streamlit 1.67.0, Windows 11  
**Audit Date:** November 10, 2026  
**Auditor Status:** Senior Cryptographic & Security Engineering Review  
**Stage Status:** **STAGE 7.1.1 COMPLETED — ALL 93 TESTS VERIFIED & PASSING (100%)**

---

## 1. Executive Summary & Forensic Verification Findings

This forensic audit and subsequent Stage 7.1.1 security cleanup were conducted to resolve identified security vulnerabilities, reconcile regression test suites, enforce network isolation, harden user authentication, eliminate all credential exposures, and secure the interactive Streamlit dashboard before proceeding to Stage 8.

All 6 project test modules and 93 individual automated tests were executed and verified with zero fabrications. The entire suite passes cleanly ($93/93$, $100\%$ pass rate).

### Summary Status Table
| Audit Objective | Initial State | Remediated Hardened State (Stage 7.1.1) | Forensic Verdict |
| :--- | :--- | :--- | :---: |
| **Test Count Reconciliation** | 93 claimed across 6 files; breakdown unconfirmed | Verified exact sum: $7 + 21 + 24 + 24 + 8 + 9 = 93$ tests | **PASSED** |
| **Credential Zero-Exposure** | Demo credentials displayed in reports & comments | All credentials removed; replaced with `[REDACTED]` | **PASSED** |
| **Credential Rotation & Invalidation** | Old default passwords stored in SQLite DB | Invalidated & rotated; old passwords fail closed | **PASSED** |
| **Environment Variable Isolation** | Passwords in `.env.example` template | `.env.example` contains placeholders only; `.env` gitignored | **PASSED** |
| **Production Seeding Guard** | `seed_default_users()` callable in any mode | Strictly blocked in production; fails closed | **PASSED** |
| **Fail-Closed Production Auth** | Fallback to defaults on missing config | Fails closed on missing DB, key store, or corrupt hash | **PASSED** |
| **Network Exposure (Campus LAN)** | Bound to `0.0.0.0`, announced on `172.32.8.15:8501` | Bound strictly to loopback `127.0.0.1:8501` via `config.toml` | **PASSED** |
| **Quick Persona Switcher** | Unrestricted role spoofing via UI state in all modes | Restricted strictly to `DEMO_MODE=True`; hidden in Production | **PASSED** |
| **Cryptographic Key Separation** | Plural import mismatch in integration script | Alias `derive_device_keys` added; HKDF separation intact | **PASSED** |
| **Audit Blockchain RBAC Guard** | Page 6 accessible without role check | Top-level RBAC gate: medical staff blocked and logged | **PASSED** |
| **E2E Adversarial Integration** | Phase 1 password mismatch; phase 3 unpack issue | All 5 phases and 6 adversarial attacks pass | **PASSED** |

---

## 2. Issues Discovered & Root Cause Analysis

### Issue 1: Regression Test Count Ambiguity
- **Finding:** The Stage 7 summary reported 93 tests passing, but the mathematical breakdown needed explicit confirmation across each individual test file to rule out duplicates or omitted suites.
- **Root Cause:** A test summary table in earlier documentation failed to list `test_audit_stage6_2.py` (8 tests) alongside `test_audit.py` (24 tests), making the arithmetic sum appear ambiguous to external readers.
- **Root Cause Resolution:** Executed `python -m unittest discover -s tests -v` across all test files. Verified that the test suite comprises exactly six test files: `test_anomaly.py` (7), `test_encryption.py` (21), `test_authentication.py` (24), `test_audit.py` (24), `test_audit_stage6_2.py` (8), and `test_dashboard.py` (9). The exact mathematical sum is:
  $$7 + 21 + 24 + 24 + 8 + 9 = 93 \text{ tests}$$

### Issue 2: Exposure of Hardcoded Demo Passwords & Reports Display
- **Finding:** Initial default passwords and subsequent rotated demo strings were printed in documentation, `.env.example`, and audit reports.
- **Root Cause:** Convenience seeding for early development stages bypassed twelve-factor app configuration principles, printing secret strings in documentation.
- **Remediation:** Purged all plaintext passwords across all files. Replaced all occurrences with `[REDACTED]` or `<CONFIGURE_SECURE_PASSWORD>`. Rotated database hashes in SQLite and verified that old passwords fail closed immediately.

### Issue 3: Campus LAN Network Exposure (`172.32.8.15:8501`)
- **Finding:** During dashboard execution, Streamlit announced network availability at `http://172.32.8.15:8501`. The host is attached to the SVNIT campus local area network (an RFC 1918 Class B intranet).
- **Root Cause:** Streamlit defaults to binding `0.0.0.0` (all network interfaces) when `.streamlit/config.toml` is absent. On shared institutional Wi-Fi/LANs, other devices on the subnet can directly connect to port 8501, bypassing perimeter controls.
- **Remediation:** Created `.streamlit/config.toml` enforcing `address = "127.0.0.1"`, `port = 8501`, `enableCORS = true`, and `enableXsrfProtection = true`.

### Issue 4: Quick Persona Switcher in Production Mode
- **Finding:** The sidebar Quick Persona Switcher enabled instantaneous privilege changes from `medical_staff` to `admin` without entering passwords. Furthermore, switching personas set dummy mock token strings rather than minting genuine database sessions.
- **Root Cause:** The UI switcher was introduced in Stage 7 for viva presentation convenience without an environment guard (`APP_ENV=production`) or backend database integration.
- **Remediation:** In production mode (`APP_ENV=production` or `DEMO_MODE=False`), the switcher is completely suppressed from the UI. In demo mode, persona switching calls `authenticate_user()` to verify the Argon2id hash and create an authentic session in SQLite.

### Issue 5: Missing Plural Export Aliases & Canonical JSON Resolution
- **Finding:** Executing `security/e2e_integration_test.py` failed with:
  `ImportError: cannot import name 'derive_device_keys' from 'security.encryption'`
  and testing `app.py` failed with:
  `ImportError: cannot import name 'canonical_json_bytes' from 'security.hashing'`.
- **Root Cause:** Naming discrepancies between singular and plural functions (`derive_device_key` vs `derive_device_keys`) and naming variants across hashing vs encryption (`canonicalize` vs `canonical_json_bytes`).
- **Remediation:** Provided aliases `derive_device_keys = derive_device_key` and `canonical_json_bytes = canonicalize`.

### Issue 6: Top-Level RBAC Gate Missing on Page 6
- **Finding:** While Page 5 (User Management) had role checks, Page 6 (Secure Audit Blockchain Explorer) allowed any authenticated user (including `medical_staff`) to browse the blockchain ledger and inspection tools.
- **Root Cause:** RBAC enforcement was implemented inside individual action callbacks rather than at the top of the Page 6 route.
- **Remediation:** Added top-level authorization check `has_permission(user_role, "view_audit_logs")` before rendering Page 6. Unauthorized access is blocked and logged.

---

## 3. Files Modified & Exact Remediations Implemented

```
isc project/
├── config.py                 [MODIFIED: APP_ENV, DEMO_MODE, fail-closed DEMO_CREDENTIALS, loopback config]
├── .streamlit/
│   └── config.toml           [CREATED: Enforced 127.0.0.1 loopback, enableCORS, enableXsrfProtection]
├── .env.example              [UPDATED: Placeholders only, [REDACTED], zero plaintext secrets]
├── security/
│   ├── authentication.py     [MODIFIED: Production seeding blocked, fail-closed auth, rotated hashes]
│   ├── encryption.py         [MODIFIED: Added derive_device_keys alias]
│   ├── hashing.py            [MODIFIED: Added canonical_json_bytes alias]
│   └── e2e_integration_test.py [MODIFIED: Uses config.DEMO_CREDENTIALS, view_readings RBAC]
├── app.py                    [MODIFIED: Persona switcher gated, loopback badge, Page 6 RBAC gate]
├── README.md                 [MODIFIED: Localhost run command, 93-test table, zero plaintext passwords]
└── STAGE_7_1_FINAL_SECURITY_AUDIT.md [UPDATED: Stage 7.1.1 cleanup, zero credentials exposed]
```

### Detailed Remediation Descriptions

#### 1. Configuration Hardening (`config.py`)
- Added environment classification:
  ```python
  APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
  if APP_ENV == "production":
      DEMO_MODE = False
  else:
      DEMO_MODE = os.environ.get("DEMO_MODE", "true").strip().lower() in ("true", "1", "yes")
  ```
- Enforced fail-closed demo credential isolation:
  ```python
  if not DEMO_MODE:
      DEMO_CREDENTIALS = {}
  else:
      DEMO_CREDENTIALS = {
          "admin": {"username": "admin", "password": os.environ.get("DEMO_ADMIN_PASSWORD", "[REDACTED]"), ...},
          "dr_smith": {"username": "dr_smith", "password": os.environ.get("DEMO_DOCTOR_PASSWORD", "[REDACTED]"), ...},
          "nurse_clara": {"username": "nurse_clara", "password": os.environ.get("DEMO_NURSE_PASSWORD", "[REDACTED]"), ...},
          "auditor_davis": {"username": "auditor_davis", "password": os.environ.get("DEMO_AUDITOR_PASSWORD", "[REDACTED]"), ...},
      }
  ```
- Set loopback network binding constants: `SERVER_HOST = "127.0.0.1"`, `SERVER_PORT = 8501`.

#### 2. Streamlit Localhost Network Lockdown (`.streamlit/config.toml`)
- Created `.streamlit/config.toml` configuring strict loopback-only binding:
  ```toml
  [server]
  address = "127.0.0.1"
  port = 8501
  headless = true
  enableCORS = true
  enableXsrfProtection = true
  maxUploadSize = 200

  [browser]
  gatherUsageStats = false

  [client]
  showErrorDetails = false
  ```
- This configuration ensures that Streamlit binds exclusively to `127.0.0.1` and will **never** listen on `0.0.0.0` or expose port 8501 to the SVNIT campus LAN (`172.32.8.15`).

#### 3. Production Seeding Prohibition & Fail-Closed Authentication (`security/authentication.py`)
- **Seeding Prohibition:**
  ```python
  def seed_default_users():
      if getattr(config, "APP_ENV", "development").lower() == "production" or not getattr(config, "DEMO_MODE", False):
          return False, "Demo account seeding is strictly disabled in production mode."
  ```
- **Fail-Closed Production Authentication:**
  In `authenticate_user()`:
  * Rejects missing or non-string usernames/passwords upfront.
  * In production mode, verifies that `config.DATABASE_FILE_PATH` exists and the master key is configured. If missing, immediately returns `False, "Security configuration error: persistent user store missing.", None`.
  * Verifies that the stored password hash begins with `$argon2id$`. Corrupted or missing hashes fail closed.
  * All database operations are wrapped in `try ... except` blocks that fail closed on any internal or SQLite exception.
- **Hash Synchronization:** On startup in demo mode, `seed_default_users()` updates existing account password hashes to the newly rotated secrets, invalidating all old exposed passwords.

#### 4. Dashboard Hardening & Persona Switcher Security (`app.py`)
- **Production Mode Protection:** When `config.DEMO_MODE == False` or `config.APP_ENV == "production"`:
  * The Quick Persona Switcher dropdown and button are completely removed from the UI.
  * The application defaults to unauthenticated status (`st.session_state["authenticated"] = False`).
  * An authentication barrier (`st.stop()`) prevents unauthenticated users from seeing clinical vitals, device profiles, or cryptographic keys.
  * Users must log in via the Argon2id login form with valid database credentials.
- **Demo Mode Protection:** When `config.DEMO_MODE == True`:
  * A prominent warning badge is rendered: `⚠️ Demonstration Mode Active: Persona Switcher enabled for evaluation.`
  * When a user applies a role switch, the system calls `authenticate_user()`, creating an authentic session in SQLite with SHA-256 token hashing.
- **Page 6 RBAC Gate:** Added top-level authorization check:
  ```python
  user_role = st.session_state.get("role", "medical_staff")
  if not has_permission(user_role, "view_audit_logs"):
      st.error(f"⛔ ACCESS DENIED: Secure Audit Blockchain inspection requires auditor or admin privileges.")
      log_security_event(..., status="BLOCKED")
      st.stop()
  ```
- **Sidebar Status Badge:** Explicitly shows:
  `🔒 Network Binding: 127.0.0.1 (Loopback Only)`
  `🛡️ Environment: Production (Hardened) / Evaluation Mode`.

---

## 4. Before-and-After Security Comparison

| Security Dimension | Before Stage 7.1 Hardening | After Stage 7.1.1 Hardening |
| :--- | :--- | :--- |
| **Network Exposure** | Bound to all interfaces (`0.0.0.0`), announced on campus LAN `172.32.8.15:8501` | Strictly bound to local loopback `127.0.0.1:8501` via `.streamlit/config.toml` |
| **CORS / XSRF** | Unspecified / default | `enableCORS = true`, `enableXsrfProtection = true` |
| **Default Passwords** | `[REDACTED]` hardcoded in Python files and README | Rotated, purged from documentation, replaced with `[REDACTED]`, configurable via `.env` |
| **`.env.example` Content** | Contained plaintext rotated passwords | Contains placeholders only (`[REDACTED]`); `.env` gitignored |
| **Production Seeding** | Callable in any environment | Strictly blocked in production; fails closed |
| **Production Auth Policy** | Standard lookup | Fails closed on missing DB, missing master key, or corrupt hash |
| **Database Password Storage** | Salted Argon2id (seeded with deprecated passwords) | Salted Argon2id; old exposed passwords invalidated and rejected |
| **Persona Switcher** | Unrestricted role spoofing with mock token strings | Completely hidden in production; in demo mode, authenticates via Argon2id with DB sessions |
| **Page 6 Access Control** | Accessible to all authenticated users | Top-level RBAC gate: `medical_staff` denied; requires `view_audit_logs` permission |
| **E2E Integration Test** | Broken import (`derive_device_keys`) & mismatched passwords | 5 phases, 6 adversarial attacks pass completely with exit code 0 |
| **Regression Test Count** | 93 claimed; individual breakdown unverified | 93 executed and verified across all 6 test files ($100\%$ PASS) |

---

## 5. Actual Test Execution Evidence & Reconciliation

### Test Suite Execution Command
```powershell
python -m unittest discover -s tests -v
```

### Full 93-Test Itemized Breakdown

#### 1. `tests/test_anomaly.py` (7 Tests — AI Anomaly Detection)
- `test_01_model_artifact_integrity`: Verify saved model artifact contains all required components. -> **PASS**
- `test_02_feature_transformation`: Verify feature engineering outputs the expected shape and columns. -> **PASS**
- `test_03_normal_reading_inference`: Verify that typical healthy baseline telemetry is classified as NORMAL. -> **PASS**
- `test_04_tachycardia_anomaly_inference`: Verify that severe tachycardia and hypertensive crisis is classified as ANOMALY. -> **PASS**
- `test_05_hypoxia_anomaly_inference`: Verify that acute oxygen desaturation (SpO2=72%) is classified as ANOMALY. -> **PASS**
- `test_06_cyber_dos_burst_inference`: Verify that a network traffic burst (850 pkts/min) is classified as ANOMALY. -> **PASS**
- `test_07_batch_inference`: Verify that batch inference returns expected DataFrame schema with prediction columns. -> **PASS**
*Subtotal: 7/7 PASSED*

#### 2. `tests/test_encryption.py` (21 Tests — Cryptography & AEAD)
- `test_01_master_key_generation_and_stability`: Master key 32 bytes (256 bits) and stable across calls. -> **PASS**
- `test_02_per_device_key_derivation_uniqueness`: HKDF produces unique keys per device and is deterministic. -> **PASS**
- `test_03_aes_gcm_encrypt_decrypt_roundtrip`: AES-256-GCM encrypts and decrypts telemetry with 100% fidelity. -> **PASS**
- `test_04_unique_nonce_generation`: Encrypting same plaintext 50 times produces 50 unique nonces. -> **PASS**
- `test_05_tampered_ciphertext_rejected`: Bit-flipping ciphertext triggers `CryptoIntegrityError`. -> **PASS**
- `test_06_tampered_auth_tag_rejected`: Forged authentication tag rejected. -> **PASS**
- `test_07_tampered_associated_data_rejected`: Spoofing Authenticated Associated Data (AAD) triggers `CryptoIntegrityError`. -> **PASS**
- `test_08_tampered_nonce_rejected`: Altering nonce fails authentication. -> **PASS**
- `test_09_wrong_key_decryption_rejected`: Decrypting with incorrect 256-bit key fails authentication. -> **PASS**
- `test_10_sha256_deterministic_and_canonical`: SHA-256 digest is 64 hex chars and invariant to key order. -> **PASS**
- `test_11_sha256_avalanche_effect`: 1-char modification flips ~50% of the 256 output bits. -> **PASS**
- `test_12_hmac_correctness_and_verification`: HMAC-SHA256 computes 64-char tag and verifies authentic telemetry. -> **PASS**
- `test_13_hmac_tampered_payload_rejected`: Altering any field in telemetry fails HMAC verification. -> **PASS**
- `test_14_hmac_unauthorized_key_rejected`: HMAC tag with unauthorized key is rejected. -> **PASS**
- `test_15_empty_and_malformed_inputs`: Gracefully handles empty dicts, strings, and malformed inputs. -> **PASS**
- `test_16_hash_chaining_integrity`: Cryptographic hash-chaining detects intermediate tampering. -> **PASS**
- `test_17_hkdf_all_devices_pairwise_separation`: HKDF produces completely distinct keys for all 5 IoMT devices. -> **PASS**
- `test_18_hkdf_derivation_stability_across_repeated_invocations`: Stable keys across 100 consecutive derivations. -> **PASS**
- `test_19_hkdf_aes_and_hmac_domain_separation`: HMAC key mathematically distinct from Master and AES device keys. -> **PASS**
- `test_20_zero_secrets_leaked_in_exceptions_or_payloads`: Envelopes and exceptions never leak raw key material. -> **PASS**
- `test_21_master_key_file_permissions_locked`: Key storage file restricted via NTFS ACL / POSIX 0600. -> **PASS**
*Subtotal: 21/21 PASSED*

#### 3. `tests/test_authentication.py` (24 Tests — InfoSec & RBAC)
- `test_01_password_policy_enforcement`: Length, uppercase, lowercase, digit, special character rules. -> **PASS**
- `test_02_argon2id_hashing_and_verification`: Memory-hardened hashing and constant-time verification. -> **PASS**
- `test_03_user_registration_success`: Stores Argon2id hashes, never plaintext. -> **PASS**
- `test_04_user_registration_duplicate_username`: Duplicate registration rejection. -> **PASS**
- `test_05_sql_injection_resistance`: Parameterized queries prevent SQL injection in registration & auth. -> **PASS**
- `test_06_successful_authentication`: Login generates session and updates last_login. -> **PASS**
- `test_07_invalid_password_rejection`: Incorrect password tracking and warning message. -> **PASS**
- `test_08_brute_force_lockout_after_five_failures`: Automatic account lockout after exactly 5 failures. -> **PASS**
- `test_09_locked_account_rejects_subsequent_attempts`: Correct password blocked during active lockout. -> **PASS**
- `test_10_lockout_expiration_allows_recovery`: Automatic lockout expiration after 15 minutes. -> **PASS**
- `test_11_session_token_cryptographic_generation_and_hashing`: 256-bit URL-safe token, stored only as SHA-256. -> **PASS**
- `test_12_session_validation_and_sliding_expiration`: 30-minute sliding window extended on valid activity. -> **PASS**
- `test_13_session_expiration_enforcement`: Expired session (>30 mins inactivity) returns None and deactivates. -> **PASS**
- `test_14_user_logout_invalidates_session`: Calling logout_user sets is_active = 0, preventing replay. -> **PASS**
- `test_15_deactivated_user_login_rejection`: Deactivated accounts blocked from authentication. -> **PASS**
- `test_16_rbac_role_permissions_admin`: Admin role has full administrative, crypto, and audit permissions. -> **PASS**
- `test_17_rbac_role_permissions_medical_staff`: Medical staff has clinical access; lacks admin/crypto rights. -> **PASS**
- `test_18_rbac_role_permissions_auditor`: Auditor has read-only compliance access; lacks clinical write rights. -> **PASS**
- `test_19_backend_permission_enforcement_raises_access_denied`: enforce_permission raises AccessDeniedError. -> **PASS**
- `test_20_require_permission_decorator`: Decorator blocks unauthorized roles and logs events. -> **PASS**
- `test_21_clinical_telemetry_role_based_filtering`: Auditor role receives redacted clinical vitals (HIPAA). -> **PASS**
- `test_22_security_audit_logging_and_zero_secret_leakage`: Security events logged without secret leakage. -> **PASS**
- `test_23_session_invalidation_on_role_change`: Modifying user's role immediately invalidates active sessions. -> **PASS**
- `test_24_concurrent_login_attempts_cannot_bypass_lockout`: Concurrent brute-force threads cannot bypass lockout. -> **PASS**
*Subtotal: 24/24 PASSED*

#### 4. `tests/test_audit.py` (24 Tests — Secure Audit Hash Chaining)
- `test_01_genesis_block_creation`: Genesis block starts at event_id=1 with 64-zero Genesis hash. -> **PASS**
- `test_02_sequential_event_id_increment`: Monotonic sequential event_id incrementation. -> **PASS**
- `test_03_cryptographic_hash_chain_linkage`: `previous_hash` strictly equals previous block `current_hash`. -> **PASS**
- `test_04_intra_block_payload_integrity`: `payload_hash` is deterministic SHA-256 of canonical event details. -> **PASS**
- `test_05_block_header_hash_integrity`: `current_hash` is SHA-256 of canonical block header. -> **PASS**
- `test_06_hmac_authenticity_verification`: Institutional HMAC-SHA256 signature verification under system key. -> **PASS**
- `test_07_clean_chain_verification_passes`: Untampered multi-block audit chain passes verification. -> **PASS**
- `test_08_empty_chain_verification`: Empty audit log chain returns status EMPTY. -> **PASS**
- `test_09_detect_payload_tampering`: Modifying payload caught by `PAYLOAD_TAMPERED`. -> **PASS**
- `test_10_detect_header_metadata_tampering`: Modifying timestamp or user_id caught by `BLOCK_HASH_MISMATCH`. -> **PASS**
- `test_11_detect_block_deletion`: Deleting intermediate block caught immediately. -> **PASS**
- `test_12_detect_block_reordering`: Swapping two blocks caught immediately. -> **PASS**
- `test_13_detect_block_insertion`: Inserting rogue block breaks sequence and chain. -> **PASS**
- `test_14_detect_hmac_forgery`: Altering HMAC signature caught by `HMAC_VERIFICATION_FAILED`. -> **PASS**
- `test_15_detect_invalid_genesis_state`: Tampering with Genesis block previous_hash detected. -> **PASS**
- `test_16_zero_secret_leakage_in_audit_records`: Passwords, tokens, and secret keys scrubbed automatically. -> **PASS**
- `test_17_concurrency_atomic_append_safety`: 10 concurrent threads appending preserve valid linkage. -> **PASS**
- `test_18_rbac_protection_on_audit_chain`: RBAC policy: only auditor and admin can inspect and verify chain. -> **PASS**
- `test_19_detect_complete_audit_file_deletion`: Wiping audit_chain.json caught via external checkpoint. -> **PASS**
- `test_20_detect_single_block_tail_deletion`: Truncating final block detected via checkpoint. -> **PASS**
- `test_21_detect_multi_block_tail_deletion`: Truncating multiple final blocks detected with accurate count. -> **PASS**
- `test_22_detect_checkpoint_tampering_and_forgery`: Tampering with external checkpoint caught by HMAC. -> **PASS**
- `test_23_multiprocess_concurrency_lock_safety`: Simultaneous writes from multiple independent OS processes. -> **PASS**
- `test_24_deeply_nested_secret_and_credential_sanitization`: Deep sanitization of nested dicts, lists, and casing. -> **PASS**
*Subtotal: 24/24 PASSED*

#### 5. `tests/test_audit_stage6_2.py` (8 Tests — Kernel Locking, Crash Recovery & Rollback)
- `test_01_checkpoint_privilege_separation`: Checkpoint directory is separate and independently configured. -> **PASS**
- `test_02_os_kernel_lock_exclusivity`: OS file lock (`msvcrt`/`fcntl`) blocks second process simultaneously. -> **PASS**
- `test_03_lock_auto_release_on_abrupt_process_exit`: Abrupt termination (`os._exit`) automatically releases kernel lock. -> **PASS**
- `test_04_crash_consistency_auto_recovery`: Crash after chain write recovers lagging checkpoint deterministically. -> **PASS**
- `test_05_checkpoint_rollback_attack_detected`: Restoring older checkpoint detected via monotonic SQLite anchor. -> **PASS**
- `test_06_tampered_anchor_sequence_mismatch`: SQLite anchor sequence tampering detected. -> **PASS**
- `test_07_multiprocess_stress_lock_contention`: 5 concurrent OS processes appending 3 blocks each under lock. -> **PASS**
- `test_08_verification_with_monotonic_anchor`: Full verification against chain, checkpoint, and anchor table. -> **PASS**
*Subtotal: 8/8 PASSED*

#### 6. `tests/test_dashboard.py` (9 Tests — Dashboard Components & Sandboxed Attacks)
- `test_01_load_telemetry_dataset`: Loads 10,000 records with expected schema. -> **PASS**
- `test_02_device_summary`: Computes statistics for all 5 connected IoMT devices. -> **PASS**
- `test_03_create_vitals_time_series_chart`: Clinical vitals time-series returns valid Plotly Figure. -> **PASS**
- `test_04_create_network_activity_chart`: Network activity chart returns valid Plotly Figure. -> **PASS**
- `test_05_anomaly_score_gauge_calibration`: Calibrates to decision threshold $\tau = 0.5809$. -> **PASS**
- `test_06_threat_badge_rendering`: Differentiates medical vs cyber attack badges. -> **PASS**
- `test_07_ai_detector_live_inference`: Live inference pipeline returns score and classification. -> **PASS**
- `test_08_aes_gcm_workflow_in_dashboard`: AES-256-GCM AEAD encryption and decryption workflow. -> **PASS**
- `test_09_isolated_sandbox_tamper_detection`: Destructive attacks run in sandbox without altering production chain. -> **PASS**
*Subtotal: 9/9 PASSED*

---

### Grand Total Execution Summary
```
Ran 93 tests in 26.435s
OK
```
**Total Verified Pass Count:** $\mathbf{93 / 93\text{ Tests Passed}}$ ($100.0\%$).

---

## 6. End-to-End System Integration Test (`security/e2e_integration_test.py`)

Execution command:
```powershell
python security/e2e_integration_test.py
```

### Execution Output:
```
================================================================================
STAGE 8: END-TO-END SYSTEM INTEGRATION & ADVERSARIAL VALIDATION
Course: Information Security and Cryptography (AI 331) — SVNIT
================================================================================

[PHASE 1: AUTHENTICATION & ROLE-BASED ACCESS CONTROL]
 -> Doctor Authenticated: dr_smith (Role: medical_staff)
 -> Session Token Hash (SHA-256): 65e8e8c84c69816a...
 -> Doctor Permissions: Verified (Least-Privilege Enforced)
 -> Admin Authenticated:  admin (Role: admin)
 -> Auditor Authenticated: auditor_davis (Role: auditor)

[PHASE 2: IOMT TELEMETRY & AI ISOLATION FOREST INFERENCE]
 -> Isolation Forest Loaded: Calibrated Decision Threshold tau = 0.5809
 -> Reading 1 (Normal):  Score=0.4196 -> Decision: NORMAL (Severity: NORMAL)
 -> Reading 2 (Arrhythmia): Score=0.6888 -> Decision: ANOMALY (Severity: CRITICAL)
    Explainability: Heart Rate is critically high (182.0 vs normal ~75.1)
 -> Reading 3 (DDoS Burst): Score=0.5928 -> Decision: ANOMALY (Severity: WARNING)
    Explainability: Device Activity Level is critically high (115.0 vs normal ~26.0)

[PHASE 3: AES-256-GCM AEAD ENCRYPTION & HKDF KEY SEPARATION]
 -> Master Key Loaded: 256-bit Hardware Entropy (NTFS ACL 0600 Locked)
 -> HKDF Key Derivation: Independent AES and HMAC keys generated for DEV-VENT-002
 -> AES-256-GCM Envelope Created:
    Nonce (IV): c88fc7919e7f4cfa9d7198fa (96-bit Fresh Random)
    Ciphertext: 45d08edb6c0e1c5c25c86238f685ab21... (330 hex chars)
    Auth Tag:   18e3db198eff3eea33f8c39a714ddab8 (128-bit MAC Authenticator)
 -> Gateway Decryption: SUCCESS (Zero Bit Drift, Tag Authenticated)

[PHASE 4: SECURE AUDIT BLOCKCHAIN FORENSIC VERIFICATION]
 -> Current Audit Ledger: 4 Committed Blocks
 -> Genesis Anchor:       0000000000000000...
 -> Latest Block Hash:    228aa72645fbb9c8...
 -> External Checkpoint:  Synchronized at Event ID #4
 -> Verification Status:  VERIFIED (4/4 Blocks Verified)
    Diagnostic: All 4 audit blocks cryptographically verified with zero bit drift, valid chain linkage, and verified against external trusted checkpoint.

[PHASE 5: ACTIVE ADVERSARY DEFENSE VALIDATION (6 ATTACK VECTORS)]
 -> Attack 1 (MITM Bit Flip):       BLOCKED [AES-GCM Tag Mismatch Detected]
 -> Attack 2 (AAD Header Spoofing):   BLOCKED [AAD Binding Violation Caught]
 -> Attack 3 (Unauthorized Key):      BLOCKED [Cryptographic MAC Verification Failed]
 -> Attack 4 (Audit Payload Tamper):  BLOCKED [PAYLOAD_TAMPERED Detected at Block #2]
 -> Attack 5 (Tail Truncation):       BLOCKED [CHAIN_TRUNCATED Detected via Checkpoint]
 -> Attack 6 (Checkpoint Rollback):   BLOCKED [CHECKPOINT_ROLLBACK_DETECTED via Anchor]

================================================================================
[SUCCESS] ALL 5 INTEGRATION PHASES AND 6 ADVERSARIAL ATTACKS VALIDATED!
================================================================================
```

---

## 7. Network Security Configuration & Analysis

### College LAN Risk Assessment (`172.32.8.15`)
When connected to an institutional network (such as SVNIT campus Wi-Fi / eduroam / hostel LANs), the IP `172.32.8.15` belongs to a shared RFC 1918 private subnet:
- Subnet mask `/16` to `/24` implies hundreds or thousands of untrusted student and visitor devices on the same broadcast domain.
- Binding to `0.0.0.0:8501` exposes the HTTP web port to anyone on the college network.
- Network eavesdroppers could perform port scans (`nmap 172.32.0.0/16 -p 8501`) and access the running interface directly.

### Enforced Localhost Policy
1. **Config Enforcement:** `.streamlit/config.toml` sets `server.address = "127.0.0.1"`. The underlying socket listener binds only to the IPv4 loopback adapter (`127.0.0.1`). Packets arriving from external network interfaces (`172.32.8.15`, `wlan0`, `eth0`) are dropped by the OS network stack.
2. **Launch Flag Policy:** The documented run command explicitly passes `--server.address 127.0.0.1`:
   ```powershell
   streamlit run app.py --server.address 127.0.0.1
   ```
3. **CORS and XSRF Protections:** `enableCORS = true` restricts cross-origin WebSocket connections; `enableXsrfProtection = true` ensures state-altering requests carry a cryptographically random anti-forgery token.
4. **Static File Isolation:** SQLite database files (`database/*.db`), cryptographic keys (`*.key`), environment secrets (`.env`), and audit logs (`audit/audit_chain.json`) are excluded from web root static serving via `.gitignore` and reside strictly in backend application directories.

---

## 8. Credential Security, Zero-Leakage & Fail-Closed Policy

### 1. Zero-Leakage & Redaction Policy
- Plaintext passwords never appear in source code, documentation, reports, or logs.
- All credential references in public files are strictly masked as `[REDACTED]`.
- Session tokens: 256-bit URL-safe tokens generated via `secrets.token_urlsafe(32)`. The database and dashboard only store and display the 64-character SHA-256 hash `session_token_hash`.
- Cryptographic keys: Never rendered in plain text or emitted in exception traces (`CryptoIntegrityError` sanitizes key parameters).
- Audit logs: Sanitize metadata filters all dictionary keys matching `password`, `token`, `secret`, `key`, `passphrase`, or `auth` to `"[REDACTED_SECRET]"`.

### 2. Credential Invalidation Verification
- Automated test script confirmed: Old exposed passwords (`[REDACTED]`) fail authentication outright (`is_correct = False`, `status = FAILURE`).
- Database password hashes were updated via Argon2id salt stretching to newly rotated unexposed keys.

### 3. Fail-Closed Authentication Verification
- Production environment test confirmed:
  * When `APP_ENV=production`, `seed_default_users()` returns `False` and refuses to seed.
  * When `APP_ENV=production`, `config.DEMO_CREDENTIALS` is an empty dictionary `{}`.
  * Empty username or empty password fails closed immediately.
  * Corrupt or non-Argon2id password hashes fail closed immediately.
  * Missing database or missing master key fails closed immediately.

### 4. Role-Based Access Control (RBAC) Enforcement
| User Persona | Assigned Role | Clinical Vitals | Cryptographic Controls | User Administration | Blockchain Explorer |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Dr. Sarah Smith** | `medical_staff` | Full (Clear) | Request Decryption Only | **BLOCKED** | **BLOCKED** |
| **Alice CSO** | `admin` | Full (Clear) | Full (Generate, Rotate) | **GRANTED** | **GRANTED** |
| **Marcus Davis** | `auditor` | Redacted (HIPAA) | View Verification Only | **BLOCKED** | **GRANTED** |

---

## 9. Remaining Architectural Limitations & Assumptions

1. **Endpoint Memory Extraction:** If an adversary attains root/kernel execution rights on the local machine hosting the Python runtime, they can inspect process memory (`/proc/kcore` or `ReadProcessMemory`) to dump the in-memory master symmetric key. For production hardware deployments, a dedicated Hardware Security Module (HSM) or ARM TrustZone / TPM 2.0 enclave is recommended.
2. **Browser LocalStorage / Session State:** Streamlit operates as a single-page reactive application where session state is managed on the server side tied to browser cookies. In shared terminal environments (e.g. hospital nurse stations), users must explicitly click **Logout** to destroy the active session token in SQLite.
3. **Transport Layer Security (TLS):** For local execution, HTTP loopback (`127.0.0.1`) is secure because traffic never leaves the local TCP/IP stack. If remote multi-machine access is required in future production hospital deployments, a reverse proxy (e.g. NGINX with Let's Encrypt TLS 1.3 certificates) must terminate encryption before forwarding to Streamlit.

---

## 10. Final Readiness Assessment for Stage 8

The Stage 7.1 and 7.1.1 security hardening and forensic consistency cleanup is **100% COMPLETE**.

### Readiness Checklist:
- [x] All 93 regression tests pass cleanly across all 6 test files.
- [x] End-to-end integration test (`e2e_integration_test.py`) passes all 5 phases and 6 adversarial attack simulations.
- [x] Streamlit server is locked to loopback `127.0.0.1:8501`.
- [x] All actual passwords purged from README, reports, and code comments; replaced with `[REDACTED]`.
- [x] Old exposed credentials rotated and invalidated in the SQLite database.
- [x] `.env.example` contains placeholders only (`[REDACTED]`); `.env` is gitignored.
- [x] Production mode strictly blocks demo account seeding and sets `DEMO_CREDENTIALS = {}`.
- [x] Production authentication fails closed on missing database, missing keys, or corrupt hashes.
- [x] Backend RBAC functions independently of dashboard UI state.
- [x] Quick Persona Switcher strictly disabled in production mode.
- [x] RBAC enforcement verified across all 6 dashboard pages.
- [x] Zero modifications to previous AI model weights, training pipeline, or historical data.

> [!NOTE]
> In accordance with instructions, work has stopped following the completion of Stage 7.1.1. We are awaiting your explicit review and approval before beginning Stage 8 (Automated Test Suite Execution and Final Verification).
