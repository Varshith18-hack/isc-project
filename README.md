# AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

**Course**: Information Security and Cryptography (AI 331)  
**Program**: B.Tech 5th Semester, Artificial Intelligence  
**Institution**: Sardar Vallabhbhai National Institute of Technology (SVNIT), Surat  

---

## 1. Project Overview

The proliferation of Internet of Medical Things (IoMT) devices (such as infusion pumps, patient monitors, ventilators, and dialysis machines) presents serious cybersecurity and patient safety concerns. Compromised or malfunctioning devices can lead to:
- **Direct patient harm** through unauthorized dosage alterations or telemetry spoofing.
- **Data breaches** violating HIPAA/GDPR through eavesdropping on unencrypted vital signs.
- **Covert tampering** of medical activity logs to disguise malicious behavior.

This project delivers an end-to-end software prototype that unifies three core computer science disciplines:
1. **Artificial Intelligence (AI)**: Unsupervised anomaly detection via **Isolation Forest** to identify physiological telemetry anomalies and suspicious device communication bursts without relying on hardcoded rules.
2. **Cryptography**: High-grade **AES-256-GCM** authenticated encryption, **SHA-256** cryptographic digests, **HMAC** authentication tags, and **tamper-evident hash-chaining** for immutable audit trails.
3. **Information Security**: Secure user authentication, salted password hashing, fine-grained **Role-Based Access Control (RBAC)**, session management, and intrusion event monitoring.

---

## 2. System Architecture

```
                   [ Connected Medical Devices (IoMT) ]
                                   │
                                   ▼ (Simulated Telemetry Stream)
                     ┌───────────────────────────┐
                     │ Medical Device Simulator  │
                     │  (Vitals + Device Stats)  │
                     └─────────────┬─────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │ AI Anomaly Detection      │
                     │  (Isolation Forest Model) │
                     └──────┬─────────────┬──────┘
                            │             │
               [Normal Telemetry]     [Anomalous Telemetry]
                            │             │
                            ▼             ▼
                     ┌───────────────────────────┐
                     │ Cryptographic Engine      │
                     │ - AES-256-GCM Encrypt     │
                     │ - SHA-256 Hashing         │
                     │ - HMAC Authentication     │
                     └─────────────┬─────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │ Immutable Audit System    │
                     │ - Hash-Chained Audit Log  │
                     │ - Tamper-Detection Engine │
                     └─────────────┬─────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │ Security & RBAC Layer     │
                     │ - Admin / Medical Staff   │
                     │ - Session Management      │
                     └─────────────┬─────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────┐
                     │ Interactive Dashboard     │
                     │   (Streamlit Interface)   │
                     └───────────────────────────┘
```

---

## 3. Directory Structure

```
isc project/
│
├── config.py                 # Central system configuration, paths, thresholds, hyperparameters
├── requirements.txt          # Python dependencies specification
├── README.md                 # Project documentation and architectural guide
├── app.py                    # Streamlit entry point (Module 6 & Stage 7)
│
├── data/
│   ├── __init__.py
│   ├── generate_data.py      # Synthetic IoMT telemetry generator (Stage 2)
│   └── medical_device_data.csv # Generated dataset (synthetic, non-real)
│
├── models/
│   ├── __init__.py
│   ├── train_model.py        # Isolation Forest training script (Stage 3)
│   ├── anomaly_detection.py  # Anomaly inference and scoring engine (Stage 3)
│   └── saved_model.pkl       # Serialized Isolation Forest model
│
├── security/
│   ├── __init__.py
│   ├── encryption.py         # AES-256-GCM encryption/decryption (Stage 4)
│   ├── hashing.py            # SHA-256 & HMAC verification (Stage 4)
│   ├── authentication.py     # User auth & password hashing (Stage 5)
│   └── access_control.py     # Role-based access control engine (Stage 5)
│
├── audit/
│   ├── __init__.py
│   ├── audit_logger.py       # Append-only hash-chained logging (Stage 6)
│   └── integrity_checker.py  # Cryptographic chain verification engine (Stage 6)
│
├── database/
│   ├── __init__.py
│   └── database.py           # SQLite persistence for devices, users, readings
│
├── dashboard/
│   ├── __init__.py
│   └── components.py         # Modular Streamlit UI components & visualizations
│
├── tests/
│   ├── __init__.py
│   ├── test_anomaly.py       # Unit tests for ML anomaly detector (7 tests)
│   ├── test_encryption.py    # Unit tests for AES-256-GCM, HKDF & HMAC (21 tests)
│   ├── test_authentication.py # Unit tests for Argon2id, lockout, sliding timeout & RBAC (27 tests)
│   ├── test_audit.py         # Unit tests for hash-chain integrity & tampering (24 tests)
│   ├── test_audit_stage6_2.py # Unit tests for kernel locks, rollback & crash recovery (8 tests)
│   ├── test_dashboard.py     # Unit tests for Streamlit UI, HMAC verify, dynamic users & timeout (12 tests)
│   └── test_end_to_end.py    # Comprehensive E2E integration test suite (13 tests)
```

---

## 4. Technology Stack & Verification Status

| Component | Library / Tool | Purpose | Status in Environment |
| :--- | :--- | :--- | :--- |
| **Python** | Python 3.13.1 | Core execution runtime | Verified |
| **Data Manipulation** | `pandas` (v2.2.3) | Dataframe processing and aggregation | Verified |
| **Array Computing** | `numpy` (v2.2.4) | Numerical transformations | Verified |
| **Machine Learning** | `scikit-learn` (v1.8.0) | Isolation Forest unsupervised detection | Verified |
| **Cryptography** | `pycryptodome` (v4.4.0) | AES-256-GCM, SHA-256, HMAC-SHA256, HKDF | Verified |
| **Password Hashing** | `argon2-cffi` (v23.1.0) | High-entropy memory-hard password verification | Verified |
| **Data Storage** | `sqlite3` (built-in) | Relational database storage with WAL & busy timeout | Verified |
| **Web Dashboard** | `streamlit` (v1.67.0) | Interactive user interface | Verified |
| **Visualizations** | `matplotlib` & `plotly` | High-fidelity charts and metrics | Verified |
| **Benchmarking** | `psutil` (v7.0.0) | System memory and process profiling | Verified |

---

## 5. Security & Cryptographic Principles

### 1. Authenticated Encryption (AES-256-GCM)
We use **Galois/Counter Mode (GCM)** rather than legacy CBC or ECB modes. AES-GCM provides **Authenticated Encryption with Associated Data (AEAD)**:
- **Confidentiality**: Prevents unauthorized viewing of vital patient telemetry.
- **Integrity & Authenticity**: Generates a 128-bit authentication tag. Any bit-flip or ciphertext tampering causes decryption to fail outright, preventing replay and bit-flipping attacks.
- **Unique IV/Nonce**: A unique 96-bit Initialization Vector is generated for every encryption operation.

### 2. Hash Chaining for Tamper-Evident Audit Logs
Every audit entry $E_i$ contains:
$$\text{Hash}_i = \text{SHA-256}(E_i \,||\, \text{Hash}_{i-1})$$
where $\text{Hash}_0$ is the genesis hash. If an adversary modifies, deletes, or inserts an entry in the audit database, the hash chain breaks at the modified entry, enabling instant detection during audit verification.

### 3. Role-Based Access Control (RBAC)
- **`admin`**: Full system permissions, user administration, crypto key management, and audit verification.
- **`medical_staff`**: Telemetry viewing, live alerts, and authorized decryption requests for assigned patients.
- **`auditor`**: Read-only verification access to the cryptographic audit trail.

---

## 6. Development Stages

- [x] **Stage 1**: Environment inspection, dependency verification, project structure creation, configuration setup.
- [x] **Stage 2**: Synthetic medical device telemetry data generation (`generate_data.py`).
- [x] **Stage 3 & 3.1**: Isolation Forest model training, temporal drift audit, and validation-only threshold calibration (`train_model.py`, `anomaly_detection.py`).
- [x] **Stage 4**: AES-256-GCM authenticated encryption, SHA-256 hashing, HMAC authentication, and secure key management (`security/encryption.py`, `security/hashing.py`, `security/pipeline_demo.py`).
- [x] **Stage 5**: User authentication, password hashing, and RBAC (`authentication.py`, `access_control.py`).
- [x] **Stage 6**: Cryptographic audit logging and hash-chain verification (`audit_logger.py`, `integrity_checker.py`).
- [x] **Stage 7 & 7.1**: Streamlit interactive dashboard integration and security hardening (`app.py`, `components.py`).
- [x] **Stage 8**: Automated test suite execution, end-to-end system validation, performance benchmarking, and final verification report (`tests/test_end_to_end.py`, 106 tests passed).
- [x] **Stage 9**: Project demonstration, final documentation, and presentation guide (`VIVA_PRESENTATION_GUIDE.md`, `DEMO_SCRIPT.md`).

---

## 7. Stage 4 Cryptography Architecture & Specifications

### 1. AES-256-GCM Authenticated Encryption (AEAD)
- **Mode**: Galois/Counter Mode (GCM), providing simultaneous confidentiality, integrity, and authenticity.
- **Key Size**: 256 bits (32 bytes).
- **Nonce (Initialization Vector)**: 96 bits (12 bytes) generated freshly via cryptographically secure pseudo-random number generator (`Crypto.Random.get_random_bytes`) for every single encryption. Nonces are **never reused**.
- **Authentication Tag**: 128 bits (16 bytes) computed by the Galois Field multiplication $GF(2^{128})$. Any bit-flip in the ciphertext or tampering with the tag causes `decrypt_and_verify()` to immediately raise `CryptoIntegrityError` before returning corrupt data.
- **Authenticated Associated Data (AAD)**: Device metadata (e.g., `device_id`, `timestamp`, `routing_destination`) is cryptographically bound into the authentication tag without being encrypted, preventing spoofed device re-routing.

### 2. SHA-256 Cryptographic Hashing
- **Digest Size**: 256 bits (64 hexadecimal characters).
- **Canonical Serialization**: Dictionaries are deterministically serialized with sorted keys and compact separators (`json.dumps(data, sort_keys=True, separators=(',', ':'))`), ensuring identical inputs always generate identical digests regardless of whitespace or dictionary key ordering.
- **Avalanche Effect**: Demonstrates strong diffusion ($>48\%$ bit flip on a single $0.1\text{ bpm}$ parameter alteration).
- **Constant-Time Verification**: Verifies digests using `hmac.compare_digest` to prevent side-channel timing attacks.

### 3. HMAC-SHA256 Message Authentication
- **Formula**: $\text{HMAC}(K, m) = H((K \oplus \text{opad}) \parallel H((K \oplus \text{ipad}) \parallel m))$
- **Key Separation**: Uses a dedicated 256-bit authentication key strictly separated from the AES encryption key via HKDF-SHA256 domain separation:
  $$K_{\text{HMAC}} = \text{HKDF}(K_{\text{master}}, \text{salt}=\text{"svnit-iomt-hmac-salt-v1"}, \text{context}=\text{"svnit-iomt-hmac-auth:global"})$$
- **Tamper Protection**: Unlike unkeyed hashes, an active network adversary who modifies patient telemetry cannot forge a valid HMAC tag without possessing the secret key $K_{\text{HMAC}}$.

### 4. Key Management Architecture & HKDF Hardening (Stage 4.1)
- **Zero-Hardcoding Policy**: Secret keys are never committed or hardcoded in source files.
- **Storage & Stability**: Master keys are loaded from the environment (`MED_DEVICE_MASTER_KEY` / `MED_DEVICE_HMAC_KEY`) or an ignored `.env` file (see `.env.example`). If absent, a cryptographically secure 256-bit key is generated once and persisted to `security/.master_key.key` (with `.gitignore` protection).
- **OS-Level Permissions Lockdown**: The master key storage file is locked using OS-specific access controls:
  - **Windows NTFS**: Uses `icacls` to disable ACL inheritance and grant `(R,W)` exclusively to the current user.
  - **POSIX**: Enforces strict `0600` permissions (owner read/write only).
- **Per-Device Key Compartmentalization via HKDF-SHA256 (RFC 5869 / NIST SP 800-56C)**:
  Because the master key has 256 bits of true cryptographic entropy, HKDF extract-and-expand is mathematically optimal and provides formal domain separation:
  $$K_{\text{device}} = \text{HKDF}(K_{\text{master}}, \text{salt}=\text{"svnit-iomt-security-salt-v1"}, \text{context}=\text{"svnit-iomt-device-key:"}\parallel\text{device\_id})$$
  If one device is physically compromised, all other medical devices remain cryptographically isolated.
- **Key Rotation Considerations**: Production deployments should employ key versioning headers (e.g. `kid` or `v1`), automated key rotation intervals, and an ephemeral key management service (KMS / HSM). Master key backup requires offline encrypted escrow with split-knowledge (M-of-N threshold).

### 5. Cryptography Workflow Diagram

```
[ Medical Telemetry Record ] ───► [ Canonical JSON Serialization ]
                                                 │
                   ┌─────────────────────────────┼─────────────────────────────┐
                   ▼                             ▼                             ▼
         [ SHA-256 Hasher ]             [ HMAC-SHA256 Signer ]       [ AES-256-GCM Cipher ]
                   │                             │                             │
                   ▼                             ▼                             ▼
         [ 64-char Hash Digest ]       [ 64-char HMAC Auth Tag ]     [ Fresh 96-bit Nonce ]
                   │                             │                   [ Ciphertext Hex Payload ]
                   │                             │                   [ 128-bit GCM Auth Tag ]
                   │                             │                   [ Bound Associated Data (AAD) ]
                   └─────────────────────────────┼─────────────────────────────┘
                                                 ▼
                               [ Secure Network Transmission ]
                                                 │
                                                 ▼
                                 [ Cryptographic Verification ]
                                                 ├─► Verify HMAC Tag (Constant-time)
                                                 ├─► Verify AES-GCM Tag & Decrypt
                                                 └─► Verify SHA-256 Digest
                                                 │
                                   [ Authentic Telemetry Admitted ]
```

### 6. Security Limitations & Assumptions
- **Endpoint Compromise**: If an attacker gains full root access to the medical device memory, they can read the in-memory symmetric key. Hardware Secure Enclaves (TPM / ARM TrustZone) are recommended for physical hardware production.
- **Replay Attacks**: Mitigated by binding monotonically increasing sequence numbers and timestamps into the Authenticated Associated Data (AAD).

---

## 8. Verification Commands for Stage 4

To run the AES-256-GCM encryption and tamper resistance demo:
```powershell
python security/encryption.py
```

To run the SHA-256 and HMAC authentication demo:
```powershell
python security/hashing.py
```

To run the end-to-end integrated telemetry cryptographic pipeline:
```powershell
python security/pipeline_demo.py
```

To run the complete automated cryptographic unit test suite (21 tests):
```powershell
python -m unittest tests/test_encryption.py
```

To run the automated information security & RBAC unit test suite (24 tests):
```powershell
python -m unittest tests/test_authentication.py
```

To run all project unit test suites (52 tests total):
```powershell
python -m unittest discover tests
```

---

## 9. Stage 5 Information Security & RBAC Architecture

### 1. Argon2id Password Hashing
- **Algorithm**: Argon2id (RFC 9106, OWASP recommendation), a hybrid of Argon2d and Argon2i providing defense against both side-channel cache timing attacks and GPU-accelerated brute-force attacks.
- **Parameters**: `memory_cost=65536` (64 MB per hash), `time_cost=2` (2 iterations), `parallelism=1`, `hash_len=32`.
- **Salt Generation**: Automatically generated per-password via OS-level CSPRNG (`secrets`).
- **Timing Attack Resistance**: Verified using constant-time comparison in `argon2-cffi`.

### 2. Brute-Force & Account Lockout Defense
- **Max Failed Attempts**: 5 consecutive failed authentications.
- **Lockout Duration**: 15 minutes (`LOCKOUT_DURATION_MINUTES = 15`).
- **Automatic Reset**: Successful authentication clears failed attempts and unlocks account.
- **Expiration Recovery**: Accounts automatically unlock once the 15-minute window elapses, allowing normal authentication.

### 3. Secure Session Management (Zero Plaintext Token Storage)
- **Token Generation**: 256-bit entropy generated with `secrets.token_urlsafe(32)`.
- **Database Storage**: The raw token is **never stored in the database**. The SQLite database stores only the deterministic SHA-256 hash `session_token_hash`.
- **Sliding Expiration**: 30-minute sliding window; each authenticated request refreshes the expiration window.
- **Session Invalidation**: Calling `logout_user()` sets `is_active = 0` immediately, permanently preventing replay.

### 4. Role-Based Access Control (RBAC) Permission Matrix

| Role | Description | Key Permissions Granted | Explicitly Denied Permissions |
| :--- | :--- | :--- | :--- |
| `admin` | System Administrator | `manage_users`, `access_system_config`, `view_audit_logs`, `manage_device_access`, `configure_crypto`, `verify_audit_chain`, `trigger_simulation`, `view_readings`, `view_anomaly_alerts`, `request_decryption` | None |
| `medical_staff` | Doctors & Nurses | `view_readings`, `view_anomaly_alerts`, `access_authorized_devices`, `view_dashboard`, `request_decryption` | `manage_users`, `configure_crypto`, `access_system_config`, `view_audit_logs` |
| `auditor` | Security Compliance | `view_audit_logs`, `view_auth_events`, `view_crypto_verification`, `verify_audit_chain`, `view_dashboard` | `manage_users`, `manage_device_access`, `configure_crypto`, `trigger_simulation` |

### 5. Backend Authorization Enforcement
- Reusable decorator `@require_permission(permission_name)` protects API endpoints and service functions.
- Any violation triggers an `AccessDeniedError` and immediately logs an immutable `UNAUTHORIZED_ACCESS_ATTEMPT` event with `BLOCKED` status in SQLite.
- Clinical telemetry filtering redacts physiological patient vitals when viewed by auditors, enforcing strict least privilege.

### 6. Verification Commands for Stage 5

To run the authentication and Argon2id demonstration:
```powershell
python security/authentication.py
```

To run the RBAC and authorization enforcement demonstration:
```powershell
python security/access_control.py
```

To run the information security test suite (24 tests):
```powershell
python -m unittest tests/test_authentication.py
```

To run the secure audit hash-chain unit test suite (18 tests):
```powershell
python -m unittest tests/test_audit.py
```

To run all project unit test suites (70 tests total):
```powershell
python -m unittest discover tests
```

---

## 10. Stage 6 Secure Audit System Architecture

### 1. Append-Only Cryptographic Hash-Chain Logging
- **File Storage**: Persisted to `audit/audit_chain.json` with atomic rename operations (`os.replace`) to guarantee zero file truncation or corruption under sudden termination.
- **Genesis Block**: The initial state starts at `event_id = 1` bound to:
  $$\text{Hash}_0 = \underbrace{\text{"0000000000000000000000000000000000000000000000000000000000000000"}}_{64\text{ zeros}}$$
- **Mathematical Formulation for Sequential Blocks**:
  $$\text{PayloadHash}_i = \text{SHA-256}(\text{Canonical}(\text{event\_details}_i))$$
  $$\text{Header}_i = \{\text{event\_id}_i, \text{timestamp}_i, \text{user\_id}_i, \text{event\_type}_i, \text{PayloadHash}_i, \text{Hash}_{i-1}\}$$
  $$\text{Hash}_i = \text{SHA-256}(\text{Canonical}(\text{Header}_i))$$
- **Institutional HMAC-SHA256 Authenticity**:
  $$\text{HMAC\_Tag}_i = \text{HMAC}(K_{\text{HMAC}}, \text{Hash}_i)$$
  Seals every block against unkeyed adversaries. Even if an attacker has read access to the audit chain, they cannot recompute valid current hashes without the institutional HMAC key derived via HKDF-SHA256.

### 2. Forensic Integrity Checker (`audit/integrity_checker.py`)
Traverses the blockchain from Genesis to the latest block, verifying 5 fundamental security properties:
1. **Intra-Block Payload Integrity**: Recalculates $\text{SHA-256}(\text{event\_details})$ and compares with `payload_hash` (detects modified vital signs or altered event details).
2. **Block Header Integrity**: Recalculates $\text{SHA-256}(\text{Header})$ and compares with `current_hash` (detects altered timestamps, user IDs, or event types).
3. **Sequential Cryptographic Linkage**: Verifies $\text{previous\_hash}_i = \text{current\_hash}_{i-1}$ (detects deleted blocks, broken links, or chain truncation).
4. **Monotonic Sequence Ordering**: Verifies $\text{event\_id}_i = i$ (detects reordered or spliced records).
5. **HMAC Signature Authenticity**: Constant-time verification using `hmac.compare_digest` against $K_{\text{HMAC}}$ (detects forged blocks).

### 3. Adversarial Attack Detection Matrix

| Attack Vector | Simulated Action | Detection Mechanism | Diagnostic Error Code |
| :--- | :--- | :--- | :--- |
| **Payload Tampering** | Attacker modifies patient heart rate or dosage in block | Recalculated payload hash mismatch | `PAYLOAD_TAMPERED` |
| **Metadata Forgery** | Attacker rewrites event timestamp or user ID | Recalculated block header hash mismatch | `BLOCK_HASH_MISMATCH` |
| **Log Deletion** | Attacker deletes an incriminating unauthorized access block | Sequence gap and broken previous_hash link | `ENTRY_ID_SEQUENCE_ERROR` / `CHAIN_LINK_BROKEN` |
| **Block Reordering** | Attacker swaps two records to conceal event timeline | Sequence disruption and linkage mismatch | `ENTRY_ID_SEQUENCE_ERROR` / `CHAIN_LINK_BROKEN` |
| **Rogue Block Insertion** | Attacker injects a synthetic or spoofed audit entry | Hash link mismatch on subsequent block | `ENTRY_ID_SEQUENCE_ERROR` / `CHAIN_LINK_BROKEN` |
| **Signature Forgery** | Attacker re-hashes block with forged or invalid HMAC tag | Constant-time HMAC comparison failure | `HMAC_VERIFICATION_FAILED` |
| **Genesis Corruption** | Attacker alters initial chain state | Genesis previous_hash != 64 zeros | `INVALID_INITIAL_STATE` |

### 4. Verification Commands for Stage 6, 6.1 & 6.2

To run the interactive secure audit logger demonstration:
```powershell
python audit/audit_logger.py
```

To run the audit chain integrity checker and tamper detection demonstration:
```powershell
python audit/integrity_checker.py
```

To run the end-to-end telemetry and audit pipeline demonstration:
```powershell
python security/pipeline_demo.py
```

To run the automated audit test suites (32 tests total across Stage 6, 6.1 and 6.2):
```powershell
python -m unittest tests/test_audit.py
python -m unittest tests/test_audit_stage6_2.py
```

To run the dashboard integration test suite (9 tests):
```powershell
python -m unittest tests/test_dashboard.py
```

To run all project regression test suites across all 6 test files (93 tests total):
```powershell
python -m unittest discover tests -v
```

### Regression Test Suite Breakdown (106 Tests Verified):
| Test Module | Subsystem Tested | Test Count | Status |
| :--- | :--- | :---: | :---: |
| `tests/test_anomaly.py` | Isolation Forest AI Engine & Pipeline | 7 | PASS |
| `tests/test_encryption.py` | AES-256-GCM AEAD, Nonce Uniqueness & HKDF-SHA256 | 21 | PASS |
| `tests/test_authentication.py` | Argon2id Auth, Lockout, Sliding Sessions & RBAC | 27 | PASS |
| `tests/test_audit.py` | SHA-256 Chaining, HMAC Signatures & Tamper Detection | 24 | PASS |
| `tests/test_audit_stage6_2.py` | Kernel Byte Locks, Crash Recovery & Rollback Defense | 8 | PASS |
| `tests/test_dashboard.py` | Streamlit Visualizations, Sandboxed Attacks, HMAC & Timeout | 12 | PASS |
| `tests/test_end_to_end.py` | Full E2E Integration, Scenarios A-F & Failure Recovery | 13 | PASS |
| **Total Regression Suite** | **Comprehensive Full-System Security & Integrity** | **112** | **PASS (100%)** |

---

## 11. Stage 7: Interactive Streamlit Dashboard Implementation

### 1. Launch Command & Network Security
To launch the interactive hospital operations and cybersecurity dashboard:
```powershell
streamlit run app.py --server.address 127.0.0.1
```

> [!IMPORTANT]
> **Network Lockdown Policy**: `.streamlit/config.toml` strictly enforces `server.address = "127.0.0.1"`, preventing unauthorized network binding to local campus LANs (such as `172.32.8.15`). The dashboard is bound strictly to local loopback. Cross-Site Request Forgery (`enableXsrfProtection = true`) and Headless execution are enforced.

The application is securely accessed on `http://127.0.0.1:8501`.

### 2. Multi-Page Architecture & Capabilities

The dashboard integrates all 6 project subsystems with role-based access control and live cryptographic operations:

1. **🏥 Hospital Overview & Executive Health**:
   - Executive telemetry KPIs (10,000 observations, 5 active IoMT devices, 584 detected anomalies, 100% cryptographic integrity).
   - Real-time connected IoMT device fleet grid (Patient Monitor, Mechanical Ventilator, Smart Infusion Pump, ECG Holter, Dialysis Machine).
   - Live Threat Intelligence feed distinguishing physiological medical anomalies from cyber intrusions.
   - Recent system activity and security event monitoring.

2. **🩺 Connected Medical Devices (IoMT Telemetry)**:
   - Device selector with profile, location, firmware, and derived HKDF key status.
   - Clinical physiological vitals stream (interactive multi-axis Plotly charts: Heart Rate, Blood Pressure Systolic/Diastolic, SpO2 with anomaly markers).
   - Network traffic packets-per-minute time series vs. upper baseline threshold (60 pkts/min).
   - **HIPAA Data Redaction Engine**: Enforces role-based privacy—clinical medical staff view full vitals, while auditors view partially masked identifiers (`DEV-***-002`) and redacted clinical fields.

3. **🤖 AI Anomaly Detection Lab**:
   - Live inference engine powered by the trained **Isolation Forest** pipeline (`models/saved_model.pkl`).
   - Interactive telemetry sliders with 6 attack/physiological threat presets (Tachycardia, Acute Hypoxemia, DDoS Burst, Telemetry Spoofing, Malignant Hyperthermia).
   - Batch CSV file uploader: Ingest and score arbitrary telemetry CSVs, with instant downloadable scored results.
   - Real-time anomaly gauge chart with calibrated decision threshold ($\tau = 0.5809$).
   - Stage 3.1 Model Performance Evaluation Showcase: Confusion matrix, score distribution, per-category detection rates (100% recall), and ROC/PR curves ($AUC = 0.9984$).

4. **🔐 Cryptography and Security Lab**:
   - **AES-256-GCM AEAD Lab**: Encrypt and decrypt custom medical records with 96-bit random nonces, 128-bit authentication tags, and Authenticated Associated Data (AAD) binding.
   - **Active Adversary Attack Simulator**: Demonstrates live detection and fail-safe abortion of in-transit MITM ciphertext bit-flips, forged authentication tags, spoofed AAD headers, and unauthorized key decryption.
   - **Nonce Uniqueness Verification**: Demonstrates that identical plaintexts generate distinct nonces, ciphertexts, and tags to prevent replay attacks.
   - **SHA-256 & HMAC-SHA256 Authenticity Lab**: Canonical JSON hashing, institutional key signing, and dedicated constant-time HMAC verification (`hmac.compare_digest`) with preserved original signatures and instant tamper detection.

5. **🛡️ Authentication and RBAC Management**:
   - Secure login and logout with **Argon2id** password verification.
   - Active user session inspector showing SHA-256 token digest, last user interaction timestamp, and sliding 30-minute inactivity timeout.
   - **Brute-Force Lockout Testing Console**: Dynamically fetches all active registered users from the SQLite database/session state (including newly registered users such as `surya`) with interactive 5-attempt/15-minute defensive lockout counters and admin unlocking.
   - **Session Inactivity Timeout Testing Console**: Interactive console with configurable test durations (1-min, 2-min, 30-min production policy), active session renewal (`validate_session`), fast-forward inactivity simulation, automatic backend session expiration, redirect with `"SESSION EXPIRED – Please authenticate again."`, expired token reuse rejection, and real-time `SESSION_EXPIRED` event logging in SQLite.
   - **Administrative User Management**: Allows authorized administrators (`admin` role) to view users, register new accounts, modify roles (with automatic session invalidation), and lock/unlock accounts. Non-admin access is blocked and logged as `UNAUTHORIZED_ACCESS_ATTEMPT`.
   - Searchable security event history from SQLite database.

6. **⛓️ Secure Audit Blockchain Explorer**:
   - Full ledger browser displaying block headers, payload hashes, backward links, institutional HMAC-SHA256 signatures, and zero-leakage sanitized details.
   - **One-Click Forensic Verifier**: Traverses the blockchain, validating SHA-256 linkage, HMAC signatures, external checkpoints, and monotonic SQLite anchors. Access is restricted to `auditor` and `admin` roles.
   - **Isolated Sandbox Adversary Attack Simulator**: Safely executes destructive attacks (payload modification, header tampering, intermediate block deletion, tail truncation, block reordering, checkpoint rollback, and file deletion) strictly within an isolated sandbox directory (`audit/.demo_sandbox/`). The production audit ledger is never modified or compromised.

### 3. Account Roles & Configurable Credentials

Demo user accounts and default credentials are configured via environment variables (see `.env.example`) and loaded through `config.py`. In production (`APP_ENV=production`), automatic account seeding and the sidebar persona switcher are disabled.

| Role | Default Username | Environment Variable for Password | Default Access Scope |
| :--- | :--- | :--- | :--- |
| `medical_staff` | `dr_smith` | `DEMO_DOCTOR_PASSWORD` | Clinical Telemetry, Physiological Vitals, Alert Inspection |
| `admin` | `admin` | `DEMO_ADMIN_PASSWORD` | Full Administration, Cryptographic Controls, User Management |
| `auditor` | `auditor_davis` | `DEMO_AUDITOR_PASSWORD` | Audit Chain Verification, Redacted Clinical Vitals, Event Logs |

*(Note: In development/demo mode (`DEMO_MODE=true`), the sidebar includes an authenticated Quick Persona Switcher for evaluation workflows. In production mode (`APP_ENV=production`), this switcher is completely hidden and genuine Argon2id authentication is enforced).*

---

## 12. Stage 8: Final System Integration, End-to-End Validation & Performance Benchmarking

### 1. Integration Scope & Architecture

Stage 8 performs full-system end-to-end integration and forensic verification, unifying all six subsystems into a cohesive, demonstrably secure pipeline:

```
[IoMT Telemetry Source]
       │ (10,000 synthetic observations across 5 connected clinical devices)
       ▼
[Feature Extraction & Z-Score Engineering]
       │ (8 standardized features: physiological vitals + statistical aggregates)
       ▼
[AI Isolation Forest Inference (τ = 0.5809)]
       │ (Scoring: NORMAL vs ANOMALY, Severity & Contributing Explainability)
       ▼
[HKDF-SHA256 Key Derivation]
       │ (Cryptographic domain separation: Device-specific AES & HMAC keys)
       ▼
[AES-256-GCM AEAD Authenticated Encryption]
       │ (96-bit fresh random nonce, 128-bit MAC tag, AAD header binding)
       ▼
[Relational Storage (SQLite with WAL & Busy Timeout)]
       │ (Stores encrypted ciphertext, sessions, and indexed security events)
       ▼
[Append-Only Hash-Chained Audit Ledger]
       │ (SHA-256 block linking, HMAC signatures, dual external checkpoints)
       ▼
[Role-Based Streamlit Dashboard (127.0.0.1 Loopback)]
       │ (6 pages with least-privilege clinical data redaction & live crypto)
       ▼
[Forensic Verifier & Adversarial Defense Engine]
       (Live detection of MITM bit-flips, AAD spoofing, rollback & truncation)
```

### 2. End-to-End Test Scenario Coverage (`tests/test_end_to_end.py`)

The dedicated integration test suite verifies the complete hospital operations workflow under authentic operating conditions:

| Scenario | Objective | Validation Method | Result |
| :--- | :--- | :--- | :---: |
| **Scenario A** | Normal Telemetry Ingestion | AI scoring (< $\tau$), AES-256-GCM encryption, DB storage, audit logging | **PASS** |
| **Scenario B** | Medical & Cyber Anomaly Detection | Severe Tachycardia (HR=185) & DoS flood (Activity=125) with explainability | **PASS** |
| **Scenario C** | Unauthorized Access Defense | 5-attempt brute-force lockout, session expiration, login security alerts | **PASS** |
| **Scenario D** | Cryptographic Attack Resistance | Ciphertext bit-flips, forged auth tags, spoofed AAD, and unauthorized keys rejected | **PASS** |
| **Scenario E** | Audit Chain Tamper Detection | Intra-block payload tampering, header forgery, intermediate deletion, and rollback | **PASS** |
| **Scenario F** | Multi-Role Workflow & HIPAA Redaction | Least-privilege redaction (`medical_staff` full vitals vs `auditor` masked vitals) | **PASS** |
| **Concurrency** | Multi-Threaded Stress Test | 10 concurrent threads appending records with kernel file locking | **PASS** |
| **Crash Recovery** | Crash Consistency | Deterministic reconciliation of lagging checkpoint after abrupt system kill | **PASS** |
| **Zero Leakage** | Confidentiality Assurance | Recursive credential scrubber ensures zero passwords/keys enter logs | **PASS** |

### 3. Empirical Performance Benchmarking Results

Measured using `security/benchmark_performance.py` across 1,000 iterations per subsystem on Python 3.13.1 (Windows 64-bit):

| Benchmark Metric | Measured Performance | Institutional Requirement / Target | Assessment |
| :--- | :---: | :---: | :---: |
| **AI Inference Latency (Mean)** | **15.94 ms** | $< 50.0\text{ ms}$ | **OPTIMAL** |
| **AI Inference Latency (Median)** | **15.25 ms** | $< 50.0\text{ ms}$ | **OPTIMAL** |
| **AI Inference Latency (95th %)** | **18.72 ms** | $< 100.0\text{ ms}$ | **OPTIMAL** |
| **AI Throughput** | **62.7 inferences/sec** | $> 20.0\text{ inf/sec}$ | **OPTIMAL** |
| **AES-256-GCM Encryption (Mean)** | **0.1406 ms** | $< 2.0\text{ ms}$ | **REAL-TIME** |
| **AES-256-GCM Encryption Throughput** | **7,113.5 enc/sec** | $> 1,000\text{ enc/sec}$ | **REAL-TIME** |
| **AES-256-GCM Decryption (Mean)** | **0.1108 ms** | $< 2.0\text{ ms}$ | **REAL-TIME** |
| **AES-256-GCM Decryption Throughput** | **9,023.6 dec/sec** | $> 1,000\text{ dec/sec}$ | **REAL-TIME** |
| **Full Pipeline Throughput (AI+AEAD)** | **64.4 records/sec** | $> 20.0\text{ rec/sec}$ | **OPTIMAL** |
| **Dashboard Dataset Ingestion (10k rows)** | **38.35 ms** | $< 500.0\text{ ms}$ | **INSTANT** |
| **Dashboard Vitals Chart Generation** | **99.90 ms** | $< 250.0\text{ ms}$ | **SMOOTH** |
| **Dashboard Page 1 Total Load Time** | **184.14 ms** | $< 1,000.0\text{ ms}$ | **FLUID** |
| **Audit Verification (100 Blocks)** | **1,131.74 ms** (11.3 ms/block) | $< 50.0\text{ ms/block}$ | **FORENSIC** |
| **Audit Verification (500 Blocks)** | **7,203.77 ms** (14.4 ms/block) | $< 50.0\text{ ms/block}$ | **FORENSIC** |
| **Concurrent Ingestion (5 Devices)** | **14.4 records/sec** | $> 5.0\text{ rec/sec}$ | **SCALABLE** |
| **Process Memory RSS (Baseline)** | **219.43 MB** | $< 500.0\text{ MB}$ | **LIGHTWEIGHT** |
| **Process Memory RSS (Peak Delta)** | **+15.25 MB** | $< 100.0\text{ MB}$ | **BOUNDED** |

### 4. Stage 8 Verification Commands

To run the complete automated test suite (106 tests across all 7 test files):
```powershell
python -m unittest discover -s tests -v
```

To run the dedicated end-to-end integration and adversarial test suite:
```powershell
python -m unittest tests/test_end_to_end.py -v
```

To run the end-to-end multi-device integration demonstration:
```powershell
python security/e2e_integration_test.py
```

To run the empirical performance and latency benchmarking engine:
```powershell
python security/benchmark_performance.py
```

### 5. Academic Prototype Classification, Execution Analysis & Operational Limitations

> [!IMPORTANT]
> **Prototype Classification**: This software is an **academically validated prototype** developed for *Information Security and Cryptography (AI 331)* at SVNIT Surat. It is **not approved for clinical production** and has not undergone formal medical device regulatory certification (such as FDA 510(k), IEC 62304, or ISO 13485).

#### 1. Test Suite Execution Duration Analysis
- The sum of reported execution times across individual test suites is **18.921 seconds**.
- Full test discovery runs range between **19.616 seconds** (warm run) and **26.077 seconds** (initial cold run).
- **Structural Explanations**:
  1. Discovery overhead and dynamic import of dependencies (`pandas`, `scikit-learn`, `joblib`, `streamlit`, `plotly`, `pycryptodome`, `argon2-cffi`).
  2. Sequential execution of heavy class fixtures (`setUpClass`): In discovery mode, all class fixtures run in a single process, including Argon2id key derivations and database setup.
  3. External process creation: `test_audit.py` and `test_audit_stage6_2.py` spawn subprocesses via `subprocess.run` to test abrupt process termination (`os._exit`) and kernel lock cleanup.
  4. System load and scheduling variability between test runs. *Note: Attributing timing deltas to disk caching specifically cannot be asserted as proven fact without low-level OS kernel I/O tracing.*

#### 2. Headless AppTest vs. Actual Browser Verification
- All six Streamlit pages were verified headlessly using `streamlit.testing.v1.AppTest`, confirming **0 unhandled exceptions**, correct widget state flow, and backend data retrieval.
- `AppTest` does **not** evaluate client-side JavaScript execution (interactive Plotly tooltips/pan/zoom), browser DOM rendering, CSS styling, or cross-browser compatibility. True clinical deployment requires full browser automation (e.g., Playwright or Selenium).

#### 3. Localhost-Only Network Binding & Potential Override Paths
- Documented launch command enforces loopback: `streamlit run app.py --server.address 127.0.0.1`.
- `.streamlit/config.toml` enforces `address = "127.0.0.1"`, `enableCORS = true`, and `enableXsrfProtection = true`.
- **Identified Override Paths**:
  1. CLI arguments: Passing `--server.address 0.0.0.0` on the command line overrides `config.toml`.
  2. Environment variables: Setting `STREAMLIT_SERVER_ADDRESS=0.0.0.0` overrides local files.
  3. User home config: `~/.streamlit/config.toml` if present.
  4. Reverse proxies / tunnels: Port forwarding utilities (e.g., ngrok, Cloudflare Tunnel, Nginx) expose port 8501 externally even if bound to 127.0.0.1 locally.

#### 4. Remaining Technical Limitations & Risks
1. **Single-Node SQLite Scalability**: SQLite in WAL mode handles $\approx 15-20\text{ records/sec}$ concurrent writes with kernel locks. High-throughput hospital networks ($> 500$ concurrent devices) require clustered PostgreSQL.
2. **Runtime Master-Key Memory Exposure**: The master cryptographic key is held in process RAM during execution. Mitigating memory dumps against root attackers requires hardware-enforced secure enclaves (Intel SGX, ARM TrustZone).
3. **Physiological Concept Drift**: Patient baselines shift over extended hospital stays; adaptive offline retraining on validated baselines is required.
4. **Clinical Validation & Clearances**: The system requires formal clinical trials and medical device regulatory clearance (**FDA 510(k)**, **IEC 62304**, **ISO 13485**) prior to healthcare adoption.

---

## 13. Stage 9: Project Demonstration, Defense Guide & Presentation Outline

### 1. Dedicated Defense Resources
Two comprehensive documentation guides have been authored for academic evaluation and committee defense:
1. [`VIVA_PRESENTATION_GUIDE.md`](file:///c:/Users/Prasad/OneDrive/Desktop/isc%20project/VIVA_PRESENTATION_GUIDE.md):
   - Theoretical & mathematical foundations across all 4 pillars (Isolation Forest $s(x,n)$, AES-256-GCM AEAD, Argon2id, SHA-256 hash chaining).
   - Top 10 high-frequency viva voce examiner questions and model answers.
   - 10-slide PowerPoint / PDF presentation deck outline.
   - Examiner trap questions and defensive strategies.
2. [`DEMO_SCRIPT.md`](file:///c:/Users/Prasad/OneDrive/Desktop/isc%20project/DEMO_SCRIPT.md):
   - 5-Minute Fast-Track live demonstration script for time-constrained evaluations.
   - 15-Minute Comprehensive Deep-Dive demonstration flow covering all six dashboard pages.
   - Live attack simulation quick-reference table (MITM bit-flips, AAD spoofing, tail truncation, rollback).
   - Emergency troubleshooting commands.

### 2. Live Demonstration Quick Commands
```powershell
# 1. Terminal Verification of 106 Automated Tests
python -m unittest discover -s tests -v

# 2. Standalone Multi-Device Pipeline & Active Adversarial Interception
python security/e2e_integration_test.py

# 3. Empirical Latency, Throughput & Memory Profiling
python security/benchmark_performance.py

# 4. Launch Interactive Streamlit Dashboard (Local Loopback)
streamlit run app.py --server.address 127.0.0.1
```




