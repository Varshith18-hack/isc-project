# LIVE DEMONSTRATION & VIVA WALKTHROUGH SCRIPT
# AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices (IoMT)

**Course:** Information Security and Cryptography (AI 331)  
**Institution:** Sardar Vallabhbhai National Institute of Technology (SVNIT), Surat  
**Target Audience:** Professor, External Examiner, and Evaluation Committee  
**Evaluation Stage:** Stage 9 — Comprehensive Project Demonstration & Defense Guide  
**Status:** 106/106 Tests Verified (100% Pass Rate) | Academically Validated Prototype; Not Approved for Clinical Production

---

## 1. Quick Launch Cheatsheet

Before the professor or examiner sits down, ensure your environment is prepared:

```powershell
# Navigate to project directory
cd "c:\Users\Prasad\OneDrive\Desktop\isc project"

# Step 1: Quick verification run (106 tests in ~20 seconds)
python -m unittest discover -s tests -v

# Step 2: Launch the interactive Streamlit dashboard (strictly bound to localhost)
streamlit run app.py --server.address 127.0.0.1
```

The dashboard opens in your browser at: **`http://127.0.0.1:8501`**

---

## 2. Option A: Five-Minute Fast-Track Demo (For Time-Constrained Examiners)

*Use this path if the examiner says: "Show me the highlights in 5 minutes."*

### Minute 1: The Automated Test Suite & Code Quality
- **Action**: In the terminal, show the 106 passed tests:
  ```powershell
  python -m unittest discover -s tests -v
  ```
- **Say**: *"We have implemented a fully automated regression and end-to-end integration suite of 106 tests across 7 modules. It validates our AI inference, AES-256-GCM authenticated encryption, Argon2id authentication, RBAC, and hash-chained blockchain forensics. All 106 tests pass in 20 seconds with 100% success."*

### Minute 2: Page 3 — Real-Time AI Anomaly Detection & Explainability
- **Action**: In the Streamlit dashboard sidebar, select **"🤖 AI Anomaly Detection Lab"**.
- **Action**: Click the preset button: **"Acute Cardiac Crisis (Tachycardia)"**.
- **Action**: Click **"Run Anomaly Inference"**.
- **Show**:
  - The gauge needle swings into the **CRITICAL** red zone ($s \approx 0.68 > \tau = 0.5809$).
  - Point to the **Explainability breakdown**:
    > *"Heart Rate is critically high (182.0 vs normal ~75.1), Systolic Bp is critically high (185.0 vs normal ~114.9)"*
- **Say**: *"Our Isolation Forest model is calibrated to a decision boundary of $\tau = 0.5809$. It achieves 100% recall on critical physiological emergencies with a 15.9 ms latency. Crucially, it provides deterministic clinical explainability rather than being a black box."*

### Minute 3: Page 4 — Active MITM Cryptographic Bit-Flip Defense
- **Action**: Select **"🔐 Cryptography and Security Lab"**.
- **Action**: Scroll to the **"Active Adversary Attack Simulator"** section.
- **Action**: Click the red button: **"Simulate MITM Ciphertext Bit-Flip"**.
- **Show**: The immediate security alert banner:
  > `[BLOCKED AS EXPECTED] Integrity check successfully caught the attack: CRITICAL SECURITY ALERT: Data integrity verification failed! Ciphertext, nonce, associated data, or authentication tag has been tampered with or corrupted in transit.`
- **Say**: *"We use AES-256-GCM AEAD. When an active network adversary flips even a single bit in-flight to tamper with patient dosages, the 128-bit GHASH authentication tag mismatch causes decryption to fail safely, preventing patient harm."*

### Minute 4: Page 2 — HIPAA Least-Privilege Clinical Data Redaction
- **Action**: Select **"🩺 Connected Medical Devices (IoMT Telemetry)"**.
- **Show**: The clinical vitals time series chart (Heart Rate, Blood Pressure, SpO2) for `DEV-VENT-002`.
- **Action**: In the sidebar Quick Persona Switcher, switch from **Doctor** (`dr_smith`) to **Auditor** (`auditor_davis`).
- **Show**: Point out that the patient ID becomes `DEV-***-002` and clinical vitals immediately switch to **`[REDACTED_FOR_AUDITOR]`**.
- **Say**: *"Our server-side RBAC enforces HIPAA least-privilege privacy. Clinical staff view full physiological data to treat patients, whereas compliance auditors inspect security metadata without viewing private patient vitals."*

### Minute 5: Page 6 — Blockchain Ledger & Sandbox Attack Forensics
- **Action**: Select **"⛓️ Secure Audit Blockchain Explorer"**.
- **Action**: Click **"Run Full Forensic Verification"** $\to$ Show green status: *"VERIFIED: 7/7 blocks verified, zero bit drift"*.
- **Action**: Under Sandbox Attack Simulator, click **"Attack: Tamper Payload in Block #2"**.
- **Show**: Verifier immediately identifies Block #2 as **`PAYLOAD_TAMPERED`**.
- **Say**: *"Every operational and security event is cryptographically linked via SHA-256 hash chaining and sealed with institutional HMAC-SHA256 signatures. Notice that our attack simulator runs strictly in an isolated sandbox, ensuring the production hospital ledger remains untouched."*

---

## 3. Option B: Fifteen-Minute Comprehensive Deep-Dive Demo

*Use this path for formal viva voce evaluation or detailed laboratory inspection.*

### Phase 1: Academic & Architectural Context (2 Minutes)
1. Open the project root in VS Code.
2. Open [`README.md`](file:///c:/Users/Prasad/OneDrive/Desktop/isc%20project/README.md) and show the **System Architecture Diagram**:
   - Point out the 6 discrete layers: IoMT Telemetry Fleet $\to$ Feature Engineering $\to$ AI Isolation Forest $\to$ AES-256-GCM AEAD $\to$ Argon2id & RBAC $\to$ Hash-Chained Blockchain $\to$ Streamlit Dashboard.
3. Show the **Development Stages Checklist**: All stages (1 through 8) completed and verified.

---

### Phase 2: Standalone Pipeline & Adversarial Terminal Execution (3 Minutes)

Run the standalone end-to-end integration pipeline:
```powershell
python security/e2e_integration_test.py
```

**Walkthrough Commentary:**
- **Phase 1 (Authentication)**: Doctor, Admin, and Auditor authenticate via Argon2id. Show that raw session tokens are never stored; only their SHA-256 hashes are persisted.
- **Phase 2 (AI Inference)**: Normal reading scored at $0.4196 < 0.5809$ (`NORMAL`). Severe Arrhythmia reading scored at $0.6888 > 0.5809$ (`CRITICAL`), identifying high heart rate. Network flood scored at $0.5928$ (`WARNING`), identifying packet burst.
- **Phase 3 (AEAD Cryptography)**: Master key loaded with locked NTFS ACL permissions (`0600`). HKDF derives distinct keys for `DEV-VENT-002`. Envelope created with fresh 96-bit nonce and 128-bit authentication tag.
- **Phase 4 (Audit Blockchain)**: Ledger traversed, validating SHA-256 linkage and HMAC signatures against the external checkpoint.
- **Phase 5 (Active Adversary Defense)**: Live blocking of:
  1. *MITM Bit-Flip* $\to$ Blocked by AES-GCM MAC tag.
  2. *AAD Header Spoofing* $\to$ Blocked by AAD binding violation.
  3. *Unauthorized Decryption Key* $\to$ Blocked by MAC verification failure.
  4. *Audit Payload Tamper* $\to$ Caught as `PAYLOAD_TAMPERED` at Block #2.
  5. *Tail Truncation Attack* $\to$ Caught as `CHAIN_TRUNCATED` via external checkpoint.
  6. *Checkpoint Rollback Attack* $\to$ Caught as `CHECKPOINT_ROLLBACK_DETECTED` via SQLite monotonic anchor.

Run the empirical benchmark:
```powershell
python security/benchmark_performance.py
```
- Point out the empirical results:
  - AI Inference Latency: **$15.94\text{ ms}$** mean ($62.7\text{ inf/sec}$).
  - Cryptography: **$0.14\text{ ms}$** encryption, **$0.11\text{ ms}$** decryption ($> 7,000\text{ ops/sec}$).
  - Total Dashboard Page 1 Load: **$184.14\text{ ms}$**.
  - Process Memory RSS: **$219.43\text{ MB}$** baseline, **$234.68\text{ MB}$** peak ($\Delta = +15.25\text{ MB}$ bounded).

---

### Phase 3: Interactive Dashboard Tour (8 Minutes)

Launch the dashboard:
```powershell
streamlit run app.py --server.address 127.0.0.1
```

#### Page 1: Hospital Overview & Executive Health
1. Show the **Executive KPI Cards**:
   - `10,000 Observations` | `5 Active IoMT Devices` | `584 Detected Anomalies` | `100% Cryptographic Integrity`.
2. Review the **IoMT Fleet Grid**:
   - 5 devices across ICU, Oncology, Cardiology, and Nephrology wards.
3. Review the **Live Threat Intelligence Feed**:
   - Explain how the AI distinguishes physiological crises (e.g., Tachycardia) from cyber attacks (e.g., Network Floods).

#### Page 2: Connected Medical Devices (IoMT Telemetry)
1. Select **`DEV-VENT-002` (Mechanical Ventilator)**.
2. Inspect the **Clinical Vitals Stream Plotly Chart**:
   - Show interactive zoom and pan on Heart Rate, Blood Pressure, and SpO2.
   - Point out red anomaly markers indicating detected crises.
3. Inspect the **Network Traffic Chart**:
   - Show packet transmission rate vs. upper baseline threshold ($60\text{ pkts/min}$).
4. **Demonstrate HIPAA Least-Privilege Privacy Redaction**:
   - Current user is `dr_smith` (Medical Staff) $\to$ Full vitals and patient ID `PAT-9942` visible.
   - In sidebar persona switcher, select `auditor_davis` (Auditor).
   - Show that clinical vitals immediately mask as `[REDACTED_FOR_AUDITOR]` and patient ID masks as `DEV-***-002`.

#### Page 3: AI Anomaly Detection Lab
1. Select `dr_smith` or `admin`.
2. Move the sliders manually or click preset buttons:
   - Click **"Acute Respiratory Failure (Severe Hypoxia)"** (SpO2 drops to $72\%$).
   - Click **"Run Anomaly Inference"**:
     - Gauge needle swings into **CRITICAL** ($s \approx 0.63 > 0.5809$).
     - Explainability surfaces: *"Oxygen Saturation is critically low (72.0 vs normal ~98.2)"*.
3. Click **"Batch Telemetry CSV Inference"**:
   - Demonstrate the batch scoring capability with instant downloadable CSV results.
4. Review the **Model Evaluation Showcase**:
   - Confusion matrix showing **$100\%$ critical recall** (zero missed life-threatening emergencies).
   - ROC Curve with **$AUC = 0.9984$**.

#### Page 4: Cryptography & Security Lab
1. **Live Encryption & Decryption**:
   - Enter custom medical text or use the prefilled record.
   - Click **"Encrypt Telemetry Record"**:
     - Show the generated 24-character hex nonce (96-bit fresh IV).
     - Show the 32-character hex authentication tag (128-bit MAC).
     - Show the ciphertext envelope.
   - Click **"Decrypt at Gateway"**:
     - Show instantaneous decryption with zero bit drift.
2. **Active Adversary Attack Simulator**:
   - Demonstrate Attack A: MITM Bit-Flip $\to$ Immediate `CryptoIntegrityError`.
   - Demonstrate Attack B: AAD Header Tamper $\to$ Immediate rejection.
   - Demonstrate Attack C: Unauthorized Key $\to$ Immediate rejection.
3. **Nonce Uniqueness Verification**:
   - Click **"Generate 3 Consecutive Envelopes for Same Plaintext"**:
     - Encrypts identical plaintext multiple times and displays completely distinct 96-bit nonces, authentication tags, and ciphertexts, proving zero nonce reuse.
4. **SHA-256 & HMAC-SHA256 Authenticity Lab**:
   - Inspect deterministic SHA-256 digest (64 hex characters) and Keyed HMAC-SHA256 signature generated with system secret key derived via HKDF.
   - **Interactive HMAC Verification & Tamper Detection**:
     - Baseline verification: Click **"Verify Existing Signature"** $\to$ Displays `Signature Valid`.
     - Tampering demonstration: Alter the payload text (e.g. change device ID) and click **"Verify Existing Signature"** $\to$ Original signature is preserved and system displays `TAMPERING DETECTED – Signature Invalid` via constant-time comparison (`hmac.compare_digest`).

#### Page 5: Authentication & RBAC Management
1. **Active Session Inspector (Tab 1)**:
   - Show current username, full name, assigned role, last interaction timestamp, and the **SHA-256 session token digest** (confirming zero plaintext token storage).
   - Explain the sliding 30-minute inactivity expiration window.
2. **Brute-Force Lockout Testing Console (Tab 2)**:
   - Target user dropdown dynamically queries all active registered users from the SQLite database (including `surya`).
   - Enter an incorrect password 5 times consecutively.
   - Show the counter: *"Attempt 1/5... 4/5... Account Locked for 15 minutes"*.
   - Show attempt 6 blocked immediately without re-hashing.
3. **Session Inactivity Timeout Testing Console (Tab 3)**:
   - **Live Session Telemetry**: Show active user, token hash, last interaction timestamp, and backend SQLite expiry time.
   - **Configurable Test Durations**: Show configurable policy options (30-min production standard, 1-min testing, 2-min testing) without changing production defaults.
   - **Active Session Renewal**: Click **"Perform Authenticated Action (Renew)"** $\to$ Demonstrates sliding window extension and last activity reset.
   - **Simulate Inactivity & Fast-Forward Expiration**: Click **"Simulate Inactivity & Expire Session"** $\to$ Real backend validation expires the session in SQLite (`is_active=0`), logs `SESSION_EXPIRED` with severity `WARNING`, redirects to authentication login, and displays: `SESSION EXPIRED – Please authenticate again.`.
   - **Expired Token Rejection**: Demonstrate that expired tokens are permanently rejected upon reuse attempts.
   - **Live Audit Log**: Show real-time `SESSION_EXPIRED` event logged in SQLite `security_events` table.
4. **Administrative User Management (Tab 4)**:
   - Show the list of registered users.
   - Demonstrate user creation with Argon2id password hashing.
5. **Security Event History (Tab 5)**:
   - Review live security events logged in SQLite (`AUTH_SUCCESS`, `AUTH_FAILURE`, `SESSION_EXPIRED`, etc.).

#### Page 6: Secure Audit Blockchain Explorer
1. **Ledger Inspection**:
   - Review committed blocks with sequence IDs, timestamps, user/device IDs, payload hashes, previous hash links, and HMAC signatures.
2. **One-Click Forensic Verifier**:
   - Click **"Run Full Forensic Verification"** $\to$ Confirms untampered ledger.
3. **Isolated Sandbox Adversary Attack Simulator**:
   - Demonstrate **Payload Modification**: Verifier flags `PAYLOAD_TAMPERED` at Block #2.
   - Demonstrate **Tail Truncation**: Verifier flags `CHAIN_TRUNCATED` via external checkpoint.
   - Demonstrate **Checkpoint Rollback**: Verifier flags `CHECKPOINT_ROLLBACK_DETECTED` via monotonic anchor.
   - Emphasize to the examiner that attacks run strictly inside `audit/.demo_sandbox/`, leaving production logs intact.

---

### Phase 4: Examiner Q&A & Wrap-Up (2 Minutes)

- Invite questions from the committee.
- Refer to [`VIVA_PRESENTATION_GUIDE.md`](file:///c:/Users/Prasad/OneDrive/Desktop/isc%20project/VIVA_PRESENTATION_GUIDE.md) for detailed mathematical and theoretical answers to tough questions.
- Conclude by highlighting:
  - **106 automated tests passed (100%)**.
  - **Zero hardcoded credentials or secret leakage**.
  - **Academically validated prototype designed specifically for the IoMT domain**.

---

## 4. Live Attack Scenarios Quick Reference Table

| Attack Name | UI Action in Dashboard | Expected System Response | Technical Security Mechanism |
| :--- | :--- | :--- | :--- |
| **MITM Ciphertext Bit-Flip** | Page 4 $\to$ Click *"Simulate MITM Ciphertext Bit-Flip"* | Red Alert: `CryptoIntegrityError` | 128-bit GHASH authentication tag mismatch |
| **AAD Routing Header Tamper** | Page 4 $\to$ Click *"Simulate AAD Routing Header Tamper"* | Red Alert: `CryptoIntegrityError` | AAD header cryptographically bound into GHASH tag |
| **Unauthorized Decryption Key** | Page 4 $\to$ Click *"Attempt Decryption with Unauthorized Key"* | Red Alert: `CryptoIntegrityError` | AES-256 key mismatch causes authentication failure |
| **Audit Payload Tampering** | Page 6 $\to$ Click *"Attack: Tamper Payload in Block #2"* | Red Status: `PAYLOAD_TAMPERED` | Recalculated payload SHA-256 hash does not match |
| **Tail Truncation (Log Deletion)** | Page 6 $\to$ Click *"Attack: Delete Tail Block (Truncation)"* | Red Status: `CHAIN_TRUNCATED` | Event count mismatch against external HMAC checkpoint |
| **Checkpoint Rollback Attack** | Page 6 $\to$ Click *"Attack: Checkpoint Rollback"* | Red Status: `CHECKPOINT_ROLLBACK_DETECTED` | Monotonic sequence regression caught by SQLite anchor |
| **Brute-Force Credential Attack** | Page 5 $\to$ Enter 5 wrong passwords | Counter locks account for 15 minutes | Atomic SQLite transaction counter tracks failed attempts |

---

## 5. Emergency Troubleshooting & Fallback Commands

If unexpected environmental issues arise during the examination:

### Issue 1: "Port 8501 is already in use"
Run Streamlit on an alternate port:
```powershell
streamlit run app.py --server.port 8502 --server.address 127.0.0.1
```

### Issue 2: "Browser doesn't open automatically"
Manually open Chrome or Edge and navigate to:
```
http://127.0.0.1:8501
```

### Issue 3: "Account locked during testing"
Unlock the account instantly via the administrative console on Page 5, or run:
```powershell
python -c "import database.database as db; conn = db.get_db_connection(); conn.execute('UPDATE users SET failed_login_attempts=0, locked_until=NULL'); conn.commit(); conn.close(); print('All accounts unlocked successfully.')"
```

### Issue 4: "Need to re-verify tests quickly in front of examiner"
```powershell
python -m unittest discover -s tests -v
```

---

*This walkthrough script ensures a smooth, flawless, and impressive live viva voce demonstration.*
