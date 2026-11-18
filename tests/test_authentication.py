"""
Automated Test Suite for Information Security & RBAC (Stage 5)
==============================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Comprehensive Test Suite (22 Tests):
------------------------------------
1.  Password policy validation (length, uppercase, lowercase, digits, special characters).
2.  Argon2id password hashing and constant-time verification.
3.  User registration with Argon2id storage (never plaintext).
4.  Duplicate username rejection.
5.  SQL injection resistance in registration and authentication queries.
6.  Successful authentication workflow with credential validation.
7.  Invalid password rejection with attempt tracking.
8.  Brute-force defense: automatic account lockout after 5 failed attempts.
9.  Lockout enforcement: subsequent attempts while locked are blocked.
10. Lockout expiration: automatic account recovery after 15 minutes.
11. Cryptographic session token generation and SHA-256 database hashing.
12. Session validation with 30-minute sliding expiration window.
13. Session expiration enforcement after inactivity timeout.
14. Secure user logout and token invalidation (preventing replay/reuse).
15. Deactivated user login rejection.
16. RBAC permission verification for 'admin' role.
17. RBAC permission verification for 'medical_staff' role (least privilege).
18. RBAC permission verification for 'auditor' role (read-only compliance).
19. Backend enforcement: enforce_permission raises AccessDeniedError on violations.
20. Reusable authorization decorator: @require_permission functionality.
21. Clinical telemetry least-privilege data filtering per role.
22. Security audit logging verification: correct event types, status, and zero secret leakage.
"""

import sys
import unittest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import database.database as db
from security.authentication import (
    validate_password_strength,
    hash_password,
    verify_password,
    hash_session_token,
    register_user,
    seed_default_users,
    authenticate_user,
    validate_session,
    logout_user,
    expire_session,
    get_session_info,
)
from security.access_control import (
    has_permission,
    check_access,
    enforce_permission,
    require_permission,
    AccessDeniedError,
    filter_patient_data_for_role,
)
from audit.security_logger import (
    sanitize_metadata,
    query_security_events,
)


class TestInformationSecurity(unittest.TestCase):
    """Automated unit and integration tests for Stage 5 Information Security."""

    @classmethod
    def setUpClass(cls):
        """Create an isolated temporary SQLite database for testing."""
        cls.temp_dir = tempfile.mkdtemp()
        cls.test_db_path = Path(cls.temp_dir) / "test_medical_security.db"
        cls.original_db_path = db.DB_PATH

        # Redirect database module to temporary test database
        db.DB_PATH = cls.test_db_path
        db.initialize_database()

    @classmethod
    def tearDownClass(cls):
        """Clean up temporary test database and restore original DB path."""
        db.DB_PATH = cls.original_db_path
        if Path(cls.temp_dir).exists():
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        """Ensure clean tables before each test execution."""
        with db.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions")
            cursor.execute("DELETE FROM security_events")
            cursor.execute("DELETE FROM users")

    # ==========================================================================
    # 1. PASSWORD POLICY & ARGON2ID TESTS
    # ==========================================================================

    def test_01_password_policy_enforcement(self):
        """Verify strict institutional password policy compliance."""
        # Too short (< 8 chars)
        ok, msg = validate_password_strength("Pass@1")
        self.assertFalse(ok)
        self.assertIn("at least 8 characters", msg)

        # Missing uppercase
        ok, msg = validate_password_strength("lowercase@123")
        self.assertFalse(ok)
        self.assertIn("uppercase", msg)

        # Missing lowercase
        ok, msg = validate_password_strength("UPPERCASE@123")
        self.assertFalse(ok)
        self.assertIn("lowercase", msg)

        # Missing digit
        ok, msg = validate_password_strength("NoDigitsSpecial!")
        self.assertFalse(ok)
        self.assertIn("digit", msg)

        # Missing special character
        ok, msg = validate_password_strength("NoSpecialChar123")
        self.assertFalse(ok)
        self.assertIn("special character", msg)

        # Meets all requirements
        ok, msg = validate_password_strength("SecureDoctor@2026")
        self.assertTrue(ok)
        self.assertIn("complexity requirements", msg)

    def test_02_argon2id_hashing_and_verification(self):
        """Verify Argon2id memory-hardened hashing and constant-time verification."""
        password = "HospitalStaff#2026"
        hashed1 = hash_password(password)
        hashed2 = hash_password(password)

        # Formats must be valid Argon2id strings
        self.assertTrue(hashed1.startswith("$argon2id$"))
        self.assertTrue(hashed2.startswith("$argon2id$"))

        # Due to random salt generation, two hashes of the same password must be distinct
        self.assertNotEqual(hashed1, hashed2)

        # Correct password verifies against both hashes
        self.assertTrue(verify_password(password, hashed1))
        self.assertTrue(verify_password(password, hashed2))

        # Incorrect password verification must fail
        self.assertFalse(verify_password("WrongPassword#999", hashed1))

    # ==========================================================================
    # 2. USER REGISTRATION & SQL INJECTION RESISTANCE
    # ==========================================================================

    def test_03_user_registration_success(self):
        """Verify user registration stores Argon2id hashes, not plaintext."""
        ok, msg = register_user(
            username="test_nurse",
            password="NursePassword@2026",
            full_name="Nurse Florence",
            role="medical_staff",
        )
        self.assertTrue(ok)

        # Inspect database record
        user = db.get_user_by_username("test_nurse")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "test_nurse")
        self.assertEqual(user["role"], "medical_staff")
        # Ensure password hash is Argon2id and NOT plaintext
        self.assertNotEqual(user["password_hash"], "NursePassword@2026")
        self.assertTrue(user["password_hash"].startswith("$argon2id$"))

    def test_04_user_registration_duplicate_username(self):
        """Verify duplicate registration rejection."""
        register_user("dr_unique", "DoctorPassword@123", "Dr. One", "medical_staff")
        ok, msg = register_user("dr_unique", "DoctorPassword@123", "Dr. Two", "medical_staff")
        self.assertFalse(ok)
        self.assertIn("already exists", msg)

    def test_05_sql_injection_resistance(self):
        """Verify parameterized queries prevent SQL injection in registration & auth."""
        injection_user = "' OR '1'='1"
        injection_pass = "' OR '1'='1' -- "

        # Registration handles special SQL characters safely
        ok, msg = register_user(injection_user, "ValidPassword@123", "SQL Injector", "medical_staff")
        self.assertTrue(ok)

        # Authentication with SQL injection payload fails safely
        ok, msg, sess = authenticate_user(injection_user, injection_pass)
        self.assertFalse(ok)
        self.assertIsNone(sess)

        # Normal authentication with proper password works
        ok, msg, sess = authenticate_user(injection_user, "ValidPassword@123")
        self.assertTrue(ok)
        self.assertIsNotNone(sess)

    # ==========================================================================
    # 3. AUTHENTICATION & LOCKOUT DEFENSE TESTS
    # ==========================================================================

    def test_06_successful_authentication(self):
        """Verify successful user login generates session and updates last_login."""
        register_user("dr_clara", "DoctorPassword@123", "Dr. Clara", "medical_staff")
        ok, msg, sess = authenticate_user("dr_clara", "DoctorPassword@123")

        self.assertTrue(ok)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["username"], "dr_clara")
        self.assertEqual(sess["role"], "medical_staff")
        self.assertTrue("session_token" in sess)

        # Verify last_login was updated in database
        user = db.get_user_by_username("dr_clara")
        self.assertIsNotNone(user["last_login"])

    def test_07_invalid_password_rejection(self):
        """Verify incorrect password tracking and warning message."""
        register_user("dr_smith_auth", "DoctorPassword@123", "Dr. Smith", "medical_staff")
        ok, msg, sess = authenticate_user("dr_smith_auth", "WrongPassword@999")

        self.assertFalse(ok)
        self.assertIsNone(sess)
        self.assertIn("4 attempt(s) remaining", msg)

        user = db.get_user_by_username("dr_smith_auth")
        self.assertEqual(user["failed_login_attempts"], 1)

    def test_08_brute_force_lockout_after_five_failures(self):
        """Verify automatic account lockout after exactly 5 consecutive failed attempts."""
        register_user("target_account", "CorrectPassword@123", "Target User", "medical_staff")

        # Attempts 1 through 4
        for i in range(1, 5):
            ok, msg, _ = authenticate_user("target_account", f"BadPass#{i}000")
            self.assertFalse(ok)

        # 5th attempt must trigger account lockout
        ok, msg, _ = authenticate_user("target_account", "BadPass#5000")
        self.assertFalse(ok)
        self.assertIn("Account is locked for 15 minutes", msg)

        user = db.get_user_by_username("target_account")
        self.assertEqual(user["failed_login_attempts"], 5)
        self.assertIsNotNone(user["locked_until"])

    def test_09_locked_account_rejects_subsequent_attempts(self):
        """Verify that even with the correct password, a locked account is blocked."""
        register_user("locked_user", "CorrectPassword@123", "Locked User", "medical_staff")

        # Trigger lockout
        for _ in range(5):
            authenticate_user("locked_user", "WrongPassword!000")

        # Now attempt with the CORRECT password while locked
        ok, msg, sess = authenticate_user("locked_user", "CorrectPassword@123")
        self.assertFalse(ok)
        self.assertIsNone(sess)
        self.assertIn("Account locked due to multiple failed login attempts", msg)

    def test_10_lockout_expiration_allows_recovery(self):
        """Verify that after 15 minutes, account lockout automatically expires."""
        register_user("temp_lock_user", "CorrectPassword@123", "Temp User", "medical_staff")

        # Trigger lockout at t0
        t0 = datetime(2026, 11, 10, 10, 0, 0)
        for _ in range(5):
            authenticate_user("temp_lock_user", "WrongPassword!000", current_time=t0)

        # Verify locked at t0 + 10 mins
        t_during = t0 + timedelta(minutes=10)
        ok, msg, _ = authenticate_user("temp_lock_user", "CorrectPassword@123", current_time=t_during)
        self.assertFalse(ok)

        # At t0 + 16 mins (lockout expired), correct password must succeed
        t_after = t0 + timedelta(minutes=16)
        ok, msg, sess = authenticate_user("temp_lock_user", "CorrectPassword@123", current_time=t_after)
        self.assertTrue(ok)
        self.assertIsNotNone(sess)

        # Verify lock was cleared and counter reset
        user = db.get_user_by_username("temp_lock_user")
        self.assertIsNone(user["locked_until"])
        self.assertEqual(user["failed_login_attempts"], 0)

    # ==========================================================================
    # 4. SESSION MANAGEMENT TESTS
    # ==========================================================================

    def test_11_session_token_entropy_and_hashing(self):
        """Verify raw session token is high entropy and only stored as SHA-256 hash in DB."""
        register_user("session_user", "UserPassword@123", "Session User", "medical_staff")
        ok, msg, sess = authenticate_user("session_user", "UserPassword@123")

        raw_token = sess["session_token"]
        expected_hash = hash_session_token(raw_token)

        self.assertGreaterEqual(len(raw_token), 32)
        self.assertEqual(sess["session_token_hash"], expected_hash)

        # Inspect SQLite sessions table directly
        with db.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE session_token_hash = ?", (expected_hash,))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            # Ensure the raw token does not exist in any column
            for val in row:
                self.assertNotEqual(val, raw_token)

    def test_12_session_validation_sliding_window(self):
        """Verify validate_session extends expiration time (sliding window)."""
        register_user("sliding_user", "DoctorPassword@123", "Dr. Sliding", "medical_staff")
        t0 = datetime(2026, 11, 10, 12, 0, 0)
        ok, msg, sess = authenticate_user("sliding_user", "DoctorPassword@123", current_time=t0)
        initial_expiry = sess["expires_at"]

        # 10 minutes later, user makes an active request
        t1 = t0 + timedelta(minutes=10)
        validated = validate_session(sess["session_token"], current_time=t1)
        self.assertIsNotNone(validated)

        # Expiration must slide forward to t1 + 30 mins
        expected_expiry = (t1 + timedelta(minutes=config.SESSION_TIMEOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(validated["expires_at"], expected_expiry)
        self.assertNotEqual(validated["expires_at"], initial_expiry)

    def test_13_session_expiration_enforcement(self):
        """Verify session is rejected after 30 minutes of inactivity."""
        register_user("inactive_user", "DoctorPassword@123", "Dr. Inactive", "medical_staff")
        t0 = datetime(2026, 11, 10, 14, 0, 0)
        ok, msg, sess = authenticate_user("inactive_user", "DoctorPassword@123", current_time=t0)

        # 31 minutes later (session expired)
        t_expired = t0 + timedelta(minutes=31)
        validated = validate_session(sess["session_token"], current_time=t_expired)
        self.assertIsNone(validated)

        # In SQLite, session should now be marked is_active = 0
        with db.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_active FROM sessions WHERE session_token_hash = ?", (sess["session_token_hash"],))
            row = cursor.fetchone()
            self.assertEqual(row["is_active"], 0)

    def test_14_user_logout_and_session_invalidation(self):
        """Verify logout invalidates session and prevents session reuse."""
        register_user("logout_user", "NursePassword@123", "Nurse Logout", "medical_staff")
        ok, msg, sess = authenticate_user("logout_user", "NursePassword@123")

        # Validate active before logout
        self.assertIsNotNone(validate_session(sess["session_token"]))

        # Execute logout
        logout_status = logout_user(sess["session_token"])
        self.assertTrue(logout_status)

        # Subsequent validation must fail
        self.assertIsNone(validate_session(sess["session_token"]))

    def test_15_deactivated_user_cannot_login(self):
        """Verify deactivated accounts cannot log in and have existing sessions terminated."""
        register_user("deact_user", "DoctorPassword@123", "Dr. Suspended", "medical_staff", user_id="USR-SUSP-01")
        ok, msg, sess = authenticate_user("deact_user", "DoctorPassword@123")
        self.assertTrue(ok)

        # Deactivate user
        db.set_user_status("USR-SUSP-01", is_active=False)

        # Existing session must now be rejected
        self.assertIsNone(validate_session(sess["session_token"]))

        # Subsequent login attempts must be rejected
        login_ok, login_msg, _ = authenticate_user("deact_user", "DoctorPassword@123")
        self.assertFalse(login_ok)
        self.assertIn("deactivated", login_msg)

    # ==========================================================================
    # 5. ROLE-BASED ACCESS CONTROL (RBAC) TESTS
    # ==========================================================================

    def test_16_rbac_role_permissions_admin(self):
        """Verify admin role has full administrative, crypto, and audit permissions."""
        admin_role = "admin"
        self.assertTrue(has_permission(admin_role, "manage_users"))
        self.assertTrue(has_permission(admin_role, "access_system_config"))
        self.assertTrue(has_permission(admin_role, "view_audit_logs"))
        self.assertTrue(has_permission(admin_role, "manage_device_access"))
        self.assertTrue(has_permission(admin_role, "configure_crypto"))
        self.assertTrue(has_permission(admin_role, "verify_audit_chain"))

    def test_17_rbac_role_permissions_medical_staff(self):
        """Verify medical_staff role has clinical access but lacks administrative/crypto rights."""
        staff_role = "medical_staff"
        # Allowed
        self.assertTrue(has_permission(staff_role, "view_readings"))
        self.assertTrue(has_permission(staff_role, "view_anomaly_alerts"))
        self.assertTrue(has_permission(staff_role, "access_authorized_devices"))

        # Explicitly Denied (Least Privilege)
        self.assertFalse(has_permission(staff_role, "manage_users"))
        self.assertFalse(has_permission(staff_role, "configure_crypto"))
        self.assertFalse(has_permission(staff_role, "access_system_config"))

    def test_18_rbac_role_permissions_auditor(self):
        """Verify auditor role has read-only compliance access but cannot alter users or devices."""
        auditor_role = "auditor"
        # Allowed
        self.assertTrue(has_permission(auditor_role, "view_audit_logs"))
        self.assertTrue(has_permission(auditor_role, "view_auth_events"))
        self.assertTrue(has_permission(auditor_role, "view_crypto_verification"))
        self.assertTrue(has_permission(auditor_role, "verify_audit_chain"))

        # Explicitly Denied
        self.assertFalse(has_permission(auditor_role, "manage_users"))
        self.assertFalse(has_permission(auditor_role, "manage_device_access"))
        self.assertFalse(has_permission(auditor_role, "configure_crypto"))

    def test_19_rbac_enforce_permission_blocks_unauthorized(self):
        """Verify enforce_permission raises AccessDeniedError and logs unauthorized attempts."""
        doctor_session = {"user_id": "USR-DOC-99", "username": "dr_curie", "role": "medical_staff"}

        # Doctor accessing telemetry -> OK
        self.assertTrue(enforce_permission(doctor_session, "view_readings"))

        # Doctor attempting to manage users -> Must raise AccessDeniedError
        with self.assertRaises(AccessDeniedError) as cm:
            enforce_permission(doctor_session, "manage_users", resource="UserManagementAPI")

        self.assertIn("lacks required permission 'manage_users'", str(cm.exception))

        # Verify UNAUTHORIZED_ACCESS_ATTEMPT was logged into security_events
        events = db.get_security_events(limit=5, event_type="UNAUTHORIZED_ACCESS_ATTEMPT")
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]["user_id"], "USR-DOC-99")
        self.assertEqual(events[0]["status"], "BLOCKED")

    def test_20_rbac_require_permission_decorator(self):
        """Verify @require_permission decorator enforces backend role authorization."""
        @require_permission("configure_crypto")
        def sensitive_crypto_operation(session, new_key_len: int):
            return f"Crypto reconfigured with length {new_key_len} by {session['username']}."

        admin_sess = {"user_id": "USR-ADMIN-01", "username": "admin_user", "role": "admin"}
        doctor_sess = {"user_id": "USR-DOC-02", "username": "dr_smith", "role": "medical_staff"}

        # Admin execution -> Succeeds
        res = sensitive_crypto_operation(admin_sess, 256)
        self.assertIn("reconfigured", res)

        # Doctor execution -> Raises AccessDeniedError
        with self.assertRaises(AccessDeniedError):
            sensitive_crypto_operation(doctor_sess, 256)

    def test_21_patient_data_least_privilege_filtering(self):
        """Verify least privilege filtering redacts physiological vitals for auditors."""
        records = [
            {
                "reading_id": "REC-001",
                "timestamp": "2026-11-10 12:00:00",
                "device_id": "DEV-VENT-002",
                "heart_rate": 78.0,
                "systolic_bp": 118.0,
                "oxygen_saturation": 98.5,
            }
        ]

        # Clinical staff gets raw data
        clinical_view = filter_patient_data_for_role(records, role="medical_staff")
        self.assertEqual(clinical_view[0]["heart_rate"], 78.0)

        # Auditor gets redacted clinical vitals
        auditor_view = filter_patient_data_for_role(records, role="auditor")
        self.assertEqual(auditor_view[0]["heart_rate"], "[REDACTED_FOR_AUDITOR]")
        self.assertEqual(auditor_view[0]["reading_id"], "REC-001")  # Audit metadata preserved

    def test_22_security_event_logging_audit_integrity(self):
        """Verify security event logging records status, severity, and strips secrets."""
        # Test sanitization utility
        dirty_meta = {
            "device_id": "DEV-VENT-002",
            "password": "ClearTextPassword123",
            "master_key": "SuperSecretKeyBytes",
            "safe_counter": 42,
        }
        clean_meta = sanitize_metadata(dirty_meta)
        self.assertEqual(clean_meta["password"], "[REDACTED_SECRET]")
        self.assertEqual(clean_meta["master_key"], "[REDACTED_SECRET]")
        self.assertEqual(clean_meta["safe_counter"], 42)

        # Test event logging in DB
        event_id = db.log_security_event(
            event_type="TEST_SECURITY_CHECK",
            severity="INFO",
            description="Automated security event integrity check.",
            user_id="USR-SYSTEM",
            status="SUCCESS",
            metadata=clean_meta,
        )
        self.assertIsInstance(event_id, int)

        events = db.get_security_events(limit=1, event_type="TEST_SECURITY_CHECK")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "SUCCESS")
        self.assertEqual(events[0]["severity"], "INFO")
        self.assertNotIn("ClearTextPassword123", events[0]["metadata"])

    def test_23_session_revocation_on_role_change(self):
        """Verify that modifying a user's role immediately invalidates any active sessions."""
        register_user("role_revoke_user", "DoctorPassword@123", "Dr. RoleRevoke", "medical_staff", user_id="USR-REVOKE-01")
        ok, msg, sess = authenticate_user("role_revoke_user", "DoctorPassword@123")
        self.assertTrue(ok)
        self.assertIsNotNone(validate_session(sess["session_token"]))

        # Admin changes role to auditor
        db.update_user_role("USR-REVOKE-01", "auditor")

        # Prior session token MUST be invalid immediately
        self.assertIsNone(validate_session(sess["session_token"]))

    def test_24_concurrent_login_attempts_cannot_bypass_lockout(self):
        """Verify that concurrent brute-force threads cannot bypass the 5-attempt lockout limit."""
        import concurrent.futures

        register_user("concur_target", "CorrectPassword@123", "Target User", "medical_staff")

        def attempt_bad_login(attempt_num):
            return authenticate_user("concur_target", f"BadPassword#{attempt_num}")

        # Fire 10 concurrent requests simultaneously
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(attempt_bad_login, range(10)))

        # Inspect database: counter must be locked and capped at 5
        user = db.get_user_by_username("concur_target")
        self.assertEqual(user["failed_login_attempts"], 5)
        self.assertIsNotNone(user["locked_until"])

        # Subsequent attempts must be locked
        locked_responses = [msg for ok, msg, _ in results if "locked" in msg.lower()]
        self.assertGreaterEqual(len(locked_responses), 5)

    def test_25_session_configurable_timeout_and_sliding_renewal(self):
        """Verify configurable test timeout durations, sliding renewal, automatic expiration, and event logging."""
        register_user("timeout_user", "DoctorPassword@123", "Dr. Timeout", "medical_staff")
        t0 = datetime(2026, 11, 10, 10, 0, 0)

        # 1. Authenticate with configurable 1-minute test timeout (without altering production 30-min timeout)
        ok, msg, sess = authenticate_user("timeout_user", "DoctorPassword@123", current_time=t0, timeout_minutes=1)
        self.assertTrue(ok)
        raw_token = sess["session_token"]
        expected_exp_1 = (t0 + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(sess["expires_at"], expected_exp_1)

        # 2. Test active session renewal within timeout (at t0 + 30s)
        t_renew = t0 + timedelta(seconds=30)
        renewed = validate_session(raw_token, current_time=t_renew, timeout_minutes=1)
        self.assertIsNotNone(renewed)
        expected_renewed_exp = (t_renew + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(renewed["expires_at"], expected_renewed_exp)

        # 3. Test automatic expiration after inactivity (at t_renew + 70s = t0 + 100s > t_renew + 60s)
        t_expired = t_renew + timedelta(seconds=70)
        expired_val = validate_session(raw_token, current_time=t_expired, timeout_minutes=1)
        self.assertIsNone(expired_val, "Session must expire after 1 minute of inactivity.")

        # 4. Test rejection of expired token (cannot be reused)
        token_hash = hash_session_token(raw_token)
        with db.get_db_connection() as conn:
            row = conn.execute("SELECT is_active FROM sessions WHERE session_token_hash = ?", (token_hash,)).fetchone()
            self.assertEqual(row["is_active"], 0, "Expired token must be marked inactive in database.")

        subsequent_val = validate_session(raw_token, current_time=t_expired + timedelta(seconds=10))
        self.assertIsNone(subsequent_val, "Expired session token must be rejected upon reuse attempt.")

        # 5. Test security event logging in SQLite
        events = db.get_security_events(limit=5, event_type="SESSION_EXPIRED")
        self.assertGreaterEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_type"], "SESSION_EXPIRED")
        self.assertEqual(ev["severity"], "WARNING")
        self.assertEqual(ev["user_id"], sess["user_id"])
        self.assertIn("timeout_user", ev["description"])

    def test_26_explicit_session_expiration_and_token_reuse_prevention(self):
        """Verify explicit expire_session marks token inactive and prevents token reuse."""
        register_user("expire_target", "DoctorPassword@123", "Dr. ExpireTarget", "medical_staff")
        ok, msg, sess = authenticate_user("expire_target", "DoctorPassword@123")
        self.assertTrue(ok)
        raw_token = sess["session_token"]

        # Validate initially active
        self.assertIsNotNone(validate_session(raw_token))

        # Explicitly expire session
        status = expire_session(raw_token, reason="test simulation")
        self.assertTrue(status)

        # Token must be rejected
        self.assertIsNone(validate_session(raw_token))

        # Verify database record
        token_hash = hash_session_token(raw_token)
        with db.get_db_connection() as conn:
            row = conn.execute("SELECT is_active FROM sessions WHERE session_token_hash = ?", (token_hash,)).fetchone()
            self.assertEqual(row["is_active"], 0)

    def test_27_get_session_info_retrieval(self):
        """Verify get_session_info inspects session metadata without sliding expiry."""
        register_user("info_user", "DoctorPassword@123", "Dr. Info", "medical_staff")
        ok, msg, sess = authenticate_user("info_user", "DoctorPassword@123")
        raw_token = sess["session_token"]

        info = get_session_info(raw_token)
        self.assertIsNotNone(info)
        self.assertEqual(info["username"], "info_user")
        self.assertEqual(info["is_active"], 1)
        self.assertEqual(info["expires_at"], sess["expires_at"])


if __name__ == "__main__":
    unittest.main()

