"""
User Authentication & Session Management Module
===============================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Implements user authentication and credential security:
1. Password Hashing: Uses Argon2id (OWASP recommended gold standard, memory-hardened).
2. Password Policy Enforcement: Minimum length, mixed case, numbers, and special characters.
3. Brute-Force & Account Lockout Defense: Locks accounts after 5 failed login attempts for 15 mins.
4. Cryptographic Session Management: Generates high-entropy session tokens (stored ONLY as SHA-256 hashes).
5. Sliding Session Expiration: 30-minute sliding window with automatic invalidation.
6. Security Audit Logging: Logs authentication successes, failures, lockouts, and logouts.
"""

import sys
import os
import re
import secrets
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timedelta
import argon2

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from database.database import (
    get_db_connection,
    log_security_event,
    initialize_database,
)

# Concurrency lock to serialize authentication requests and defeat race conditions
_auth_lock = threading.Lock()

# Initialize Argon2id password hasher with secure parameters:
# - type=argon2.Type.ID (Argon2id: hybrid defense against side-channel & GPU attacks)
# - memory_cost=65536 (64 MB RAM per hash)
# - time_cost=2 (2 iterations)
# - parallelism=1
_hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    type=argon2.Type.ID,
)

MAX_FAILED_ATTEMPTS = getattr(config, "MAX_FAILED_LOGIN_ATTEMPTS", 5)
LOCKOUT_DURATION_MINUTES = getattr(config, "LOCKOUT_DURATION_MINUTES", 15)
SESSION_TIMEOUT_MINUTES = getattr(config, "SESSION_TIMEOUT_MINUTES", 30)

__all__ = [
    "validate_password_strength",
    "hash_password",
    "verify_password",
    "hash_session_token",
    "register_user",
    "seed_default_users",
    "authenticate_user",
    "validate_session",
    "logout_user",
    "expire_session",
    "get_session_info",
    "MAX_FAILED_ATTEMPTS",
    "LOCKOUT_DURATION_MINUTES",
    "SESSION_TIMEOUT_MINUTES",
]


# ==============================================================================
# 1. PASSWORD POLICY & HASHING
# ==============================================================================

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password compliance with institutional security policy:
    - Minimum 8 characters.
    - At least one uppercase letter (A-Z).
    - At least one lowercase letter (a-z).
    - At least one digit (0-9).
    - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?).
    """
    if not isinstance(password, str):
        return False, "Password must be a valid string."

    policy = config.PASSWORD_POLICY
    if len(password) < policy["min_length"]:
        return False, f"Password must be at least {policy['min_length']} characters long."
    if policy["require_uppercase"] and not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if policy["require_lowercase"] and not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if policy["require_digit"] and not re.search(r"\d", password):
        return False, "Password must contain at least one numerical digit."
    if policy["require_special"] and not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)."

    return True, "Password meets complexity requirements."


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id with automatic salt generation.
    Returns an encoded string containing the salt, parameters, and hash digest.
    Plaintext password is never persisted.
    """
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.
    Safe against timing attacks.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError, Exception):
        return False


def hash_session_token(token: str) -> str:
    """
    Compute deterministic SHA-256 digest of a session token.
    Ensures raw session tokens are never stored in plaintext in the database.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ==============================================================================
# 2. USER MANAGEMENT & SEEDING
# ==============================================================================

def register_user(
    username: str,
    password: str,
    full_name: str,
    role: str,
    user_id: str = None,
) -> tuple[bool, str]:
    """
    Register a new user in the database with role validation and parameterized queries.
    Prevents SQL injection and stores only salted Argon2id hashes.
    """
    if not username or not isinstance(username, str) or not username.strip():
        return False, "Username cannot be empty."

    clean_username = username.strip().lower()

    if role not in config.ROLES:
        return False, f"Invalid role '{role}'. Allowed roles: {list(config.ROLES.keys())}"

    is_valid, msg = validate_password_strength(password)
    if not is_valid:
        return False, msg

    uid = user_id or f"USR-{secrets.token_hex(4).upper()}"
    pwd_hash = hash_password(password)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (user_id, username, password_hash, full_name, role, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
            """, (uid, clean_username, pwd_hash, full_name.strip(), role, now_str))

            log_security_event(
                event_type="USER_REGISTERED",
                severity="INFO",
                description=f"User '{clean_username}' registered with role '{role}'.",
                user_id=uid,
                status="SUCCESS",
                conn=conn,
            )
        return True, f"User '{clean_username}' successfully registered."
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return False, f"Username '{clean_username}' already exists."
        return False, f"Registration error: {e}"


def seed_default_users():
    """
    Seed standard institutional demo users if DEMO_MODE is active.
    In production (APP_ENV == 'production' or DEMO_MODE is False),
    automatic seeding is strictly disabled and fails closed.
    """
    if getattr(config, "APP_ENV", "development").lower() == "production" or not getattr(config, "DEMO_MODE", False):
        return False, "Demo account seeding is strictly disabled in production mode."

    initialize_database()

    demo_creds = getattr(config, "DEMO_CREDENTIALS", {})
    if not demo_creds:
        return False, "No demo credentials configured."

    default_accounts = list(demo_creds.values())

    with get_db_connection() as conn:
        cursor = conn.cursor()
        for acc in default_accounts:
            cursor.execute("SELECT user_id, password_hash FROM users WHERE username = ?", (acc["username"],))
            existing = cursor.fetchone()
            if not existing:
                register_user(
                    username=acc["username"],
                    password=acc["password"],
                    full_name=acc["full_name"],
                    role=acc["role"],
                    user_id=acc["user_id"],
                )
            else:
                # If existing account uses deprecated password, update hash to match rotated credential
                if not verify_password(acc["password"], existing["password_hash"]):
                    new_hash = hash_password(acc["password"])
                    cursor.execute(
                        "UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL WHERE username = ?",
                        (new_hash, acc["username"]),
                    )
    return True, "Demo accounts seeded/updated successfully."


# ==============================================================================
# 3. AUTHENTICATION & ACCOUNT LOCKOUT
# ==============================================================================

def authenticate_user(
    username: str,
    password: str,
    ip_address: str = "127.0.0.1",
    current_time: datetime = None,
    timeout_minutes: int = None,
) -> tuple[bool, str, dict | None]:
    """
    Authenticate user credentials with brute-force lockout protection and session generation.
    - Parameterized queries defeat SQL injection.
    - Argon2id password verification prevents timing attacks.
    - 5 consecutive failures trigger an automatic 15-minute account lockout.
    - Lockout expires automatically after 15 minutes.
    - Stores only SHA-256 hash of session token in database.

    Parameters:
    -----------
    username: str
    password: str
    ip_address: str
    current_time: datetime (optional, supports controlled clock testing)

    Returns:
    --------
    tuple: (success: bool, message: str, session_data: dict | None)
    """
    if not username or not isinstance(username, str) or not password or not isinstance(password, str):
        return False, "Invalid username or password.", None

    clean_username = username.strip().lower()
    if not clean_username:
        return False, "Invalid username or password.", None

    # Fail closed in production if required security configuration is missing
    if getattr(config, "APP_ENV", "development").lower() == "production":
        if not config.DATABASE_FILE_PATH.exists():
            return False, "Security configuration error: persistent user store missing.", None
        if not os.environ.get(config.SYSTEM_MASTER_KEY_ENV) and not (config.SECURITY_DIR / ".master_key.key").exists():
            return False, "Security configuration error: cryptographic key store missing.", None

    now = current_time or datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    try:
        with _auth_lock:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (clean_username,))
                user = cursor.fetchone()

                if not user:
                    # Generic message to prevent username enumeration
                    log_security_event(
                        event_type="AUTH_FAILURE",
                        severity="WARNING",
                        description=f"Failed login attempt for non-existent user '{clean_username}'.",
                        ip_address=ip_address,
                        status="FAILURE",
                        conn=conn,
                    )
                    return False, "Invalid username or password.", None

                user_dict = dict(user)

                # Check if account is active
                if not user_dict.get("is_active"):
                    log_security_event(
                        event_type="AUTH_FAILURE",
                        severity="WARNING",
                        description=f"Login attempt on deactivated account '{clean_username}'.",
                        user_id=user_dict.get("user_id"),
                        ip_address=ip_address,
                        status="FAILURE",
                        conn=conn,
                    )
                    return False, "Account has been deactivated. Please contact an administrator.", None

                # Fail closed on corrupt or missing Argon2id password hash
                pwd_hash = user_dict.get("password_hash")
                if not pwd_hash or not isinstance(pwd_hash, str) or not pwd_hash.startswith("$argon2id$"):
                    log_security_event(
                        event_type="AUTH_FAILURE",
                        severity="CRITICAL",
                        description=f"Corrupt or missing Argon2id password hash for user '{clean_username}'. Access denied.",
                        user_id=user_dict.get("user_id"),
                        ip_address=ip_address,
                        status="FAILURE",
                        conn=conn,
                    )
                    return False, "Invalid account security configuration. Access denied.", None

                # Check account lockout status
                locked_until_str = user_dict.get("locked_until")
                if locked_until_str:
                    try:
                        locked_until = datetime.strptime(locked_until_str, "%Y-%m-%d %H:%M:%S")
                        if now < locked_until:
                            remaining_secs = int((locked_until - now).total_seconds())
                            remaining_mins = max(1, (remaining_secs // 60) + 1)
                            log_security_event(
                                event_type="AUTH_BLOCKED",
                                severity="WARNING",
                                description=f"Login attempted while account '{clean_username}' is locked.",
                                user_id=user_dict["user_id"],
                                ip_address=ip_address,
                                status="BLOCKED",
                                conn=conn,
                            )
                            return False, f"Account locked due to multiple failed login attempts. Try again in {remaining_mins} minute(s).", None
                        else:
                            # Lockout period expired; automatically reset lock and counter
                            cursor.execute("""
                                UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE user_id = ?
                            """, (user_dict["user_id"],))
                            user_dict["failed_login_attempts"] = 0
                    except Exception:
                        return False, "Account status error. Access denied.", None

                # Verify password using Argon2id
                is_correct = verify_password(password, pwd_hash)

                if not is_correct:
                    # Atomically increment failed attempts in database to defeat race conditions
                    cursor.execute("""
                        UPDATE users
                        SET failed_login_attempts = failed_login_attempts + 1
                        WHERE user_id = ?
                        RETURNING failed_login_attempts
                    """, (user_dict["user_id"],))
                    new_attempts = cursor.fetchone()[0]

                    if new_attempts >= MAX_FAILED_ATTEMPTS:
                        lockout_until = (now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
                        cursor.execute("""
                            UPDATE users SET locked_until = ? WHERE user_id = ?
                        """, (lockout_until, user_dict["user_id"]))

                        log_security_event(
                            event_type="ACCOUNT_LOCKED",
                            severity="CRITICAL",
                            description=f"Account '{clean_username}' locked for {LOCKOUT_DURATION_MINUTES} mins after {new_attempts} consecutive failed attempts.",
                            user_id=user_dict["user_id"],
                            ip_address=ip_address,
                            status="BLOCKED",
                            conn=conn,
                        )
                        return False, f"Maximum login attempts exceeded ({MAX_FAILED_ATTEMPTS}). Account is locked for {LOCKOUT_DURATION_MINUTES} minutes.", None
                    else:
                        log_security_event(
                            event_type="AUTH_FAILURE",
                            severity="WARNING",
                            description=f"Failed password attempt for user '{clean_username}' (Attempt {new_attempts}/{MAX_FAILED_ATTEMPTS}).",
                            user_id=user_dict["user_id"],
                            ip_address=ip_address,
                            status="FAILURE",
                            conn=conn,
                        )
                        remaining = MAX_FAILED_ATTEMPTS - new_attempts
                        return False, f"Invalid username or password. {remaining} attempt(s) remaining before lockout.", None

                # --- Authentication Successful ---
                # 1. Reset failed attempts & clear lockout
                cursor.execute("""
                    UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = ? WHERE user_id = ?
                """, (now_str, user_dict["user_id"]))

                # 2. Invalidate previous active sessions for this user (single-session policy)
                cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_dict["user_id"],))

                # 3. Create fresh high-entropy session token (256-bit URL-safe token)
                raw_session_token = secrets.token_urlsafe(32)
                token_hash = hash_session_token(raw_session_token)
                eff_timeout = timeout_minutes if timeout_minutes is not None else SESSION_TIMEOUT_MINUTES
                expires_at = (now + timedelta(minutes=eff_timeout)).strftime("%Y-%m-%d %H:%M:%S")

                # 4. Store ONLY hashed token in database (zero plaintext token storage)
                cursor.execute("""
                    INSERT INTO sessions (session_token_hash, user_id, username, role, created_at, expires_at, is_active, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (token_hash, user_dict["user_id"], user_dict["username"], user_dict["role"], now_str, expires_at, ip_address))

                session_data = {
                    "session_token": raw_session_token,
                    "session_token_hash": token_hash,
                    "user_id": user_dict["user_id"],
                    "username": user_dict["username"],
                    "full_name": user_dict["full_name"],
                    "role": user_dict["role"],
                    "expires_at": expires_at,
                    "ip_address": ip_address,
                }

                log_security_event(
                    event_type="AUTH_SUCCESS",
                    severity="INFO",
                    description=f"User '{clean_username}' successfully authenticated (Role: {user_dict['role']}).",
                    user_id=user_dict["user_id"],
                    ip_address=ip_address,
                    status="SUCCESS",
                    conn=conn,
                )

                return True, "Authentication successful.", session_data

    except Exception:
        return False, "Authentication service error. Access denied.", None


# ==============================================================================
# 4. SESSION MANAGEMENT
# ==============================================================================

def validate_session(
    session_token: str,
    current_time: datetime = None,
    timeout_minutes: int = None,
) -> dict | None:
    """
    Validate session token authenticity, check active status, and enforce 30-min sliding expiration.
    Hashes the incoming raw token and queries against session_token_hash in the database.

    Parameters:
    -----------
    session_token: str (the raw session token held by client)
    current_time: datetime (optional, supports controlled clock testing)
    timeout_minutes: int (optional, supports configurable test timeouts like 1 or 2 minutes)

    Returns:
    --------
    dict with session and user metadata if valid; None if expired or invalid.
    """
    if not session_token or not isinstance(session_token, str):
        return None

    token_hash = hash_session_token(session_token)
    now = current_time or datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, u.full_name, u.is_active AS user_active, u.role AS current_user_role
            FROM sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.session_token_hash = ? AND s.is_active = 1
        """, (token_hash,))
        session = cursor.fetchone()

        if not session:
            return None

        sess_dict = dict(session)

        # Check if user account was deactivated while session was alive
        if not sess_dict["user_active"]:
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE session_token_hash = ?", (token_hash,))
            return None

        # Check if user role was changed while session was alive (stale privilege prevention)
        if sess_dict.get("role") != sess_dict.get("current_user_role"):
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE session_token_hash = ?", (token_hash,))
            log_security_event(
                event_type="SESSION_REVOKED",
                severity="WARNING",
                description=f"Session revoked for user '{sess_dict['username']}': Role changed from '{sess_dict['role']}' to '{sess_dict['current_user_role']}'.",
                user_id=sess_dict["user_id"],
                status="BLOCKED",
                conn=conn,
            )
            return None

        # Check expiration against now
        expires_at = datetime.strptime(sess_dict["expires_at"], "%Y-%m-%d %H:%M:%S")
        if now > expires_at:
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE session_token_hash = ?", (token_hash,))
            log_security_event(
                event_type="SESSION_EXPIRED",
                severity="WARNING",
                description=f"Session for user '{sess_dict['username']}' expired due to inactivity.",
                user_id=sess_dict["user_id"],
                ip_address=sess_dict.get("ip_address", "127.0.0.1"),
                status="EXPIRED",
                metadata={"username": sess_dict["username"], "event": "SESSION_EXPIRED"},
                conn=conn,
            )
            return None

        # Sliding window: Refresh expiration time on active user interaction
        eff_timeout = timeout_minutes if timeout_minutes is not None else SESSION_TIMEOUT_MINUTES
        new_expiry = (now + timedelta(minutes=eff_timeout)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE sessions SET expires_at = ? WHERE session_token_hash = ?", (new_expiry, token_hash))
        sess_dict["expires_at"] = new_expiry
        sess_dict["session_token"] = session_token

        return sess_dict


def logout_user(session_token: str) -> bool:
    """
    Explicitly terminate a user session and mark token inactive.
    Prevents session reuse.
    """
    if not session_token or not isinstance(session_token, str):
        return False

    token_hash = hash_session_token(session_token)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, username FROM sessions
            WHERE session_token_hash = ? AND is_active = 1
        """, (token_hash,))
        row = cursor.fetchone()

        if row:
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE session_token_hash = ?", (token_hash,))
            log_security_event(
                event_type="LOGOUT",
                severity="INFO",
                description=f"User '{row['username']}' successfully logged out.",
                user_id=row["user_id"],
                status="SUCCESS",
                conn=conn,
            )
            return True
        return False


def expire_session(
    session_token: str,
    reason: str = "inactivity",
    current_time: datetime = None,
) -> bool:
    """
    Explicitly expire an active session due to inactivity or simulation.
    Marks session inactive in SQLite (is_active = 0) and logs a SESSION_EXPIRED security event.
    """
    if not session_token or not isinstance(session_token, str):
        return False

    token_hash = hash_session_token(session_token)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, u.username AS user_name
            FROM sessions s
            LEFT JOIN users u ON s.user_id = u.user_id
            WHERE s.session_token_hash = ? AND s.is_active = 1
        """, (token_hash,))
        sess = cursor.fetchone()
        if not sess:
            return False

        sess_dict = dict(sess)
        username = sess_dict.get("username") or sess_dict.get("user_name") or "unknown"
        cursor.execute("UPDATE sessions SET is_active = 0 WHERE session_token_hash = ?", (token_hash,))
        log_security_event(
            event_type="SESSION_EXPIRED",
            severity="WARNING",
            description=f"Session for user '{username}' expired due to {reason}.",
            user_id=sess_dict.get("user_id"),
            ip_address=sess_dict.get("ip_address", "127.0.0.1"),
            status="EXPIRED",
            metadata={"username": username, "reason": reason},
            conn=conn,
        )
        return True


def get_session_info(session_token: str) -> dict | None:
    """Fetch session row from database without altering expires_at or sliding window."""
    if not session_token or not isinstance(session_token, str):
        return None
    token_hash = hash_session_token(session_token)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, u.full_name, u.role AS current_role
            FROM sessions s
            LEFT JOIN users u ON s.user_id = u.user_id
            WHERE s.session_token_hash = ?
        """, (token_hash,))
        row = cursor.fetchone()
        return dict(row) if row else None


if __name__ == "__main__":
    print("=" * 75)
    print("DEMONSTRATION: USER AUTHENTICATION & ARGON2ID SECURITY")
    print("=" * 75)

    # 1. Seed demo users
    seed_default_users()
    print("[PASS] Demo accounts initialized.")

    # 2. Test successful authentication
    doc_pwd = config.DEMO_CREDENTIALS["dr_smith"]["password"]
    ok, msg, session = authenticate_user("dr_smith", doc_pwd)
    print(f"\n1. Successful Login Test:\n -> {msg}")
    print(f" -> Raw Session Token: {session['session_token'][:16]}... (Length: {len(session['session_token'])})")
    print(f" -> Stored Token Hash: {session['session_token_hash'][:16]}... (SHA-256)")
    print(f" -> Authenticated Role: {session['role']}")

    # 3. Test Session Validation
    validated = validate_session(session["session_token"])
    print(f"\n2. Session Validation Test:\n -> Validated user: {validated['full_name']} ({validated['role']})")
    print(f" -> Sliding Expiry Extended: {validated['expires_at']}")

    # 4. Test Invalid Password
    bad_ok, bad_msg, _ = authenticate_user("dr_smith", "WrongPassword!99")
    print(f"\n3. Bad Password Test:\n -> {bad_msg}")

    # 5. Test Logout
    logout_ok = logout_user(session["session_token"])
    print(f"\n4. User Logout Test:\n -> Logout status: {logout_ok}")
    print(f" -> Session active after logout? {validate_session(session['session_token']) is not None}")
    print("=" * 75)
