"""
Security Audit Logger Module
============================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Provides structured, privacy-preserving security event logging into SQLite:
- Logs authentication events (logins, logouts, lockouts).
- Logs access control events (unauthorized access attempts, privilege elevations).
- Sanitizes logs to guarantee zero secret leakage (passwords, session tokens, master keys).
- Prepares audit events for Stage 6 cryptographic hash-chaining.
"""

import sys
from pathlib import Path
from datetime import datetime

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import re
from database.database import log_security_event, get_security_events, get_db_connection


# Comprehensive normalized patterns for sensitive credential fields
SENSITIVE_KEY_PATTERNS = {
    "password", "passwd", "pwd", "passphrase", "secret",
    "masterkey", "apikey", "token", "sessiontoken", "authtoken",
    "privatekey", "privkey", "accesstoken", "refreshtoken",
    "authtag", "credential", "jwt", "bearer", "authorization",
}

# Regex to detect private key blocks and JWT-like strings in values
_PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----", re.IGNORECASE)
_JWT_REGEX = re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def is_sensitive_key(key: any) -> bool:
    """Check if key name matches any sensitive credential pattern after alphanumeric normalization."""
    if not isinstance(key, str):
        key = str(key)
    normalized = re.sub(r"[^a-zA-Z0-9]", "", key).lower()
    return any(pat in normalized for pat in SENSITIVE_KEY_PATTERNS)


def sanitize_metadata(data: any) -> any:
    """
    Recursively scrub sensitive credential fields, private keys, tokens, and secrets
    from audit metadata across nested dictionaries, lists, tuples, and sets.
    """
    if data is None:
        return None

    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if is_sensitive_key(k):
                sanitized[str(k)] = "[REDACTED_SECRET]"
            else:
                sanitized[str(k)] = sanitize_metadata(v)
        return sanitized

    elif isinstance(data, (list, tuple, set)):
        sanitized_list = []
        for item in data:
            sanitized_list.append(sanitize_metadata(item))
        return sanitized_list

    elif isinstance(data, str):
        # Value inspection: detect raw private key pem strings or JWT tokens
        if _PRIVATE_KEY_REGEX.search(data):
            return "[REDACTED_PRIVATE_KEY]"
        if _JWT_REGEX.match(data.strip()):
            return "[REDACTED_JWT]"
        return data

    else:
        # Primitive scalar types (int, float, bool)
        return data


def log_auth_success(
    user_id: str,
    username: str,
    role: str,
    ip_address: str = "127.0.0.1",
) -> int:
    """Log successful user authentication."""
    return log_security_event(
        event_type="AUTH_SUCCESS",
        severity="INFO",
        description=f"User '{username}' successfully authenticated (Role: {role}).",
        user_id=user_id,
        ip_address=ip_address,
        status="SUCCESS",
        metadata={"role": role},
    )


def log_auth_failure(
    username: str,
    reason: str,
    user_id: str = None,
    attempt_count: int = None,
    ip_address: str = "127.0.0.1",
) -> int:
    """Log failed authentication attempt."""
    desc = f"Authentication failure for user '{username}': {reason}"
    if attempt_count is not None:
        desc += f" (Attempt {attempt_count})"

    return log_security_event(
        event_type="AUTH_FAILURE",
        severity="WARNING",
        description=desc,
        user_id=user_id,
        ip_address=ip_address,
        status="FAILURE",
        metadata={"attempt_count": attempt_count} if attempt_count else None,
    )


def log_account_lockout(
    user_id: str,
    username: str,
    failed_attempts: int,
    lockout_minutes: int,
    ip_address: str = "127.0.0.1",
) -> int:
    """Log account brute-force defense lockout."""
    return log_security_event(
        event_type="ACCOUNT_LOCKED",
        severity="CRITICAL",
        description=f"Account '{username}' locked for {lockout_minutes} mins after {failed_attempts} failed attempts.",
        user_id=user_id,
        ip_address=ip_address,
        status="BLOCKED",
        metadata={"failed_attempts": failed_attempts, "lockout_minutes": lockout_minutes},
    )


def log_unauthorized_access(
    user_id: str,
    username: str,
    role: str,
    attempted_permission: str,
    resource: str = None,
    ip_address: str = "127.0.0.1",
) -> int:
    """Log unauthorized access attempt (RBAC violation)."""
    res_str = f" on resource '{resource}'" if resource else ""
    return log_security_event(
        event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
        severity="WARNING" if role else "CRITICAL",
        description=f"Access denied for user '{username}' (Role: {role}) attempting '{attempted_permission}'{res_str}.",
        user_id=user_id,
        ip_address=ip_address,
        status="BLOCKED",
        metadata={"attempted_permission": attempted_permission, "role": role, "resource": resource},
    )


def log_user_lifecycle_event(
    event_type: str,
    admin_user_id: str,
    target_username: str,
    target_role: str,
    details: str,
) -> int:
    """Log administrative user creation, role modification, or deactivation."""
    return log_security_event(
        event_type=event_type,
        severity="INFO",
        description=f"Admin {admin_user_id} performed {event_type} on '{target_username}': {details}",
        user_id=admin_user_id,
        status="SUCCESS",
        metadata={"target_username": target_username, "target_role": target_role},
    )


def query_security_events(limit: int = 50, event_type: str = None, severity: str = None) -> list[dict]:
    """Query recent security events with optional type and severity filtering."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM security_events"
        conditions = []
        params = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY event_id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

