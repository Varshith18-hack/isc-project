"""
Role-Based Access Control (RBAC) & Authorization Engine
======================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Implements granular, least-privilege Role-Based Access Control (RBAC):
1. Three Distinct Security Roles:
   - admin: Full administrative governance, user management, crypto configuration, audit inspection.
   - medical_staff: Clinical monitoring of patient telemetry and AI anomaly detection alerts.
   - auditor: Independent compliance inspection of security audit logs and hash chains (read-only).
2. Backend Authorization Enforcement:
   - Verifies permissions programmatically before executing sensitive operations.
   - Reusable decorators (@require_permission) and functional checks (has_permission, enforce_permission).
3. Intrusion Detection & Audit Trail:
   - Automatically detects unauthorized access attempts.
   - Immediately logs UNAUTHORIZED_ACCESS_ATTEMPT events in SQLite security_events with high severity.
   - Raises AccessDeniedError preventing data leakage.
"""

import sys
import functools
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from database.database import log_security_event


class AccessDeniedError(Exception):
    """
    Raised when an authenticated or unauthenticated entity attempts an operation
    exceeding their assigned Role-Based Access Control permissions.
    """
    def __init__(
        self,
        message: str,
        user_id: str = None,
        username: str = None,
        role: str = None,
        required_permission: str = None,
        resource: str = None,
    ):
        super().__init__(message)
        self.message = message
        self.user_id = user_id
        self.username = username
        self.role = role
        self.required_permission = required_permission
        self.resource = resource

    def to_dict(self) -> dict:
        return {
            "error": "ACCESS_DENIED",
            "message": self.message,
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role,
            "required_permission": self.required_permission,
            "resource": self.resource,
        }


# ==============================================================================
# 1. CORE PERMISSION EVALUATION
# ==============================================================================

def get_role_permissions(role: str) -> list[str]:
    """Retrieve list of granted permissions for a given role from config."""
    if not role or role not in config.ROLES:
        return []
    return config.ROLES[role].get("permissions", [])


def has_permission(role: str, permission: str) -> bool:
    """
    Check if a specific role possesses the requested permission.
    Pure boolean check (no side effects or logging).
    """
    if not role or not permission:
        return False
    granted = get_role_permissions(role)
    return permission in granted


def check_access(
    user_or_session: dict | None,
    required_permission: str,
) -> tuple[bool, str]:
    """
    Evaluate whether a user session has access to perform an operation.
    Returns:
    tuple: (is_allowed: bool, reason: str)
    """
    if not user_or_session or not isinstance(user_or_session, dict):
        return False, "Unauthenticated: No active session provided."

    role = user_or_session.get("role")
    if not role:
        return False, "Invalid session: No role associated with session."

    if role not in config.ROLES:
        return False, f"Unknown security role '{role}'."

    if has_permission(role, required_permission):
        return True, f"Permission '{required_permission}' granted to role '{role}'."

    return False, f"Role '{role}' lacks required permission '{required_permission}'."


def enforce_permission(
    user_or_session: dict | None,
    required_permission: str,
    resource: str = None,
    ip_address: str = "127.0.0.1",
) -> bool:
    """
    Enforce RBAC policy on an active session.
    If authorized: returns True.
    If unauthorized: logs UNAUTHORIZED_ACCESS_ATTEMPT in SQLite and raises AccessDeniedError.
    """
    is_allowed, reason = check_access(user_or_session, required_permission)

    if is_allowed:
        return True

    # Extract user metadata safely
    user_id = user_or_session.get("user_id") if isinstance(user_or_session, dict) else "ANONYMOUS"
    username = user_or_session.get("username") if isinstance(user_or_session, dict) else "unknown"
    role = user_or_session.get("role") if isinstance(user_or_session, dict) else "none"

    resource_desc = f" on resource '{resource}'" if resource else ""
    event_desc = (
        f"Unauthorized access attempt: User '{username}' (Role: '{role}', ID: {user_id}) "
        f"denied permission '{required_permission}'{resource_desc}."
    )

    # Log security event with HIGH/WARNING severity
    log_security_event(
        event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
        severity="WARNING" if role in config.ROLES else "CRITICAL",
        description=event_desc,
        user_id=user_id,
        ip_address=ip_address,
        status="BLOCKED",
        metadata={
            "required_permission": required_permission,
            "role": role,
            "resource": resource,
        },
    )

    raise AccessDeniedError(
        message=f"Access Denied: {reason}",
        user_id=user_id,
        username=username,
        role=role,
        required_permission=required_permission,
        resource=resource,
    )


# ==============================================================================
# 2. REUSABLE AUTHORIZATION DECORATOR
# ==============================================================================

def require_permission(permission: str, resource: str = None):
    """
    Decorator to enforce RBAC permissions on backend service functions.

    The wrapped function must accept a `session` argument (either positional or keyword).
    Example:
        @require_permission("manage_users")
        def create_new_doctor(session, user_data):
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Look for session in kwargs first, then positional args
            session = kwargs.get("session")
            if session is None and args:
                # Check if first or second arg is a session dict
                for arg in args:
                    if isinstance(arg, dict) and ("role" in arg or "session_token" in arg or "session_token_hash" in arg):
                        session = arg
                        break

            # Enforce permission
            enforce_permission(session, permission, resource=resource or func.__name__)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ==============================================================================
# 3. SPECIALIZED CLINICAL & AUDIT RESTRICTIONS (LEAST PRIVILEGE)
# ==============================================================================

def can_view_telemetry(role: str) -> bool:
    """Medical staff and admins can view live patient telemetry."""
    return has_permission(role, "view_readings")


def can_view_anomalies(role: str) -> bool:
    """Medical staff and admins can view AI anomaly alerts."""
    return has_permission(role, "view_anomaly_alerts")


def can_manage_users(role: str) -> bool:
    """Only administrators can manage users and assign roles."""
    return has_permission(role, "manage_users")


def can_view_audit_logs(role: str) -> bool:
    """Auditors and administrators have read access to security audit logs."""
    return has_permission(role, "view_audit_logs")


def can_verify_audit_chain(role: str) -> bool:
    """Auditors and administrators can run cryptographic hash chain verification."""
    return has_permission(role, "verify_audit_chain")


def can_configure_cryptography(role: str) -> bool:
    """Only administrators can modify cryptographic configurations or key policies."""
    return has_permission(role, "configure_crypto")


def filter_patient_data_for_role(data_records: list[dict], role: str) -> list[dict]:
    """
    Enforces least privilege at the dataset level.
    - medical_staff and admin: Full clinical telemetry.
    - auditor: Redacts clinical telemetry (preserves timestamps and reading_id for audit).
    - other: Returns empty list.
    """
    if not role or role not in config.ROLES:
        return []

    if role in ("admin", "medical_staff"):
        return data_records

    if role == "auditor":
        # Auditor should inspect audit metadata without accessing private patient vitals
        redacted = []
        for r in data_records:
            item = dict(r)
            for vital in ["heart_rate", "systolic_bp", "diastolic_bp", "oxygen_saturation", "body_temperature"]:
                if vital in item:
                    item[vital] = "[REDACTED_FOR_AUDITOR]"
            redacted.append(item)
        return redacted

    return []


if __name__ == "__main__":
    print("=" * 75)
    print("DEMONSTRATION: ROLE-BASED ACCESS CONTROL (RBAC) ENGINE")
    print("=" * 75)

    # Simulated Sessions
    admin_sess = {"user_id": "USR-01", "username": "admin", "role": "admin"}
    doctor_sess = {"user_id": "USR-02", "username": "dr_smith", "role": "medical_staff"}
    auditor_sess = {"user_id": "USR-03", "username": "auditor_davis", "role": "auditor"}

    print("\n1. Permission Checks:")
    print(f" -> Admin can manage users:            {has_permission(admin_sess['role'], 'manage_users')}")
    print(f" -> Doctor can manage users:           {has_permission(doctor_sess['role'], 'manage_users')}")
    print(f" -> Doctor can view telemetry:         {has_permission(doctor_sess['role'], 'view_readings')}")
    print(f" -> Auditor can view audit logs:       {has_permission(auditor_sess['role'], 'view_audit_logs')}")
    print(f" -> Auditor can manage users:          {has_permission(auditor_sess['role'], 'manage_users')}")

    print("\n2. Decorator Enforcement Test:")

    @require_permission("manage_users")
    def administrative_user_creation(session, new_user_name: str):
        return f"[SUCCESS] User '{new_user_name}' created by {session['username']}."

    # Test Admin Success
    result = administrative_user_creation(admin_sess, "dr_watson")
    print(f" -> Admin Action: {result}")

    # Test Doctor Blocked
    try:
        administrative_user_creation(doctor_sess, "unauthorized_user")
    except AccessDeniedError as e:
        print(f" -> Doctor Action Blocked: {e.message}")
        print(f" -> Event automatically logged to security_events table.")

    # Test Auditor Blocked from Crypto Config
    try:
        enforce_permission(auditor_sess, "configure_crypto", resource="KeyManagementService")
    except AccessDeniedError as e:
        print(f" -> Auditor Action Blocked: {e.message}")
        print(f" -> Event automatically logged to security_events table.")

    print("=" * 75)

