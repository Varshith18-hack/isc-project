"""
SQLite Database Layer & Persistence Engine
==========================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Purpose:
--------
Provides structured, secure relational persistence for:
1. Users & Credentials (storing salted Argon2id password hashes, never plaintext).
2. Active User Sessions (with timeouts and token validation).
3. Security Event Monitoring & Audit Trail (recording authentication events, unauthorized access, and alerts).
4. Encrypted Telemetry Records (storing AES-256-GCM ciphertexts with nonces, tags, and AAD).
"""

import sys
import os
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta
from contextlib import contextmanager

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config

DB_PATH = config.DATABASE_FILE_PATH


@contextmanager
def get_db_connection():
    """
    Context manager providing a thread-safe SQLite connection
    with WAL mode enabled, busy timeout, and Row factory configured.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    # Enable Write-Ahead Logging (WAL) for concurrent read/write performance
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database():
    """
    Create database tables if they do not exist and apply schema migrations.
    Creates:
    - users: User profiles, salted password hashes, roles, and lockout status.
    - sessions: Ephemeral login session tokens with timestamps and expiration (stores SHA-256 hash of token).
    - security_events: Security audit log for access monitoring and intrusion detection.
    - encrypted_telemetry: Stored AES-256-GCM encrypted medical records.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Users Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT
        );
        """)

        # 2. Check and migrate sessions table to use session_token_hash
        cursor.execute("PRAGMA table_info(sessions)")
        sess_cols = [col[1] for col in cursor.fetchall()]
        if sess_cols and "session_id" in sess_cols and "session_token_hash" not in sess_cols:
            cursor.execute("DROP TABLE sessions")

        # 2. Sessions Table (stores SHA-256 hash of token for zero plaintext storage)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );
        """)

        # 3. Security Events Table (Access Control & Intrusion Detection)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            user_id TEXT,
            device_id TEXT,
            description TEXT NOT NULL,
            ip_address TEXT,
            status TEXT DEFAULT 'SUCCESS',
            metadata TEXT
        );
        """)

        # Check and migrate security_events if status column is missing
        cursor.execute("PRAGMA table_info(security_events)")
        event_cols = [col[1] for col in cursor.fetchall()]
        if event_cols and "status" not in event_cols:
            cursor.execute("ALTER TABLE security_events ADD COLUMN status TEXT DEFAULT 'SUCCESS';")

        # 4. Encrypted Telemetry Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_telemetry (
            record_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            auth_tag TEXT NOT NULL,
            associated_data TEXT,
            ai_status TEXT,
            ai_score REAL,
            created_at TEXT NOT NULL
        );
        """)

        # 5. Independent Audit Chain Anchor (Monotonic High-Water Mark)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_anchor (
            anchor_id INTEGER PRIMARY KEY CHECK (anchor_id = 1),
            max_event_id INTEGER NOT NULL,
            max_event_hash TEXT NOT NULL,
            last_committed_timestamp TEXT NOT NULL,
            anchor_hmac TEXT NOT NULL
        );
        """)

        # Indices for high-speed indexing
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_device ON encrypted_telemetry(device_id);")


# ==============================================================================
# DATABASE CRUD HELPERS
# ==============================================================================

def log_security_event(
    event_type: str,
    severity: str,
    description: str,
    user_id: str = None,
    device_id: str = None,
    ip_address: str = "127.0.0.1",
    status: str = "SUCCESS",
    metadata: dict = None,
    conn: sqlite3.Connection = None,
) -> int:
    """
    Log an immutable security audit event into the database.

    Event Types:
    - AUTH_SUCCESS, AUTH_FAILURE, ACCOUNT_LOCKED, LOGOUT
    - ACCESS_GRANTED, ACCESS_DENIED, UNAUTHORIZED_ATTEMPT
    - ANOMALY_ALERT, CRYPTO_TAMPER_DETECTED, KEY_ROTATION
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta_str = json.dumps(metadata) if metadata else None

    sql = """
        INSERT INTO security_events (
            timestamp, event_type, severity, user_id, device_id, description, ip_address, status, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (timestamp, event_type, severity, user_id, device_id, description, ip_address, status, meta_str)

    if conn is not None:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        return cursor.lastrowid
    else:
        with get_db_connection() as new_conn:
            cursor = new_conn.cursor()
            cursor.execute(sql, params)
            return cursor.lastrowid


def get_security_events(limit: int = 50, event_type: str = None) -> list[dict]:
    """Retrieve recent security monitoring events."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if event_type:
            cursor.execute("""
                SELECT * FROM security_events WHERE event_type = ? ORDER BY event_id DESC LIMIT ?
            """, (event_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM security_events ORDER BY event_id DESC LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def save_encrypted_telemetry(
    record_id: str,
    device_id: str,
    timestamp: str,
    algorithm: str,
    nonce: str,
    ciphertext: str,
    auth_tag: str,
    associated_data: str = None,
    ai_status: str = "NORMAL",
    ai_score: float = 0.0,
) -> bool:
    """Save an AES-256-GCM encrypted medical telemetry record to database."""
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO encrypted_telemetry (
                record_id, device_id, timestamp, algorithm, nonce, ciphertext,
                auth_tag, associated_data, ai_status, ai_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record_id, device_id, timestamp, algorithm, nonce, ciphertext,
            auth_tag, associated_data, ai_status, ai_score, created_at
        ))
        return True


def get_encrypted_telemetry(device_id: str = None, limit: int = 50) -> list[dict]:
    """Retrieve stored encrypted telemetry records."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if device_id:
            cursor.execute("""
                SELECT * FROM encrypted_telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?
            """, (device_id, limit))
        else:
            cursor.execute("""
                SELECT * FROM encrypted_telemetry ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_user_by_username(username: str) -> dict | None:
    """Fetch user account dictionary by username."""
    if not username:
        return None
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_all_users() -> list[dict]:
    """Fetch all users (excluding raw password hash for safe listing)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, username, full_name, role, is_active, failed_login_attempts, locked_until, created_at, last_login
            FROM users ORDER BY created_at ASC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def set_user_status(user_id: str, is_active: bool) -> bool:
    """Activate or deactivate a user account."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_active = ? WHERE user_id = ?", (1 if is_active else 0, user_id))
        if not is_active:
            # Terminate active sessions for deactivated user
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))
        return cursor.rowcount > 0


def update_user_role(user_id: str, new_role: str) -> bool:
    """Update role for a user account and invalidate active sessions."""
    if new_role not in config.ROLES:
        return False
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE user_id = ?", (new_role, user_id))
        # Terminate active sessions to enforce immediate re-authentication with new privileges
        cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))
        return cursor.rowcount > 0


# ==============================================================================
# INDEPENDENT AUDIT ANCHOR (MONOTONIC HIGH-WATER MARK)
# ==============================================================================

def update_audit_anchor(
    max_event_id: int,
    max_event_hash: str,
    timestamp: str,
    conn: sqlite3.Connection = None,
) -> dict:
    """
    Persist the monotonic audit anchor inside the SQLite database,
    signed with institutional HMAC-SHA256. Prevents checkpoint rollback attacks.
    """
    from security.hashing import compute_hmac
    header = {
        "max_event_id": max_event_id,
        "max_event_hash": max_event_hash,
        "timestamp": timestamp,
    }
    anchor_hmac = compute_hmac(header)

    query = """
    INSERT INTO audit_anchor (anchor_id, max_event_id, max_event_hash, last_committed_timestamp, anchor_hmac)
    VALUES (1, ?, ?, ?, ?)
    ON CONFLICT(anchor_id) DO UPDATE SET
        max_event_id = excluded.max_event_id,
        max_event_hash = excluded.max_event_hash,
        last_committed_timestamp = excluded.last_committed_timestamp,
        anchor_hmac = excluded.anchor_hmac;
    """
    params = (max_event_id, max_event_hash, timestamp, anchor_hmac)

    if conn is not None:
        conn.execute(query, params)
    else:
        with get_db_connection() as c:
            c.execute(query, params)

    return {**header, "anchor_hmac": anchor_hmac}


def get_audit_anchor(conn: sqlite3.Connection = None) -> dict | None:
    """
    Retrieve and forensically authenticate the persistent audit anchor from SQLite.
    Returns None if empty. Returns {'is_corrupted': True} if HMAC fails.
    """
    from security.hashing import verify_hmac
    query = "SELECT max_event_id, max_event_hash, last_committed_timestamp, anchor_hmac FROM audit_anchor WHERE anchor_id = 1"
    row = None
    if conn is not None:
        row = conn.execute(query).fetchone()
    else:
        with get_db_connection() as c:
            row = c.execute(query).fetchone()

    if not row:
        return None

    data = dict(row)
    header = {
        "max_event_id": data["max_event_id"],
        "max_event_hash": data["max_event_hash"],
        "timestamp": data["last_committed_timestamp"],
    }
    if not verify_hmac(header, data["anchor_hmac"]):
        return {"is_corrupted": True, **data}
    return data


def reset_audit_anchor(conn: sqlite3.Connection = None):
    """Reset persistent audit anchor (for testing and administrative reset)."""
    query = "DELETE FROM audit_anchor WHERE anchor_id = 1"
    if conn is not None:
        conn.execute(query)
    else:
        with get_db_connection() as c:
            c.execute(query)


if __name__ == "__main__":
    print("=" * 70)
    print("INITIALIZING SQLITE SECURITY DATABASE")
    print("=" * 70)
    initialize_database()
    print(f"[PASS] Database schema initialized at: {DB_PATH.resolve()}")

    # Test event logging
    event_id = log_security_event(
        event_type="SYSTEM_INIT",
        severity="INFO",
        description="Database schema initialized and verified.",
        user_id="SYSTEM",
    )
    print(f"[PASS] Test security event logged with Event ID: {event_id}")
    print("=" * 70)
