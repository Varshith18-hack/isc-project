"""
Authentication Database Interface Adapter
=========================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

Exposes relational persistence and authentication database operations:
- Connection pooling and thread-safe SQLite context manager.
- Schema initialization and migrations.
- User management, session persistence, and security event queries.
"""

from database.database import (
    get_db_connection,
    initialize_database,
    log_security_event,
    get_security_events,
    get_user_by_username,
    get_all_users,
    set_user_status,
    update_user_role,
    save_encrypted_telemetry,
    get_encrypted_telemetry,
    DB_PATH,
)

__all__ = [
    "get_db_connection",
    "initialize_database",
    "log_security_event",
    "get_security_events",
    "get_user_by_username",
    "get_all_users",
    "set_user_status",
    "update_user_role",
    "save_encrypted_telemetry",
    "get_encrypted_telemetry",
    "DB_PATH",
]

