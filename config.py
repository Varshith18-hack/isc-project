"""
Configuration Module for Medical Device Security System
======================================================
Course: Information Security and Cryptography (AI 331) - SVNIT
Project: AI-Based Anomaly Detection and Secure Audit System for Connected Medical Devices

This module centralizes all configuration settings across the application:
1. File paths for data, models, database, and logs.
2. Medical device simulation parameters and physiological thresholds.
3. Machine learning hyperparameters for Isolation Forest.
4. Cryptographic parameters (AES-256, SHA-256, HMAC).
5. Information Security and Role-Based Access Control (RBAC) definitions.
"""

import os
from pathlib import Path

# ==============================================================================
# 1. BASE PATHS & DIRECTORY STRUCTURE
# ==============================================================================
# BASE_DIR points to the project root directory
BASE_DIR = Path(__file__).resolve().parent

# Automatically load environment variables from .env if present (Zero-dependency parser)
ENV_FILE = BASE_DIR / ".env"
if ENV_FILE.exists():
    with open(ENV_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                env_key, env_val = line.split("=", 1)
                env_key = env_key.strip()
                env_val = env_val.strip().strip("\"'")
                if env_key and env_key not in os.environ:
                    os.environ[env_key] = env_val

# Subdirectory paths
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
SECURITY_DIR = BASE_DIR / "security"
AUDIT_DIR = BASE_DIR / "audit"
DATABASE_DIR = BASE_DIR / "database"
DASHBOARD_DIR = BASE_DIR / "dashboard"
TESTS_DIR = BASE_DIR / "tests"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

# File paths
DATA_FILE_PATH = DATA_DIR / "medical_device_data.csv"
MODEL_FILE_PATH = MODELS_DIR / "saved_model.pkl"
DATABASE_FILE_PATH = DATABASE_DIR / "medical_security.db"
AUDIT_LOG_FILE_PATH = AUDIT_DIR / "audit_chain.json"

# Checkpoint configuration (independent directory support for privilege separation)
CHECKPOINT_DIR = Path(os.environ.get("CHECKPOINT_DIR", str(SECURITY_DIR)))
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINT_FILE_PATH = CHECKPOINT_DIR / ".chain_checkpoint.json"

# ==============================================================================
# 2. MEDICAL DEVICE SIMULATION CONFIGURATION
# ==============================================================================
# Simulated Connected Medical Device Types
DEVICE_PROFILES = {
    "DEV-PUMP-001": {"type": "Infusion Pump", "location": "ICU Room 101"},
    "DEV-VENT-002": {"type": "Mechanical Ventilator", "location": "ICU Room 102"},
    "DEV-MON-003": {"type": "Multi-Parameter Patient Monitor", "location": "General Ward Bed 04"},
    "DEV-DIAL-004": {"type": "Hemodialysis Machine", "location": "Dialysis Unit 02"},
    "DEV-ECG-005": {"type": "Telemetry ECG Transmitter", "location": "Cardiac Care Unit 03"},
}

# Normal physiological & device activity baselines (for synthetic generation)
NORMAL_RANGES = {
    "heart_rate": (60.0, 100.0),            # Beats per minute (bpm)
    "systolic_bp": (90.0, 120.0),           # mmHg
    "diastolic_bp": (60.0, 80.0),           # mmHg
    "oxygen_saturation": (95.0, 100.0),     # SpO2 percentage (%)
    "body_temperature": (36.5, 37.5),       # Degrees Celsius (°C)
    "device_activity_level": (10.0, 60.0),  # Packets / messages transmitted per min
    "battery_level": (30.0, 100.0),         # Battery charge percentage (%)
}

# Features used for ML Anomaly Detection
FEATURE_COLUMNS = [
    "heart_rate",
    "systolic_bp",
    "diastolic_bp",
    "oxygen_saturation",
    "body_temperature",
    "device_activity_level",
]

# ==============================================================================
# 3. AI & ISOLATION FOREST CONFIGURATION
# ==============================================================================
# Isolation Forest hyperparameters
# Contamination: Expected proportion of anomalies in the training set (~5%)
ML_CONFIG = {
    "n_estimators": 150,           # Number of isolation trees
    "contamination": 0.05,         # Expected anomaly ratio
    "max_samples": "auto",         # Sample size drawn to train each tree
    "random_state": 42,            # Fixed seed for reproducibility
    "bootstrap": False,
}

# ==============================================================================
# 4. CRYPTOGRAPHIC CONFIGURATION
# ==============================================================================
# AES-256 Encryption in GCM mode (Authenticated Encryption with Associated Data)
AES_KEY_SIZE_BYTES = 32      # 256 bits = 32 bytes
GCM_NONCE_SIZE_BYTES = 12    # Standard 96-bit nonce for GCM
GCM_TAG_SIZE_BYTES = 16      # 128-bit authentication tag

# HMAC Authentication
HMAC_ALGORITHM = "SHA256"    # Using SHA-256 for HMAC calculation
HMAC_KEY_SIZE_BYTES = 32     # 256-bit key for HMAC integrity

# Key derivation & management
KDF_SALT_SIZE_BYTES = 16     # 128-bit salt
KDF_ITERATIONS = 100_000     # PBKDF2 iterations for key derivation

# Secret Key environment variable names (avoids hardcoding keys in code)
SYSTEM_MASTER_KEY_ENV = "MED_DEVICE_MASTER_KEY"
SYSTEM_HMAC_KEY_ENV = "MED_DEVICE_HMAC_KEY"

# ==============================================================================
# 5. INFORMATION SECURITY & RBAC CONFIGURATION
# ==============================================================================
# Role-Based Access Control definitions
ROLES = {
    "admin": {
        "description": "System Administrator with full access to audit, security, and device controls.",
        "permissions": [
            "view_dashboard",
            "manage_users",
            "access_system_config",
            "view_audit_logs",
            "manage_device_access",
            "verify_audit_chain",
            "trigger_simulation",
            "configure_crypto",
            "view_readings",
            "view_anomaly_alerts",
            "request_decryption",
        ],
    },
    "medical_staff": {
        "description": "Doctors and nurses monitoring real-time patient status and anomaly alerts.",
        "permissions": [
            "view_dashboard",
            "view_readings",
            "view_anomaly_alerts",
            "access_authorized_devices",
            "request_decryption",
        ],
    },
    "auditor": {
        "description": "Independent security auditor verifying log integrity and compliance.",
        "permissions": [
            "view_dashboard",
            "view_audit_logs",
            "view_auth_events",
            "view_crypto_verification",
            "verify_audit_chain",
        ],
    },
}

# Aggregate list of all recognized permissions across all roles
PERMISSIONS = sorted(list({p for r in ROLES.values() for p in r.get("permissions", [])}))

# Password Policy Configuration
PASSWORD_POLICY = {
    "min_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
    "require_special": True,
}

# Brute-force & Lockout Settings
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# Session timeout (in minutes - sliding window)
SESSION_TIMEOUT_MINUTES = 30

# ==============================================================================
# 6. APPLICATION ENVIRONMENT & DEMO CONFIGURATION
# ==============================================================================
# APP_ENV: 'development', 'staging', or 'production'
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()

# DEMO_MODE: Explicit flag to enable demo-only conveniences (e.g. persona switcher)
# In production, DEMO_MODE is strictly enforced to False regardless of env vars.
if APP_ENV == "production":
    DEMO_MODE = False
else:
    DEMO_MODE = os.environ.get("DEMO_MODE", "true").strip().lower() in ("true", "1", "yes")

# Network lockdown settings (Default: strict loopback binding)
SERVER_HOST = os.environ.get("STREAMLIT_SERVER_ADDRESS", "127.0.0.1")
SERVER_PORT = int(os.environ.get("STREAMLIT_SERVER_PORT", "8501"))

# Configurable Demo Credentials (Development / Evaluation Mode Only)
# Rotated from previously exposed credentials; overridable via environment variables.
# In production, this dictionary is strictly empty to prevent pre-configured account injection.
if not DEMO_MODE:
    DEMO_CREDENTIALS = {}
else:
    DEMO_CREDENTIALS = {
        "admin": {
            "username": os.environ.get("DEMO_ADMIN_USERNAME", "admin"),
            "password": os.environ.get("DEMO_ADMIN_PASSWORD", "K8x#mP9$vL2@wQ5!zR4"),
            "full_name": "Chief Security Officer Alice",
            "role": "admin",
            "user_id": "USR-ADMIN-01",
        },
        "dr_smith": {
            "username": os.environ.get("DEMO_DOCTOR_USERNAME", "dr_smith"),
            "password": os.environ.get("DEMO_DOCTOR_PASSWORD", "C9$yT2#uJ8!pW4@vN6"),
            "full_name": "Dr. Sarah Smith (ICU Lead)",
            "role": "medical_staff",
            "user_id": "USR-DOC-02",
        },
        "nurse_clara": {
            "username": os.environ.get("DEMO_NURSE_USERNAME", "nurse_clara"),
            "password": os.environ.get("DEMO_NURSE_PASSWORD", "W3@zE7!rX9#tB2$mK5"),
            "full_name": "Nurse Clara Barton (Telemetry Ward)",
            "role": "medical_staff",
            "user_id": "USR-NURSE-03",
        },
        "auditor_davis": {
            "username": os.environ.get("DEMO_AUDITOR_USERNAME", "auditor_davis"),
            "password": os.environ.get("DEMO_AUDITOR_PASSWORD", "A4#bH7$kM1@yV8!pQ3"),
            "full_name": "Marcus Davis (Compliance Auditor)",
            "role": "auditor",
            "user_id": "USR-AUDIT-04",
        },
    }

