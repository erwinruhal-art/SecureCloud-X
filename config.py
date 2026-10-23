"""
SecureCloud-X: System Configuration
Contains application constants, directory paths, and security parameters.
"""

import os
from pathlib import Path

# Project root directory
BASE_DIR = Path(__file__).resolve().parent

# Database configuration
DATABASE_PATH = BASE_DIR / "database" / "securecloud.db"

# Storage simulation directories
STORAGE_SIM_DIR = BASE_DIR / "storage_simulation"
CLOUD_A_DIR = STORAGE_SIM_DIR / "cloud_A"
CLOUD_B_DIR = STORAGE_SIM_DIR / "cloud_B"
CLOUD_C_DIR = STORAGE_SIM_DIR / "cloud_C"

# Ensure storage directories exist
for cloud_path in [CLOUD_A_DIR, CLOUD_B_DIR, CLOUD_C_DIR]:
    os.makedirs(cloud_path, exist_ok=True)

# Logging configuration
LOGS_DIR = BASE_DIR / "logs"
os.makedirs(LOGS_DIR, exist_ok=True)
SECURITY_LOG_PATH = LOGS_DIR / "security.log"

# Machine learning model path
ML_MODEL_PATH = BASE_DIR / "ml" / "model.pkl"
ML_DATASET_PATH = BASE_DIR / "ml" / "security_events.csv"

# Post-quantum ML-KEM configuration
# Default parameter set: ML-KEM-768 (NIST Security Category 3)
MLKEM_PARAM_SET = "ML-KEM-768"
KEM_KEYS_DIR = BASE_DIR / "crypto" / "kem_keys"
os.makedirs(KEM_KEYS_DIR, exist_ok=True)

# Flask session security
SECRET_KEY = "securecloud-x-academic-secret-key-btech-2026"

# ML Anomaly risk thresholds
# 0.00 - 0.30: Low risk (Allow)
# 0.30 - 0.70: Medium risk (Allow with warning/log)
# 0.70 - 1.00: High risk (Block sensitive action)
RISK_THRESHOLD_LOW = 0.30
RISK_THRESHOLD_HIGH = 0.70

# File fragmentation settings
FRAGMENT_COUNT = 3
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload limit for academic demo
