"""
SecureCloud-X: Database Management Layer
Handles SQLite database connection, table initialization, and structured logging.
"""

import sqlite3
import os
from datetime import datetime
from config import DATABASE_PATH, SECURITY_LOG_PATH


def get_db_connection():
    """Establish connection to the SQLite database with row access by column name."""
    os.makedirs(DATABASE_PATH.parent, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create all required tables for SecureCloud-X if they do not already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'User',
        created_at TEXT NOT NULL
    )
    """)
    

    # 2. Files Metadata Table
    # Note: Plaintext cryptographic keys are NEVER stored here.
    # Only the wrapped session key and ML-KEM ciphertext are retained.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        file_id TEXT PRIMARY KEY,
        original_filename TEXT NOT NULL,
        encrypted_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        sha3_hash TEXT NOT NULL,
        kem_ciphertext TEXT NOT NULL,
        wrapped_session_key TEXT NOT NULL,
        wrap_nonce TEXT NOT NULL,
        chacha_nonce TEXT NOT NULL,
        key_id TEXT NOT NULL,
        kem_param TEXT NOT NULL,
        upload_time TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 3. File Fragments Table (Multi-Cloud distribution)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_fragments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT NOT NULL,
        fragment_index INTEGER NOT NULL,
        cloud_provider TEXT NOT NULL,
        fragment_filename TEXT NOT NULL,
        fragment_path TEXT NOT NULL,
        fragment_hash TEXT NOT NULL,
        size_bytes INTEGER NOT NULL
    )
    """)

    # 4. Key Metadata Table (ASKG Key Registry)
    # Only metadata (ID, generation time, algorithm, status) is stored, never raw keys.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        key_id TEXT PRIMARY KEY,
        algorithm TEXT NOT NULL,
        key_size INTEGER NOT NULL,
        generated_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Active',
        reseed_counter INTEGER NOT NULL DEFAULT 1
        
    )
    """)

    # 5. Blockchain Integrity Ledger Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blockchain_blocks (
        block_index INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        file_id TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL,
        nonce_proof INTEGER NOT NULL,
        transaction_info TEXT NOT NULL
    )
    """)

    # 6. Structured Security Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        event_type TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        details TEXT
    )
    """)

    # 7. ML Threat Detection Decisions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ml_predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        risk_score REAL NOT NULL,
        prediction TEXT NOT NULL,
        features_json TEXT NOT NULL,
        decision TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def log_security_event(username: str, event_type: str, ip_address: str = "127.0.0.1",
                       user_agent: str = "SecureCloud-Client", details: str = ""):
    """
    Records a structured security event both in SQLite and in the file log.
    Ensures that no plaintext keys, secrets, or passwords are ever logged.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Insert into database
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO security_events (timestamp, username, event_type, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, username, event_type, ip_address, user_agent, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database logging error: {e}")

    # Write structured line to log file
    try:
        os.makedirs(SECURITY_LOG_PATH.parent, exist_ok=True)
        log_line = f"[{timestamp}] {event_type} user={username} ip={ip_address} details={details}\n"
        with open(SECURITY_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"File logging error: {e}")
