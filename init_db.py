"""
SecureCloud-X: Database Initialization & Seeding Script
Initializes SQLite tables, default users, blockchain genesis block, and demo logs.

Default Demo Account:
  Username: admin
  Password: admin123
  Role: Admin
  Notice: This account is intended for local academic evaluation and viva demonstration only.

Run command: python init_db.py
"""

from werkzeug.security import generate_password_hash
from datetime import datetime
from database.database import init_db, get_db_connection, log_security_event
from blockchain.ledger import blockchain_ledger
from crypto.key_manager import get_or_create_system_kem_keypair


def seed_database():
    print("=" * 60)
    print("SecureCloud-X: Initializing System Database & Cryptographic Keys")
    print("=" * 60)

    # 1. Initialize all SQLite tables
    init_db()
    print("[+] Database tables verified/created.")

    # 2. Ensure Blockchain Genesis block exists
    blockchain_ledger.ensure_genesis_block()
    print("[+] Blockchain ledger initialized with Genesis Block.")

    # 3. Ensure System Post-Quantum ML-KEM Keypair exists
    pub_key, priv_key = get_or_create_system_kem_keypair()
    print(f"[+] Post-Quantum ML-KEM keypair initialized (Public key: {len(pub_key)} bytes, Private key: {len(priv_key)} bytes).")

    # 4. Seed default demo accounts
    conn = get_db_connection()
    cursor = conn.cursor()

    users_to_seed = [
        ("admin", "admin123", "Admin"),
        ("student", "student123", "User")
    ]

    for username, password, role in users_to_seed:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing = cursor.fetchone()
        if not existing:
            pwd_hash = generate_password_hash(password, method="pbkdf2:sha256")
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
            """, (username, pwd_hash, role, now_str))
            print(f"[+] Seeded user: {username} (Role: {role})")
        else:
            print(f"[*] User '{username}' already exists.")

    conn.commit()
    conn.close()

    log_security_event("SYSTEM", "SYSTEM_INIT", details="SecureCloud-X database seeded successfully")
    print("=" * 60)
    print("Database initialization complete.")
    print("=" * 60)


if __name__ == "__main__":
    seed_database()
