"""
SecureCloud-X: Adaptive Secure Session Key Generator (ASKG)
An application-level key-generation module based on HMAC-DRBG using SHA-256,
additional entropy input, and periodic reseeding.

Notice: This module wraps standard HMAC-DRBG (NIST SP 800-90A) and applies
application-level key lifecycle management (generation, reseeding, rotation,
and metadata tracking). It does not introduce any unverified cryptographic primitives.
"""

import os
import time
import uuid
from datetime import datetime
from crypto.hmac_drbg import HMAC_DRBG
from database.database import get_db_connection, log_security_event


class AdaptiveSecureKeyGenerator:
    """
    Manages session key generation for SecureCloud-X using HMAC-DRBG.
    Collects high-entropy seeds from os.urandom() mixed with system micro-timing,
    enforces periodic reseeding, and tracks key metadata.
    """

    def __init__(self, reseed_interval: int = 50):
        self.reseed_interval = reseed_interval
        self.generation_count = 0
        self.total_keys_generated = 0
        self.reseed_count = 0
        self.active_key_id = None
        self.drbg = None
        self._initialize_generator()

    def _collect_additional_entropy(self) -> bytes:
        """
        Gathers supplementary runtime entropy (monotonic timing, process ID)
        to mix with cryptographically secure OS entropy.
        """
        timestamp_nano = str(time.perf_counter_ns()).encode()
        pid = str(os.getpid()).encode()
        thread_id = str(time.thread_time_ns()).encode()
        return timestamp_nano + pid + thread_id

    def _initialize_generator(self):
        """Initializes HMAC-DRBG with fresh OS entropy and personalization."""
        primary_entropy = os.urandom(32)
        nonce = os.urandom(16)
        personalization = b"SecureCloud-X_ASKG_Init_" + self._collect_additional_entropy()

        self.drbg = HMAC_DRBG(entropy=primary_entropy, nonce=nonce, personalization=personalization)
        self.reseed_count = 1
        self.generation_count = 0

    def reseed(self, force: bool = False):
        """Reseeds the internal HMAC-DRBG instance with fresh OS entropy."""
        fresh_entropy = os.urandom(32)
        additional_input = self._collect_additional_entropy()
        self.drbg.reseed(entropy=fresh_entropy, additional_input=additional_input)
        self.reseed_count += 1
        self.generation_count = 0

    def generate_session_key(self, scope: str = "application") -> tuple[str, bytes, dict]:
        """
        Generates a fresh 256-bit (32 bytes) symmetric session key.
        
        Returns:
            key_id (str): Human-readable unique key identifier (e.g. KEY-0042)
            raw_key (bytes): 32-byte binary session key
            metadata (dict): Safe metadata for logging and UI display (no secret bits)
        """
        # Periodic reseeding check
        if self.generation_count >= self.reseed_interval:
            self.reseed()

        additional_input = self._collect_additional_entropy()
        raw_key = self.drbg.generate(num_bytes=32, additional_input=additional_input)

        self.generation_count += 1
        self.total_keys_generated += 1

        key_id = f"KEY-{self.total_keys_generated:04d}"
        self.active_key_id = key_id
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        metadata = {
            "key_id": key_id,
            "algorithm": "HMAC-DRBG / SHA-256",
            "key_size": 256,
            "status": "Active",
            "generated_at": timestamp_str,
            "reseed_count": self.reseed_count
        }

        # Store only metadata in the database
        try:
            conn = get_db_connection()
            conn.execute("""
                INSERT OR REPLACE INTO keys (key_id, algorithm, key_size, generated_at, status, reseed_counter)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (key_id, metadata["algorithm"], metadata["key_size"], metadata["generated_at"],
                  metadata["status"], metadata["reseed_count"]))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error persisting key metadata: {e}")

        # Note: Raw key is returned in memory for immediate encryption and NEVER logged.
        log_security_event("SYSTEM", "KEY_GENERATED", details=f"key_id={key_id} algorithm=HMAC-DRBG-SHA256")

        return key_id, raw_key, metadata

    def rotate_key(self) -> tuple[str, bytes, dict]:
        """
        Forces an explicit HMAC-DRBG reseed and generates a new active session key,
        marking previous keys as Rotated.
        """
        self.reseed(force=True)

        # Mark previously active key as Rotated in SQLite
        if self.active_key_id:
            try:
                conn = get_db_connection()
                conn.execute("UPDATE keys SET status = 'Rotated' WHERE key_id = ?", (self.active_key_id,))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Error updating key status: {e}")

        return self.generate_session_key()

    def get_key_stats(self) -> dict:
        """Returns operational summary of the ASKG module."""
        return {
            "algorithm": "HMAC-DRBG",
            "hash_function": "SHA-256",
            "key_size_bits": 256,
            "reseed_interval": self.reseed_interval,
            "reseed_count": self.reseed_count,
            "total_keys_generated": self.total_keys_generated,
            "active_key_id": self.active_key_id or "None"
        }


# Global singleton instance for application session key management
askg_instance = AdaptiveSecureKeyGenerator()
