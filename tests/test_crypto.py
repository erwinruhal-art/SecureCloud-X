"""
Unit Tests: Cryptographic Services
Verifies ChaCha20-Poly1305, Post-Quantum ML-KEM, HKDF, and Key Wrapping.
"""

import unittest
import os
from crypto.chacha_service import encrypt_data, decrypt_data
from crypto.mlkem_service import mlkem_service
from crypto.key_manager import derive_wrapping_key, wrap_session_key, unwrap_session_key
from crypto.hash_service import compute_sha3_256, verify_sha3_integrity


class TestCryptoPipeline(unittest.TestCase):

    def test_chacha20_roundtrip(self):
        """Plaintext -> Encrypt -> Decrypt -> Compare Original == PASS."""
        key = os.urandom(32)
        plaintext = b"SecureCloud-X Academic Cryptographic Roundtrip Test Payload 2026."

        ciphertext, nonce = encrypt_data(plaintext, key)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(len(nonce), 12)

        decrypted = decrypt_data(ciphertext, key, nonce)
        self.assertEqual(decrypted, plaintext)

    def test_chacha20_tamper_fails(self):
        """Corrupted ciphertext or tag must raise exception."""
        key = os.urandom(32)
        plaintext = b"Sensitive engineering data."
        ciphertext, nonce = encrypt_data(plaintext, key)

        # Corrupt one byte of ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        from cryptography.exceptions import InvalidTag
        with self.assertRaises(InvalidTag):
            decrypt_data(bytes(tampered), key, nonce)

    def test_mlkem_encapsulation_decapsulation(self):
        """ML-KEM Keygen -> Encapsulate -> Decapsulate -> Shared Secret Match."""
        pub_key, priv_key = mlkem_service.generate_keypair()
        self.assertGreater(len(pub_key), 0)
        self.assertGreater(len(priv_key), 0)

        shared_secret_enc, kem_ct = mlkem_service.encapsulate(pub_key)
        self.assertEqual(len(shared_secret_enc), 32)

        shared_secret_dec = mlkem_service.decapsulate(priv_key, kem_ct)
        self.assertEqual(shared_secret_enc, shared_secret_dec)

    def test_hkdf_wrapping_roundtrip(self):
        """Session key wrapping with post-quantum KEM and HKDF-SHA256."""
        pub_key, priv_key = mlkem_service.generate_keypair()
        session_key = os.urandom(32)

        # Wrap session key
        kem_ct, wrapped_key, wrap_nonce = wrap_session_key(session_key, pub_key)
        self.assertNotEqual(wrapped_key, session_key)

        # Unwrap session key
        recovered_key = unwrap_session_key(kem_ct, wrapped_key, wrap_nonce, priv_key)
        self.assertEqual(recovered_key, session_key)

    def test_sha3_256_integrity(self):
        """SHA3-256 calculation and constant-time match verification."""
        sample_bytes = b"Multi-cloud storage block verification"
        digest = compute_sha3_256(sample_bytes)
        self.assertEqual(len(digest), 64)
        self.assertTrue(verify_sha3_integrity(sample_bytes, digest))
        self.assertFalse(verify_sha3_integrity(b"Altered payload", digest))


if __name__ == "__main__":
    unittest.main()
