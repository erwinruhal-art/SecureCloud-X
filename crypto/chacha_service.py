"""
SecureCloud-X: ChaCha20-Poly1305 Cryptographic Service
Provides authenticated encryption with associated data (AEAD) using
the standard ChaCha20 stream cipher combined with the Poly1305 authenticator.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


def generate_nonce() -> bytes:
    """Generates a cryptographically secure 12-byte (96-bit) nonce."""
    return os.urandom(12)


def encrypt_data(plaintext: bytes, key: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypts plaintext bytes using ChaCha20-Poly1305.
    
    Args:
        plaintext: The raw file or data bytes to encrypt.
        key: 32-byte (256-bit) symmetric key.
        associated_data: Optional authenticated metadata (not encrypted).
        
    Returns:
        ciphertext: The encrypted payload containing authentication tag.
        nonce: The 12-byte nonce used for encryption.
    """
    if len(key) != 32:
        raise ValueError(f"ChaCha20-Poly1305 requires a 32-byte key, got {len(key)} bytes.")

    nonce = generate_nonce()
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce


def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypts ciphertext bytes using ChaCha20-Poly1305 and verifies authenticity.
    
    Args:
        ciphertext: The encrypted data including Poly1305 authentication tag.
        key: 32-byte symmetric key.
        nonce: 12-byte nonce previously used for encryption.
        associated_data: Optional authenticated metadata.
        
    Returns:
        plaintext: The decrypted original byte stream.
        
    Raises:
        InvalidTag: If the ciphertext has been tampered with or key/nonce is invalid.
    """
    if len(key) != 32:
        raise ValueError(f"ChaCha20-Poly1305 requires a 32-byte key, got {len(key)} bytes.")
    if len(nonce) != 12:
        raise ValueError(f"ChaCha20-Poly1305 requires a 12-byte nonce, got {len(nonce)} bytes.")

    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, associated_data)
