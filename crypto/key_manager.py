"""
SecureCloud-X: Hybrid Key Management & Post-Quantum Key Encapsulation (HKDF + ML-KEM)
Enforces strict cryptographic key separation:
  1. ASKG-Generated Session Key (K_session): 256-bit symmetric key that encrypts the file payload.
  2. ML-KEM Shared Secret (ss_kem): 32-byte secret established via post-quantum encapsulation.
  3. HKDF-Derived Wrapping Key (K_wrap): 256-bit key derived from ss_kem using HKDF-SHA256.
  4. Wrapped Session Key: K_session encrypted under K_wrap using ChaCha20-Poly1305.

Notice: Plaintext session keys are never stored in SQLite or persisted to disk.
Only the KEM ciphertext, wrapped session key, and wrap nonce are stored in metadata.
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from crypto.mlkem_service import mlkem_service
from crypto.chacha_service import encrypt_data, decrypt_data
from config import KEM_KEYS_DIR

HKDF_INFO = b"SecureCloud-X-KeyWrap-v1"


def derive_wrapping_key(shared_secret: bytes, salt: bytes = None) -> bytes:
    """
    Derives a 256-bit symmetric key-wrapping key (K_wrap) from the ML-KEM
    shared secret using HKDF-SHA256 according to RFC 5869.
    """
    if len(shared_secret) != 32:
        raise ValueError(f"ML-KEM shared secret must be 32 bytes, got {len(shared_secret)}")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def wrap_session_key(session_key: bytes, kem_public_key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Protects the ASKG file session key using post-quantum ML-KEM encapsulation:
      1. Encapsulates against recipient's ML-KEM public key -> (ss_kem, c_kem).
      2. Derives K_wrap from ss_kem using HKDF-SHA256.
      3. Encrypts K_session using K_wrap via ChaCha20-Poly1305 -> (wrapped_key, wrap_nonce).
      
    Returns:
        kem_ciphertext (bytes): KEM encapsulation ciphertext.
        wrapped_session_key (bytes): Encrypted session key payload.
        wrap_nonce (bytes): 12-byte nonce used by the key-wrapping cipher.
    """
    if len(session_key) != 32:
        raise ValueError(f"Session key must be 32 bytes, got {len(session_key)}")

    # Step 1: ML-KEM encapsulation
    shared_secret, kem_ciphertext = mlkem_service.encapsulate(kem_public_key)

    # Step 2: HKDF-SHA256 derivation of wrapping key
    wrapping_key = derive_wrapping_key(shared_secret)

    # Step 3: Wrap session key with ChaCha20-Poly1305
    wrapped_session_key, wrap_nonce = encrypt_data(session_key, wrapping_key)

    return kem_ciphertext, wrapped_session_key, wrap_nonce


def unwrap_session_key(kem_ciphertext: bytes, wrapped_session_key: bytes,
                       wrap_nonce: bytes, kem_private_key: bytes) -> bytes:
    """
    Recovers the ASKG file session key using post-quantum ML-KEM decapsulation:
      1. Decapsulates c_kem using recipient's ML-KEM private key -> ss_kem.
      2. Derives K_wrap from ss_kem using HKDF-SHA256.
      3. Decrypts wrapped_session_key using K_wrap and wrap_nonce -> K_session.
      
    Returns:
        recovered_session_key (bytes): 32-byte plaintext session key.
    """
    # Step 1: ML-KEM decapsulation
    shared_secret = mlkem_service.decapsulate(kem_private_key, kem_ciphertext)

    # Step 2: HKDF-SHA256 derivation of wrapping key
    wrapping_key = derive_wrapping_key(shared_secret)

    # Step 3: Decrypt wrapped session key
    recovered_session_key = decrypt_data(wrapped_session_key, wrapping_key, wrap_nonce)

    return recovered_session_key


def get_or_create_system_kem_keypair() -> tuple[bytes, bytes]:
    """
    Loads or generates the recipient's post-quantum ML-KEM keypair.
    In a multi-user cloud system, the storage enabler / cloud recipient has
    an ML-KEM keypair to securely receive and decapsulate wrapped keys.
    """
    pub_path = KEM_KEYS_DIR / "system_kem_public.bin"
    priv_path = KEM_KEYS_DIR / "system_kem_private.bin"

    if pub_path.exists() and priv_path.exists():
        with open(pub_path, "rb") as f:
            pub_key = f.read()
        with open(priv_path, "rb") as f:
            priv_key = f.read()
        return pub_key, priv_key

    # Generate new pair
    pub_key, priv_key = mlkem_service.generate_keypair()
    with open(pub_path, "wb") as f:
        f.write(pub_key)
    with open(priv_path, "wb") as f:
        f.write(priv_key)

    return pub_key, priv_key
