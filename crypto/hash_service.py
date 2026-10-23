"""
SecureCloud-X: Hashing and Integrity Cryptographic Service
Uses standard SHA3-256 for file and data integrity checks,
and SHA-256 for blockchain block headers and fast identifier generation.
"""

import hashlib


def compute_sha3_256(data: bytes) -> str:
    """
    Computes the SHA3-256 cryptographic hash of arbitrary byte data.
    Returns the 64-character lowercase hex digest.
    """
    hasher = hashlib.sha3_256()
    hasher.update(data)
    return hasher.hexdigest()


def compute_sha256(data: bytes) -> str:
    """
    Computes the standard SHA-256 hash of arbitrary byte data.
    Returns the 64-character lowercase hex digest.
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def verify_sha3_integrity(data: bytes, expected_hash: str) -> bool:
    """
    Verifies that the SHA3-256 digest of `data` strictly matches `expected_hash`.
    Uses constant-time comparison to prevent timing side-channels.
    """
    actual_hash = compute_sha3_256(data)
    # hashlib.sha3_256 produces lowercase hex; normalize input
    expected_normalized = expected_hash.strip().lower()
    import hmac
    return hmac.compare_digest(actual_hash, expected_normalized)
