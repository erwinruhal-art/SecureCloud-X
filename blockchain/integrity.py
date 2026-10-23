"""
SecureCloud-X: File Integrity Verification Service
Verifies reconstructed file payloads against SHA3-256 blockchain records.
Detects any unauthorized modification, bit flips, or fragment tampering.
"""

from crypto.hash_service import compute_sha3_256, verify_sha3_integrity
from blockchain.ledger import blockchain_ledger
from database.database import log_security_event


def verify_file_integrity(file_id: str, reconstructed_data: bytes, username: str = "anonymous") -> dict:
    """
    Verifies that the SHA3-256 hash of reconstructed ciphertext strictly matches
    the immutable record stored in the blockchain ledger.
    
    Args:
        file_id: The unique identifier of the file.
        reconstructed_data: The reassembled encrypted bytes.
        username: User requesting the verification.
        
    Returns:
        dict containing integrity status, expected hash, calculated hash, and match boolean.
    """
    record = blockchain_ledger.get_file_record(file_id)

    if not record:
        return {
            "status": "ERROR_NO_RECORD",
            "is_valid": False,
            "message": f"No blockchain integrity record found for file {file_id}."
        }

    expected_hash = record["file_hash"]
    actual_hash = compute_sha3_256(reconstructed_data)
    is_valid = verify_sha3_integrity(reconstructed_data, expected_hash)

    if is_valid:
        log_security_event(username, "HASH_VERIFIED", details=f"file_id={file_id} sha3={actual_hash[:16]}...")
        # Optionally record a verification transaction in the ledger
        return {
            "status": "INTEGRITY_VERIFIED",
            "is_valid": True,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "block_index": record["block_index"],
            "timestamp": record["timestamp"],
            "message": "SHA3-256 hash matches blockchain ledger. File integrity confirmed."
        }
    else:
        log_security_event(username, "HASH_MISMATCH", details=f"file_id={file_id} expected={expected_hash[:16]}... got={actual_hash[:16]}...")
        log_security_event(username, "BLOCKCHAIN_TAMPER_DETECTED", details=f"file_id={file_id} status=TAMPERING_DETECTED")
        return {
            "status": "TAMPERING_DETECTED",
            "is_valid": False,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "block_index": record["block_index"],
            "timestamp": record["timestamp"],
            "message": "ALERT: SHA3-256 mismatch detected! File payload has been tampered with or corrupted in cloud storage."
        }
