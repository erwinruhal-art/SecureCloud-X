"""
SecureCloud-X: Blockchain Block Definition
Defines the structure and cryptographic hashing logic for an immutable integrity block.
"""

import hashlib
import json
from datetime import datetime


class Block:
    """Represents a single cryptographic block in the integrity ledger."""

    def __init__(self, index: int, file_id: str, file_hash: str, previous_hash: str,
                 transaction_info: str = "FILE_UPLOAD", timestamp: str = None,
                 nonce_proof: int = 0, current_hash: str = None):
        self.index = index
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.file_id = file_id
        self.file_hash = file_hash
        self.previous_hash = previous_hash
        self.nonce_proof = nonce_proof
        self.transaction_info = transaction_info
        self.current_hash = current_hash or self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Computes SHA-256 hash across block header attributes to guarantee tamper resistance.
        """
        header = f"{self.index}|{self.timestamp}|{self.file_id}|{self.file_hash}|{self.previous_hash}|{self.nonce_proof}|{self.transaction_info}"
        return hashlib.sha256(header.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        """Converts block to dictionary representation."""
        return {
            "block_index": self.index,
            "timestamp": self.timestamp,
            "file_id": self.file_id,
            "file_hash": self.file_hash,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "nonce_proof": self.nonce_proof,
            "transaction_info": self.transaction_info
        }
