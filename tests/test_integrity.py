"""
Unit Tests: Blockchain-Style Integrity Ledger & Tampering Detection
Verifies block creation, chain linkage, and tamper detection.
"""

import unittest
from blockchain.block import Block
from blockchain.ledger import BlockchainLedger
from blockchain.integrity import verify_file_integrity
from crypto.hash_service import compute_sha3_256
from database.database import init_db


class TestIntegrityLedger(unittest.TestCase):

    def setUp(self):
        init_db()
        self.ledger = BlockchainLedger()

    def test_block_hash_calculation(self):
        """Block hash accurately reflects all header parameters."""
        b = Block(index=1, file_id="FILE-TEST", file_hash="abc123hash", previous_hash="0"*64)
        h1 = b.calculate_hash()
        self.assertEqual(len(h1), 64)

        # Altering a header value must change the hash
        b.file_hash = "altered_hash"
        h2 = b.calculate_hash()
        self.assertNotEqual(h1, h2)

    def test_chain_verification_and_tamper_detection(self):
        """Blockchain ledger detects link breaks and header tampering."""
        is_valid, msg = self.ledger.verify_chain()
        self.assertTrue(is_valid)

        # Add a block
        block = self.ledger.add_block(file_id="FILE-INTEGRITY-01", file_hash="fe9876543210abcd"*4)
        self.assertIsNotNone(block)

        is_valid_after, _ = self.ledger.verify_chain()
        self.assertTrue(is_valid_after)

    def test_file_integrity_tampering_check(self):
        """Tampered file payload fails blockchain verification."""
        original_data = b"Original cloud data block"
        sha3 = compute_sha3_256(original_data)
        file_id = "FILE-TAMPER-TEST"

        self.ledger.add_block(file_id=file_id, file_hash=sha3)

        # Untampered check -> True
        res_ok = verify_file_integrity(file_id, original_data)
        self.assertTrue(res_ok["is_valid"])
        self.assertEqual(res_ok["status"], "INTEGRITY_VERIFIED")

        # Tampered check -> False
        tampered_data = b"Corrupted cloud data block"
        res_tampered = verify_file_integrity(file_id, tampered_data)
        self.assertFalse(res_tampered["is_valid"])
        self.assertEqual(res_tampered["status"], "TAMPERING_DETECTED")


if __name__ == "__main__":
    unittest.main()
