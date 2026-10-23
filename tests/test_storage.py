"""
Unit Tests: Multi-Cloud Storage Simulation & Fragmentation
Verifies fragment distribution across Cloud A, B, and C and binary reassembly.
"""

import unittest
import os
from storage.fragmentation import fragment_data, reassemble_fragments
from storage.cloud_manager import CloudManager
from database.database import init_db


class TestStorageSimulation(unittest.TestCase):

    def setUp(self):
        init_db()
        self.cloud_mgr = CloudManager()

    def test_fragmentation_and_reassembly(self):
        """Payload divided into 3 pieces reassembles byte-for-byte to original."""
        original_data = os.urandom(1024 * 15)  # 15 KB test binary
        fragments = fragment_data(original_data, num_fragments=3)

        self.assertEqual(len(fragments), 3)
        reassembled = reassemble_fragments(fragments)
        self.assertEqual(reassembled, original_data)

    def test_multi_cloud_distribution_and_retrieval(self):
        """Full cycle: distribute across Cloud A/B/C -> retrieve and reconstruct."""
        original_payload = b"Academic Multi-Cloud Storage Payload Verification."
        test_file_id = "FILE-STORAGE-TEST"

        # Distribute
        stored_frags = self.cloud_mgr.distribute_file(test_file_id, original_payload)
        self.assertEqual(len(stored_frags), 3)

        # Retrieve & Reconstruct
        reconstructed = self.cloud_mgr.retrieve_and_reconstruct(test_file_id)
        self.assertEqual(reconstructed, original_payload)


if __name__ == "__main__":
    unittest.main()
