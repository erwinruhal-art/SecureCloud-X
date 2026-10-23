"""
Unit Tests: ASKG and HMAC-DRBG Key Generator
Verifies internal state maintenance, key uniqueness, reseeding, and rotation.
"""

import unittest
import os
from crypto.hmac_drbg import HMAC_DRBG
from crypto.askg import AdaptiveSecureKeyGenerator


class TestKeyGeneration(unittest.TestCase):

    def test_hmac_drbg_state(self):
        """HMAC-DRBG initializes K and V to 32 bytes and produces bytes."""
        drbg = HMAC_DRBG()
        self.assertEqual(len(drbg.K), 32)
        self.assertEqual(len(drbg.V), 32)

        out1 = drbg.generate(32)
        out2 = drbg.generate(32)
        self.assertEqual(len(out1), 32)
        self.assertEqual(len(out2), 32)
        self.assertNotEqual(out1, out2)

    def test_askg_generation_and_uniqueness(self):
        """ASKG generates 256-bit keys and guarantees uniqueness across 100 iterations."""
        askg = AdaptiveSecureKeyGenerator(reseed_interval=20)
        generated_keys = set()

        for _ in range(100):
            key_id, raw_key, metadata = askg.generate_session_key()
            self.assertEqual(len(raw_key), 32)
            self.assertEqual(metadata["key_size"], 256)
            self.assertEqual(metadata["algorithm"], "HMAC-DRBG / SHA-256")
            self.assertNotIn(raw_key, generated_keys)
            generated_keys.add(raw_key)

        self.assertEqual(len(generated_keys), 100)

    def test_askg_reseed_and_rotation(self):
        """Reseed updates entropy and key rotation marks active key."""
        askg = AdaptiveSecureKeyGenerator(reseed_interval=5)
        initial_reseed_count = askg.reseed_count

        # Force reseed
        askg.reseed()
        self.assertEqual(askg.reseed_count, initial_reseed_count + 1)

        # Force rotate
        key_id, raw_key, metadata = askg.rotate_key()
        self.assertTrue(key_id.startswith("KEY-"))
        self.assertEqual(metadata["status"], "Active")


if __name__ == "__main__":
    unittest.main()
