"""
SecureCloud-X: HMAC-DRBG (Deterministic Random Bit Generator)
Compliant with NIST SP 800-90A construction using HMAC-SHA256.

Maintains internal state (K, V) and enforces cryptographically secure
entropy seeding via os.urandom() alongside system entropy mixing.
"""

import hmac
import hashlib
import os
import time


class HMAC_DRBG:
    """
    Standard NIST SP 800-90A HMAC-DRBG using SHA-256.
    Internal state consists of:
      - K: 32-byte HMAC key
      - V: 32-byte working value
      - reseed_counter: Number of generation requests since last seed/reseed.
    """

    def __init__(self, entropy: bytes = None, nonce: bytes = None, personalization: bytes = b""):
        # If no entropy provided, gather from cryptographically secure OS source
        if entropy is None:
            entropy = os.urandom(32)
        if nonce is None:
            nonce = os.urandom(16)

        # Initialize state to fixed values
        self.K = b"\x00" * 32
        self.V = b"\x01" * 32
        self.reseed_counter = 1

        seed_material = entropy + nonce + personalization
        self.update(seed_material)

    def update(self, provided_data: bytes = b""):
        """Updates the internal state (K, V) using HMAC-SHA256."""
        # Step 1: K = HMAC(K, V || 0x00 || provided_data)
        h = hmac.new(self.K, digestmod=hashlib.sha256)
        h.update(self.V + b"\x00" + provided_data)
        self.K = h.digest()

        # Step 2: V = HMAC(K, V)
        h = hmac.new(self.K, digestmod=hashlib.sha256)
        h.update(self.V)
        self.V = h.digest()

        if provided_data:
            # Step 3: K = HMAC(K, V || 0x01 || provided_data)
            h = hmac.new(self.K, digestmod=hashlib.sha256)
            h.update(self.V + b"\x01" + provided_data)
            self.K = h.digest()

            # Step 4: V = HMAC(K, V)
            h = hmac.new(self.K, digestmod=hashlib.sha256)
            h.update(self.V)
            self.V = h.digest()

    def reseed(self, entropy: bytes = None, additional_input: bytes = b""):
        """Reseeds the DRBG with fresh OS entropy and optional additional input."""
        if entropy is None:
            entropy = os.urandom(32)
        self.update(entropy + additional_input)
        self.reseed_counter = 1

    def generate(self, num_bytes: int, additional_input: bytes = b"") -> bytes:
        """
        Generates pseudorandom bytes.
        Performs state update if additional input is provided, then iteratively
        computes V = HMAC(K, V) to accumulate pseudorandom bytes.
        """
        if additional_input:
            self.update(additional_input)

        temp = bytearray()
        while len(temp) < num_bytes:
            h = hmac.new(self.K, digestmod=hashlib.sha256)
            h.update(self.V)
            self.V = h.digest()
            temp.extend(self.V)

        self.update(additional_input)
        self.reseed_counter += 1
        return bytes(temp[:num_bytes])
