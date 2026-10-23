"""
SecureCloud-X: Post-Quantum Cryptography Service (ML-KEM / FIPS 203)
Provides modular post-quantum Key Encapsulation Mechanism (ML-KEM-768 / Kyber).

Includes a clean abstraction layer:
  - generate_keypair()
  - encapsulate(public_key)
  - decapsulate(private_key, ciphertext)

Provides an explicit status report to ensure transparent UI indication of
"ML-KEM MODE: ACTIVE" vs clearly marked DEVELOPMENT FALLBACK.
"""

import os
import hashlib
from config import MLKEM_PARAM_SET

# Attempt to load the FIPS 203 ML-KEM implementation
_MLKEM_AVAILABLE = False
_MLKEM_ENGINE = None

try:
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    _MLKEM_ENGINES = {
        "ML-KEM-512": ML_KEM_512,
        "ML-KEM-768": ML_KEM_768,
        "ML-KEM-1024": ML_KEM_1024,
    }
    _MLKEM_ENGINE = _MLKEM_ENGINES.get(MLKEM_PARAM_SET, ML_KEM_768)
    _MLKEM_AVAILABLE = True
except ImportError:
    _MLKEM_AVAILABLE = False


class MLKEMService:
    """
    Modular wrapper for Post-Quantum ML-KEM key encapsulation.
    Default parameter set: ML-KEM-768 (NIST Category 3 equivalent to AES-192).
    """

    def __init__(self, param_set: str = MLKEM_PARAM_SET):
        self.param_set = param_set
        self.is_active = _MLKEM_AVAILABLE
        self.engine = _MLKEM_ENGINE

    def get_status(self) -> dict:
        """Returns the current operational mode of the ML-KEM service."""
        if self.is_active:
            return {
                "status_text": "ML-KEM MODE: ACTIVE",
                "is_fallback": False,
                "parameter_set": self.param_set,
                "security_standard": "FIPS 203 (NIST Post-Quantum Cryptography)",
                "description": f"Standard {self.param_set} Lattice-based KEM actively running."
            }
        else:
            return {
                "status_text": "ML-KEM DEVELOPMENT FALLBACK: ACTIVE",
                "is_fallback": True,
                "parameter_set": "SIMULATED-KEM-FALLBACK",
                "security_standard": "Academic Development Fallback Only",
                "description": "ML-KEM library unavailable; running in marked development fallback mode."
            }

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """
        Generates an ML-KEM public encapsulation key and private decapsulation key.
        
        Returns:
            public_key (bytes): Encapsulation key (1184 bytes for ML-KEM-768)
            private_key (bytes): Decapsulation key (2400 bytes for ML-KEM-768)
        """
        if self.is_active and self.engine:
            ek, dk = self.engine.keygen()
            return bytes(ek), bytes(dk)
        else:
            # Clearly marked DEVELOPMENT FALLBACK ONLY
            priv = os.urandom(32)
            pub = hashlib.sha3_256(priv + b"SIMULATED_KEM_PUB").digest()
            return pub, priv

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulates a shared secret using the recipient's ML-KEM public key.
        
        Args:
            public_key: Public encapsulation key bytes.
            
        Returns:
            shared_secret (bytes): 32-byte post-quantum shared secret.
            ciphertext (bytes): KEM ciphertext (1088 bytes for ML-KEM-768).
        """
        if self.is_active and self.engine:
            shared_secret, ciphertext = self.engine.encaps(public_key)
            return bytes(shared_secret), bytes(ciphertext)
        else:
            # Fallback encapsulation simulation
            ephemeral = os.urandom(32)
            ciphertext = ephemeral + hashlib.sha3_256(public_key + ephemeral).digest()
            shared_secret = hashlib.sha3_256(ciphertext + b"FALLBACK_SECRET").digest()
            return shared_secret, ciphertext

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulates the shared secret using the recipient's ML-KEM private key.
        
        Args:
            private_key: Private decapsulation key bytes.
            ciphertext: KEM ciphertext previously generated during encapsulation.
            
        Returns:
            shared_secret (bytes): 32-byte post-quantum shared secret.
        """
        if self.is_active and self.engine:
            shared_secret = self.engine.decaps(private_key, ciphertext)
            return bytes(shared_secret)
        else:
            # Fallback decapsulation simulation
            return hashlib.sha3_256(ciphertext + b"FALLBACK_SECRET").digest()


# Global ML-KEM service instance
mlkem_service = MLKEMService()
