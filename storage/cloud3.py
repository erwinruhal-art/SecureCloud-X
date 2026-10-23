"""
SecureCloud-X: Simulated Cloud Provider C
Simulates an independent cloud storage repository (e.g. Google Cloud Storage simulation).
"""

import os
from pathlib import Path
from config import CLOUD_C_DIR


class SimulatedCloudC:
    """Represents Cloud Provider C."""

    def __init__(self):
        self.name = "Cloud C"
        self.storage_dir = Path(CLOUD_C_DIR)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.is_online = True

    def store_fragment(self, filename: str, data: bytes) -> Path:
        """Stores a file fragment on Cloud C."""
        if not self.is_online:
            raise ConnectionError(f"{self.name} is currently offline (simulated outage).")
        file_path = self.storage_dir / filename
        with open(file_path, "wb") as f:
            f.write(data)
        return file_path

    def retrieve_fragment(self, filename: str) -> bytes:
        """Retrieves a stored fragment from Cloud C."""
        if not self.is_online:
            raise ConnectionError(f"{self.name} is currently offline (simulated outage).")
        file_path = self.storage_dir / filename
        if not file_path.exists():
            raise FileNotFoundError(f"Fragment {filename} not found in {self.name}.")
        with open(file_path, "rb") as f:
            return f.read()

    def tamper_fragment(self, filename: str) -> bool:
        """Intentionally corrupts bytes in a fragment to demonstrate integrity verification."""
        file_path = self.storage_dir / filename
        if not file_path.exists():
            return False
        with open(file_path, "rb") as f:
            data = bytearray(f.read())
        if len(data) > 0:
            data[0] ^= 0xAA
            if len(data) > 8:
                data[8] ^= 0x77
        with open(file_path, "wb") as f:
            f.write(data)
        return True

    def get_status(self) -> dict:
        """Returns provider health and fragment count."""
        count = len(list(self.storage_dir.glob("*"))) if self.storage_dir.exists() else 0
        return {
            "name": self.name,
            "status": "Online" if self.is_online else "Offline",
            "directory": str(self.storage_dir),
            "fragments_stored": count
        }


cloud_c = SimulatedCloudC()
