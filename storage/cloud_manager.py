"""
SecureCloud-X: Multi-Cloud Storage Manager
Coordinates the distribution, retrieval, integrity checking, and fault simulation
of file fragments across Cloud A, Cloud B, and Cloud C.
"""

from storage.cloud1 import cloud_a
from storage.cloud2 import cloud_b
from storage.cloud3 import cloud_c
from storage.fragmentation import fragment_data, reassemble_fragments
from database.database import get_db_connection, log_security_event


class CloudManager:
    """Manages multi-cloud fragment distribution and retrieval."""

    def __init__(self):
        self.providers = {
            "Cloud A": cloud_a,
            "Cloud B": cloud_b,
            "Cloud C": cloud_c
        }
        self.provider_list = [cloud_a, cloud_b, cloud_c]

    def distribute_file(self, file_id: str, encrypted_data: bytes) -> list[dict]:
        """
        Fragments encrypted data into 3 pieces and distributes them across Cloud A, B, and C.
        Records fragment locations in SQLite.
        """
        fragments = fragment_data(encrypted_data, num_fragments=len(self.provider_list))
        stored_records = []

        conn = get_db_connection()
        cursor = conn.cursor()

        for frag in fragments:
            idx = frag["index"]
            provider = self.provider_list[idx % len(self.provider_list)]
            filename = f"{file_id}_part_{idx}.frag"

            # Store on the respective simulated cloud provider
            dest_path = provider.store_fragment(filename, frag["data"])

            # Save metadata in file_fragments
            cursor.execute("""
                INSERT INTO file_fragments (file_id, fragment_index, cloud_provider, fragment_filename, fragment_path, fragment_hash, size_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (file_id, idx, provider.name, filename, str(dest_path), frag["sha3_hash"], frag["size"]))

            stored_records.append({
                "fragment_index": idx,
                "cloud_provider": provider.name,
                "fragment_filename": filename,
                "sha3_hash": frag["sha3_hash"],
                "size_bytes": frag["size"]
            })

        conn.commit()
        conn.close()

        log_security_event("SYSTEM", "FILE_UPLOADED", details=f"file_id={file_id} fragments={len(fragments)} clouds=CloudA/B/C")
        return stored_records

    def retrieve_and_reconstruct(self, file_id: str) -> bytes:
        """
        Fetches all fragments for a file from their respective cloud providers
        and reassembles the complete encrypted data stream.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT fragment_index, cloud_provider, fragment_filename, fragment_hash
            FROM file_fragments
            WHERE file_id = ?
            ORDER BY fragment_index ASC
        """, (file_id,))
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            raise FileNotFoundError(f"No fragments found in multi-cloud storage for file {file_id}.")

        retrieved_fragments = []
        for row in rows:
            idx = row["fragment_index"]
            provider_name = row["cloud_provider"]
            filename = row["fragment_filename"]

            provider = self.providers.get(provider_name)
            if not provider:
                raise ValueError(f"Unknown cloud provider: {provider_name}")

            # Fetch binary data from provider
            data = provider.retrieve_fragment(filename)
            retrieved_fragments.append({
                "index": idx,
                "data": data,
                "expected_hash": row["fragment_hash"]
            })

        # Reassemble the encrypted binary
        return reassemble_fragments(retrieved_fragments)

    def tamper_file_fragment(self, file_id: str, fragment_index: int = 0) -> bool:
        """
        Simulates malicious tampering by flipping bytes in a stored cloud fragment.
        Used for demonstrating SHA3-256 integrity verification failures.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cloud_provider, fragment_filename
            FROM file_fragments
            WHERE file_id = ? AND fragment_index = ?
        """, (file_id, fragment_index))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return False

        provider = self.providers.get(row["cloud_provider"])
        if provider:
            success = provider.tamper_fragment(row["fragment_filename"])
            if success:
                log_security_event("DEMO", "SIMULATED_TAMPER", details=f"file_id={file_id} fragment={fragment_index} cloud={row['cloud_provider']}")
            return success
        return False

    def get_cloud_health(self) -> list[dict]:
        """Returns operational status for each simulated cloud provider."""
        return [p.get_status() for p in self.provider_list]


# Global storage manager instance
cloud_manager = CloudManager()
