"""
SecureCloud-X: File Fragmentation and Reassembly Service
Splits encrypted ciphertext payloads into N discrete fragments for
multi-cloud distribution, and reassembles them upon retrieval.
"""

import math
from crypto.hash_service import compute_sha3_256


def fragment_data(data: bytes, num_fragments: int = 3) -> list[dict]:
    """
    Divides raw binary data into ordered fragments.
    
    Args:
        data: Encrypted binary payload.
        num_fragments: Number of chunks (defaults to 3 for Cloud A, B, C).
        
    Returns:
        List of dicts containing fragment index, byte payload, size, and SHA3-256 hash.
    """
    total_len = len(data)
    if total_len == 0:
        return []

    chunk_size = math.ceil(total_len / num_fragments)
    fragments = []

    for i in range(num_fragments):
        start = i * chunk_size
        end = min(start + chunk_size, total_len)
        chunk = data[start:end]

        fragments.append({
            "index": i,
            "data": chunk,
            "size": len(chunk),
            "sha3_hash": compute_sha3_256(chunk)
        })

        if end >= total_len:
            break

    return fragments


def reassemble_fragments(fragments: list[dict]) -> bytes:
    """
    Reassembles ordered fragment chunks back into the complete binary payload.
    
    Args:
        fragments: List of dicts with 'index' and 'data'.
        
    Returns:
        Reconstructed binary payload.
    """
    # Sort fragments by index to guarantee correct reassembly order
    sorted_frags = sorted(fragments, key=lambda f: f["index"])
    reassembled = bytearray()
    for f in sorted_frags:
        reassembled.extend(f["data"])
    return bytes(reassembled)
