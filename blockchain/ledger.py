"""
SecureCloud-X: Blockchain-Style Integrity Ledger
Maintains an immutable cryptographic ledger of all file upload, update,
and verification transactions backed by SQLite.
"""

from blockchain.block import Block
from database.database import get_db_connection, log_security_event


class BlockchainLedger:
    """Manages the append-only block chain and validates link integrity."""

    def __init__(self):
        self.ensure_genesis_block()

    def ensure_genesis_block(self):
        """Creates the Genesis Block (Index 0) if the blockchain is empty."""
        from database.database import init_db
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM blockchain_blocks")
        count = cursor.fetchone()["count"]

        if count == 0:
            genesis = Block(
                index=0,
                file_id="GENESIS",
                file_hash="0" * 64,
                previous_hash="0" * 64,
                transaction_info="GENESIS_BLOCK",
                timestamp="2026-01-01 00:00:00",
                nonce_proof=0
            )
            cursor.execute("""
                INSERT INTO blockchain_blocks (block_index, timestamp, file_id, file_hash, previous_hash, current_hash, nonce_proof, transaction_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (genesis.index, genesis.timestamp, genesis.file_id, genesis.file_hash,
                  genesis.previous_hash, genesis.current_hash, genesis.nonce_proof, genesis.transaction_info))
            conn.commit()
            log_security_event("SYSTEM", "BLOCKCHAIN_GENESIS_CREATED", details="Genesis block initialized")

        conn.close()

    def get_last_block(self) -> Block:
        """Retrieves the latest block in the chain."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT block_index, timestamp, file_id, file_hash, previous_hash, current_hash, nonce_proof, transaction_info
            FROM blockchain_blocks
            ORDER BY block_index DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return Block(
            index=row["block_index"],
            timestamp=row["timestamp"],
            file_id=row["file_id"],
            file_hash=row["file_hash"],
            previous_hash=row["previous_hash"],
            current_hash=row["current_hash"],
            nonce_proof=row["nonce_proof"],
            transaction_info=row["transaction_info"]
        )

    def add_block(self, file_id: str, file_hash: str, transaction_info: str = "FILE_UPLOAD") -> Block:
        """Appends a new integrity record block to the ledger."""
        last_block = self.get_last_block()
        new_index = (last_block.index + 1) if last_block else 0
        prev_hash = last_block.current_hash if last_block else ("0" * 64)

        new_block = Block(
            index=new_index,
            file_id=file_id,
            file_hash=file_hash,
            previous_hash=prev_hash,
            transaction_info=transaction_info
        )

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO blockchain_blocks (block_index, timestamp, file_id, file_hash, previous_hash, current_hash, nonce_proof, transaction_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (new_block.index, new_block.timestamp, new_block.file_id, new_block.file_hash,
              new_block.previous_hash, new_block.current_hash, new_block.nonce_proof, new_block.transaction_info))
        conn.commit()
        conn.close()

        log_security_event("SYSTEM", "BLOCKCHAIN_UPDATED", details=f"block_index={new_block.index} file_id={file_id} hash={file_hash[:16]}...")
        return new_block

    def get_all_blocks(self) -> list[dict]:
        """Returns all blocks formatted for UI presentation."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT block_index, timestamp, file_id, file_hash, previous_hash, current_hash, nonce_proof, transaction_info
            FROM blockchain_blocks
            ORDER BY block_index ASC
        """)
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def verify_chain(self) -> tuple[bool, str]:
        """
        Validates the entire blockchain:
          1. Verifies that each block's current_hash matches its computed header hash.
          2. Verifies that each block's previous_hash matches the previous block's current_hash.
        """
        blocks = self.get_all_blocks()
        if not blocks:
            return True, "Blockchain is empty."

        for i in range(len(blocks)):
            current = blocks[i]
            # Reconstruct Block object to verify hash calculation
            b = Block(
                index=current["block_index"],
                timestamp=current["timestamp"],
                file_id=current["file_id"],
                file_hash=current["file_hash"],
                previous_hash=current["previous_hash"],
                transaction_info=current["transaction_info"],
                nonce_proof=current["nonce_proof"]
            )
            if b.calculate_hash() != current["current_hash"]:
                return False, f"Tamper detected! Block #{current['block_index']} header hash mismatch."

            if i > 0:
                previous = blocks[i - 1]
                if current["previous_hash"] != previous["current_hash"]:
                    return False, f"Tamper detected! Block #{current['block_index']} broken link with Block #{previous['block_index']}."

        return True, "Blockchain ledger integrity verified: all blocks and links valid."

    def get_file_record(self, file_id: str) -> dict:
        """Retrieves the latest blockchain integrity block for a given file_id."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT block_index, timestamp, file_id, file_hash, previous_hash, current_hash
            FROM blockchain_blocks
            WHERE file_id = ?
            ORDER BY block_index DESC
            LIMIT 1
        """, (file_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None


# Global ledger instance
blockchain_ledger = BlockchainLedger()
