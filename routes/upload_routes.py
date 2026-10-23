"""
SecureCloud-X: File Upload and Cryptographic Pipeline Route
Implements Module 13 end-to-end security workflow:
  1. ML Behavior Check
  2. ASKG Session Key Generation (HMAC-DRBG SHA-256)
  3. ChaCha20-Poly1305 Payload Encryption
  4. Post-Quantum ML-KEM Encapsulation + HKDF Key Wrapping
  5. SHA3-256 File Hashing
  6. Blockchain Ledger Block Creation
  7. Multi-Cloud Fragmentation & Storage (Cloud A, B, C)
  8. Metadata Persistence & Audit Logging
"""

import time
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from routes.auth_routes import login_required
from crypto.askg import askg_instance
from crypto.chacha_service import encrypt_data
from crypto.key_manager import get_or_create_system_kem_keypair, wrap_session_key
from crypto.hash_service import compute_sha3_256
from crypto.mlkem_service import mlkem_service
from storage.cloud_manager import cloud_manager
from blockchain.ledger import blockchain_ledger
from database.database import get_db_connection, log_security_event
from ml.anomaly_detector import anomaly_detector
from ml.feature_engineering import create_feature_dict
from config import MLKEM_PARAM_SET

upload_bp = Blueprint("upload", __name__)


@upload_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    """Renders upload interface and processes uploaded files through the cryptographic pipeline."""
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("Please select a file to upload.", "warning")
            return redirect(url_for("upload.upload_file"))

        file_bytes = file.read()
        file_size = len(file_bytes)
        original_filename = file.filename

        username = session.get("username", "anonymous")
        user_id = session.get("user_id", 1)

        # -------------------------------------------------------------
        # STAGE 1: ML User Behavior Risk Evaluation
        # -------------------------------------------------------------
        start_ml = time.perf_counter()
        session_duration = 10.0
        if "login_time" in session:
            try:
                login_dt = datetime.fromisoformat(session["login_time"])
                session_duration = max(1.0, (datetime.now() - login_dt).total_seconds() / 60.0)
            except Exception:
                session_duration = 10.0

        features = create_feature_dict(
            failed_login_count=session.get("failed_logins", 0),
            files_accessed=session.get("files_accessed", 0) + 1,
            download_count=session.get("download_count", 0),
            download_volume_mb=session.get("download_volume_mb", 0.0),
            session_duration_min=session_duration,
            access_hour=datetime.now().hour,
            new_ip_flag=1 if session.get("ip_address") != "127.0.0.1" else 0
        )

        threat_eval = anomaly_detector.evaluate_behavior(features, username=username, action="FILE_UPLOAD")
        ml_time_ms = (time.perf_counter() - start_ml) * 1000

        if threat_eval["decision"] == "BLOCK":
            flash(f"Upload blocked by AI threat detection engine (Risk: {threat_eval['risk_score']}).", "danger")
            return redirect(url_for("upload.upload_file"))

        # -------------------------------------------------------------
        # STAGE 2: Secure Session Key Generation (ASKG / HMAC-DRBG)
        # -------------------------------------------------------------
        start_key = time.perf_counter()
        key_id, session_key, key_metadata = askg_instance.generate_session_key()
        keygen_time_ms = (time.perf_counter() - start_key) * 1000

        # -------------------------------------------------------------
        # STAGE 3: ChaCha20-Poly1305 Payload Encryption
        # -------------------------------------------------------------
        start_enc = time.perf_counter()
        ciphertext, chacha_nonce = encrypt_data(file_bytes, session_key)
        enc_time_ms = (time.perf_counter() - start_enc) * 1000
        log_security_event(username, "FILE_ENCRYPTED", details=f"file={original_filename} size={file_size}B chacha20-poly1305")

        # -------------------------------------------------------------
        # STAGE 4: Post-Quantum ML-KEM Key Encapsulation & HKDF Wrapping
        # -------------------------------------------------------------
        start_kem = time.perf_counter()
        kem_pub, _ = get_or_create_system_kem_keypair()
        kem_ciphertext, wrapped_session_key, wrap_nonce = wrap_session_key(session_key, kem_pub)
        kem_time_ms = (time.perf_counter() - start_kem) * 1000

        # Plaintext session_key is immediately cleared from local scope
        del session_key

        # -------------------------------------------------------------
        # STAGE 5: SHA3-256 File Hash Generation
        # -------------------------------------------------------------
        start_hash = time.perf_counter()
        sha3_hash = compute_sha3_256(ciphertext)
        hash_time_ms = (time.perf_counter() - start_hash) * 1000
        file_id = f"FILE-{uuid.uuid4().hex[:8].upper()}"
        log_security_event(username, "HASH_CREATED", details=f"file_id={file_id} sha3={sha3_hash[:16]}...")

        # -------------------------------------------------------------
        # STAGE 6: Blockchain-Style Ledger Recording
        # -------------------------------------------------------------
        start_bc = time.perf_counter()
        block = blockchain_ledger.add_block(file_id=file_id, file_hash=sha3_hash, transaction_info="FILE_UPLOAD")
        blockchain_time_ms = (time.perf_counter() - start_bc) * 1000

        # -------------------------------------------------------------
        # STAGE 7: Multi-Cloud Fragmentation & Distribution
        # -------------------------------------------------------------
        start_frag = time.perf_counter()
        fragments = cloud_manager.distribute_file(file_id=file_id, encrypted_data=ciphertext)
        frag_time_ms = (time.perf_counter() - start_frag) * 1000

        # -------------------------------------------------------------
        # STAGE 8: Save Metadata in Database (No Plaintext Keys)
        # -------------------------------------------------------------
        encrypted_filename = f"{file_id}_{original_filename}.enc"
        upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO files (
                file_id, original_filename, encrypted_filename, file_size, sha3_hash,
                kem_ciphertext, wrapped_session_key, wrap_nonce, chacha_nonce,
                key_id, kem_param, upload_time, user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            file_id, original_filename, encrypted_filename, file_size, sha3_hash,
            kem_ciphertext.hex(), wrapped_session_key.hex(), wrap_nonce.hex(), chacha_nonce.hex(),
            key_id, MLKEM_PARAM_SET, upload_time, user_id
        ))
        conn.commit()
        conn.close()

        # Update session tracking
        session["files_accessed"] = session.get("files_accessed", 0) + 1

        # Summary results for academic viva demonstration
        result_details = {
            "file_id": file_id,
            "original_filename": original_filename,
            "file_size": file_size,
            "key_id": key_id,
            "sha3_hash": sha3_hash,
            "block_index": block.index,
            "block_hash": block.current_hash,
            "fragments": fragments,
            "metrics": {
                "ml_time_ms": round(ml_time_ms, 2),
                "keygen_time_ms": round(keygen_time_ms, 2),
                "enc_time_ms": round(enc_time_ms, 2),
                "kem_time_ms": round(kem_time_ms, 2),
                "hash_time_ms": round(hash_time_ms, 2),
                "blockchain_time_ms": round(blockchain_time_ms, 2),
                "frag_time_ms": round(frag_time_ms, 2),
                "total_time_ms": round(ml_time_ms + keygen_time_ms + enc_time_ms + kem_time_ms + hash_time_ms + blockchain_time_ms + frag_time_ms, 2)
            },
            "threat_eval": threat_eval,
            "kem_status": mlkem_service.get_status()
        }

        flash(f"File '{original_filename}' successfully processed and distributed across Cloud A/B/C.", "success")
        return render_template("upload.html", result=result_details, kem_status=mlkem_service.get_status())

    return render_template("upload.html", result=None, kem_status=mlkem_service.get_status())
