"""
SecureCloud-X: File Download and Integrity Verification Route
Implements Module 14 end-to-end download & decryption workflow:
  1. ML Behavior Check
  2. Multi-Cloud Fragment Retrieval (Cloud A, B, C)
  3. Reassembly of Encrypted Payload
  4. SHA3-256 Blockchain Integrity Verification
  5. Tamper Interception (Halt if mismatch detected)
  6. Post-Quantum ML-KEM Decapsulation & HKDF Session Key Recovery
  7. ChaCha20-Poly1305 Decryption
  8. Secure File Delivery & Audit Logging
"""

import io
import time
from datetime import datetime
from flask import Blueprint, request, redirect, url_for, session, flash, send_file, jsonify, render_template
from routes.auth_routes import login_required
from crypto.key_manager import get_or_create_system_kem_keypair, unwrap_session_key
from crypto.chacha_service import decrypt_data
from storage.cloud_manager import cloud_manager
from blockchain.integrity import verify_file_integrity
from database.database import get_db_connection, log_security_event
from ml.anomaly_detector import anomaly_detector
from ml.feature_engineering import create_feature_dict

download_bp = Blueprint("download", __name__)


@download_bp.route("/download/<file_id>", methods=["GET"])
@login_required
def download_file(file_id):
    """
    Executes the secure multi-cloud retrieval, blockchain integrity check,
    and post-quantum decapsulation/decryption pipeline.
    """
    username = session.get("username", "anonymous")

    # 1. Fetch File Metadata from Database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT file_id, original_filename, file_size, sha3_hash,
               kem_ciphertext, wrapped_session_key, wrap_nonce, chacha_nonce
        FROM files WHERE file_id = ?
    """, (file_id,))
    file_record = cursor.fetchone()
    conn.close()

    if not file_record:
        flash("Requested file not found in registry.", "danger")
        return redirect(url_for("dashboard.files_view"))

    # 2. ML Threat Assessment on Download Request
    download_vol_mb = session.get("download_volume_mb", 0.0) + (file_record["file_size"] / (1024 * 1024))
    download_cnt = session.get("download_count", 0) + 1

    features = create_feature_dict(
        failed_login_count=session.get("failed_logins", 0),
        files_accessed=session.get("files_accessed", 0) + 1,
        download_count=download_cnt,
        download_volume_mb=download_vol_mb,
        access_hour=datetime.now().hour,
        new_ip_flag=1 if session.get("ip_address") != "127.0.0.1" else 0,
        unusual_download_frequency=1 if download_cnt > 10 else 0
    )

    threat_eval = anomaly_detector.evaluate_behavior(features, username=username, action="FILE_DOWNLOAD")
    if threat_eval["decision"] == "BLOCK":
        log_security_event(username, "DOWNLOAD_BLOCKED", details=f"file_id={file_id} risk={threat_eval['risk_score']}")
        flash(f"Download blocked by AI threat detection engine. Suspicious download volume/frequency detected (Risk: {threat_eval['risk_score']}).", "danger")
        return redirect(url_for("dashboard.files_view"))

    try:
        # 3. Retrieve Fragments from Simulated Cloud Providers (Cloud A, B, C)
        reconstructed_ciphertext = cloud_manager.retrieve_and_reconstruct(file_id)

        # 4. SHA3-256 Blockchain Integrity Check
        integrity_result = verify_file_integrity(file_id, reconstructed_ciphertext, username=username)

        # 5. Check if Tampered
        if not integrity_result["is_valid"]:
            # Tampering Detected! Cease operation immediately.
            flash(f"SECURITY ALERT: Tampering detected for file '{file_record['original_filename']}'! "
                  f"SHA3-256 hash mismatch between cloud fragments and blockchain record. Decryption halted.", "danger")
            return redirect(url_for("dashboard.files_view"))

        # 6. Post-Quantum ML-KEM Decapsulation & HKDF Key Recovery
        _, kem_priv = get_or_create_system_kem_keypair()
        kem_ciphertext = bytes.fromhex(file_record["kem_ciphertext"])
        wrapped_session_key = bytes.fromhex(file_record["wrapped_session_key"])
        wrap_nonce = bytes.fromhex(file_record["wrap_nonce"])

        session_key = unwrap_session_key(kem_ciphertext, wrapped_session_key, wrap_nonce, kem_priv)

        # 7. ChaCha20-Poly1305 Decryption
        chacha_nonce = bytes.fromhex(file_record["chacha_nonce"])
        plaintext = decrypt_data(reconstructed_ciphertext, session_key, chacha_nonce)

        # Clear session key from memory
        del session_key

        # Update user session metrics
        session["download_count"] = download_cnt
        session["download_volume_mb"] = round(download_vol_mb, 2)
        session["files_accessed"] = session.get("files_accessed", 0) + 1

        log_security_event(username, "FILE_DOWNLOADED", details=f"file_id={file_id} size={len(plaintext)}B")
        log_security_event(username, "FILE_DECRYPTED", details=f"file_id={file_id} status=SUCCESS")

        # 8. Deliver Original File to Browser
        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=file_record["original_filename"],
            mimetype="application/octet-stream"
        )

    except Exception as e:
        log_security_event(username, "DOWNLOAD_ERROR", details=f"file_id={file_id} error={str(e)}")
        flash(f"Error processing file download: {str(e)}", "danger")
        return redirect(url_for("dashboard.files_view"))


@download_bp.route("/verify-integrity/<file_id>", methods=["GET"])
@login_required
def verify_integrity(file_id):
    """API endpoint to run a standalone integrity verification without downloading the file."""
    try:
        reconstructed = cloud_manager.retrieve_and_reconstruct(file_id)
        result = verify_file_integrity(file_id, reconstructed, username=session.get("username", "anonymous"))
        return jsonify(result)
    except Exception as e:
        return jsonify({"is_valid": False, "status": "ERROR", "message": str(e)}), 400
