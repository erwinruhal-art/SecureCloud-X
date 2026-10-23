"""
SecureCloud-X: Security Monitoring, Threat Simulation, and Tampering Lab
Provides interactive demonstration controls for:
  - Module 15: File Tampering & Blockchain Integrity Verification
  - Module 16: ML Anomaly Threat Simulation (Normal vs Suspicious Activity)
  - Blockchain Ledger Explorer & Full Chain Verification
  - Structured Security Audit Log Viewer
"""

from flask import Blueprint, render_template, request, jsonify, session
from routes.auth_routes import login_required
from database.database import get_db_connection, log_security_event
from blockchain.ledger import blockchain_ledger
from blockchain.integrity import verify_file_integrity
from storage.cloud_manager import cloud_manager
from ml.anomaly_detector import anomaly_detector
from ml.feature_engineering import create_feature_dict
from crypto.hash_service import compute_sha3_256

security_bp = Blueprint("security", __name__)


@security_bp.route("/security")
@login_required
def security_dashboard():
    """Security monitoring view with threat status and interactive test panels."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get recent ML threat predictions
    cursor.execute("""
        SELECT timestamp, username, action, risk_score, prediction, decision
        FROM ml_predictions
        ORDER BY id DESC
        LIMIT 10
    """)
    predictions = cursor.fetchall()

    # Get recent security events
    cursor.execute("""
        SELECT timestamp, username, event_type, ip_address, details
        FROM security_events
        ORDER BY id DESC
        LIMIT 15
    """)
    events = cursor.fetchall()
    conn.close()

    chain_ok, chain_msg = blockchain_ledger.verify_chain()

    return render_template(
        "security.html",
        predictions=predictions,
        events=events,
        chain_ok=chain_ok,
        chain_msg=chain_msg
    )


@security_bp.route("/blockchain")
@login_required
def blockchain_view():
    """Interactive Blockchain Ledger explorer showing all blocks and link hashes."""
    blocks = blockchain_ledger.get_all_blocks()
    chain_ok, chain_msg = blockchain_ledger.verify_chain()
    return render_template("blockchain.html", blocks=blocks, chain_ok=chain_ok, chain_msg=chain_msg)


@security_bp.route("/api/blockchain/verify-chain", methods=["GET"])
@login_required
def api_verify_chain():
    """Validates the entire cryptographic blockchain link structure."""
    is_valid, message = blockchain_ledger.verify_chain()
    return jsonify({"is_valid": is_valid, "message": message})


@security_bp.route("/logs")
@login_required
def logs_view():
    """Structured security event audit log viewer."""
    event_filter = request.args.get("type", "")
    username_filter = request.args.get("user", "")

    query = "SELECT id, timestamp, username, event_type, ip_address, user_agent, details FROM security_events"
    params = []
    conditions = []

    if event_filter:
        conditions.append("event_type LIKE ?")
        params.append(f"%{event_filter}%")
    if username_filter:
        conditions.append("username LIKE ?")
        params.append(f"%{username_filter}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC LIMIT 100"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    logs = cursor.fetchall()
    conn.close()

    return render_template("logs.html", logs=logs, selected_type=event_filter, selected_user=username_filter)


@security_bp.route("/api/security/simulate-ml", methods=["POST"])
@login_required
def simulate_ml():
    """
    Module 16: Simulates user behavioral activity to demonstrate ML threat detection.
    Supports 'normal' and 'suspicious' preset activity patterns.
    """
    data = request.get_json() or {}
    sim_type = data.get("type", "normal")

    if sim_type == "normal":
        # Normal user profile
        features = create_feature_dict(
            failed_login_count=0,
            files_accessed=3,
            download_count=1,
            download_volume_mb=4.5,
            session_duration_min=18.0,
            access_hour=14,
            new_ip_flag=0,
            new_device_flag=0,
            unusual_download_frequency=0
        )
        username = session.get("username", "student")
        result = anomaly_detector.evaluate_behavior(features, username=username, action="NORMAL_ACTIVITY_SIM")
    else:
        # Suspicious / anomalous user profile
        features = create_feature_dict(
            failed_login_count=8,
            files_accessed=120,
            download_count=45,
            download_volume_mb=2800.0,  # 2.8 GB
            session_duration_min=190.0,
            access_hour=3,  # 3 AM
            new_ip_flag=1,
            new_device_flag=1,
            unusual_download_frequency=1
        )
        username = session.get("username", "intruder_sim")
        result = anomaly_detector.evaluate_behavior(features, username=username, action="SUSPICIOUS_EXFIL_SIM")

    return jsonify({"success": True, "simulation_type": sim_type, "result": result})


@security_bp.route("/api/security/simulate-tamper", methods=["POST"])
@login_required
def simulate_tamper():
    """
    Module 15: Simulates unauthorized file tampering in cloud storage.
    Corrupts bytes in Cloud A's fragment for the specified file and runs
    the SHA3-256 verification against the immutable blockchain ledger.
    """
    data = request.get_json() or {}
    file_id = data.get("file_id")

    if not file_id:
        return jsonify({"success": False, "message": "file_id is required"}), 400

    # Retrieve blockchain record before tampering
    record = blockchain_ledger.get_file_record(file_id)
    if not record:
        return jsonify({"success": False, "message": f"File {file_id} not found in blockchain."}), 404

    expected_hash = record["file_hash"]

    # Step 1: Intentionally corrupt fragment in Cloud A
    corrupted = cloud_manager.tamper_file_fragment(file_id, fragment_index=0)
    if not corrupted:
        return jsonify({"success": False, "message": "Failed to tamper fragment in Cloud A."}), 500

    # Step 2: Retrieve all fragments and reassemble
    reconstructed = cloud_manager.retrieve_and_reconstruct(file_id)

    # Step 3: Recalculate SHA3-256
    calculated_hash = compute_sha3_256(reconstructed)

    # Step 4: Run integrity check
    integrity = verify_file_integrity(file_id, reconstructed, username=session.get("username", "demo"))

    return jsonify({
        "success": True,
        "file_id": file_id,
        "expected_hash": expected_hash,
        "calculated_hash": calculated_hash,
        "status": "TAMPERING DETECTED - BLOCKED" if not integrity["is_valid"] else "VERIFIED",
        "is_valid": integrity["is_valid"],
        "message": integrity["message"],
        "block_index": record["block_index"]
    })
