"""
SecureCloud-X: Dashboard and Administrative Views
Provides overview statistics, file registry, the Key Generation Lab,
and live performance evaluation benchmark suites.
"""

import os
import time
from flask import Blueprint, render_template, redirect, url_for, session, request, jsonify
from routes.auth_routes import login_required
from database.database import get_db_connection
from crypto.mlkem_service import mlkem_service
from crypto.askg import askg_instance
from crypto.chacha_service import encrypt_data, decrypt_data
from crypto.key_manager import get_or_create_system_kem_keypair, wrap_session_key, unwrap_session_key
from crypto.hash_service import compute_sha3_256, verify_sha3_integrity
from blockchain.ledger import blockchain_ledger
from storage.cloud_manager import cloud_manager
from ml.anomaly_detector import anomaly_detector
from ml.feature_engineering import create_feature_dict

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """Default landing route redirects to dashboard if authenticated, else login."""
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard_view"))
    return redirect(url_for("auth.login"))


@dashboard_bp.route("/dashboard")
@login_required
def dashboard_view():
    """Main system status overview dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Aggregate statistics
    cursor.execute("SELECT COUNT(*) as count FROM users")
    total_users = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM files")
    total_files = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM keys WHERE status = 'Active'")
    active_keys = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM file_fragments")
    total_fragments = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM ml_predictions WHERE prediction = 'ANOMALY'")
    detected_anomalies = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM security_events WHERE event_type LIKE '%TAMPER%' OR event_type LIKE '%MISMATCH%'")
    integrity_alerts = cursor.fetchone()["count"]

    # Recent files
    cursor.execute("""
        SELECT f.file_id, f.original_filename, f.file_size, f.upload_time, f.sha3_hash, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        ORDER BY f.upload_time DESC
        LIMIT 5
    """)
    recent_files = cursor.fetchall()

    # Recent security events
    cursor.execute("""
        SELECT timestamp, username, event_type, details
        FROM security_events
        ORDER BY id DESC
        LIMIT 6
    """)
    recent_events = cursor.fetchall()
    conn.close()

    # Blockchain status
    chain_valid, chain_msg = blockchain_ledger.verify_chain()

    return render_template(
        "dashboard.html",
        total_users=total_users,
        total_files=total_files,
        active_keys=active_keys,
        total_fragments=total_fragments,
        detected_anomalies=detected_anomalies,
        integrity_alerts=integrity_alerts,
        recent_files=recent_files,
        recent_events=recent_events,
        chain_valid=chain_valid,
        chain_msg=chain_msg,
        kem_status=mlkem_service.get_status(),
        cloud_health=cloud_manager.get_cloud_health()
    )


@dashboard_bp.route("/files")
@login_required
def files_view():
    """File inventory view with integrity status and cloud distribution details."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.file_id, f.original_filename, f.file_size, f.upload_time, f.sha3_hash,
               f.key_id, f.kem_param, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        ORDER BY f.upload_time DESC
    """)
    files = cursor.fetchall()
    conn.close()

    return render_template("files.html", files=files, kem_status=mlkem_service.get_status())


@dashboard_bp.route("/keygen-lab")
@login_required
def keygen_lab_view():
    """Module 17: Key Generation Lab and ASKG Management."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT key_id, algorithm, key_size, generated_at, status, reseed_counter
        FROM keys
        ORDER BY generated_at DESC
        LIMIT 20
    """)
    key_history = cursor.fetchall()
    conn.close()

    stats = askg_instance.get_key_stats()
    return render_template("keygen.html", stats=stats, key_history=key_history)


@dashboard_bp.route("/api/keygen/generate", methods=["POST"])
@login_required
def api_keygen_generate():
    """Generates a fresh session key via ASKG."""
    key_id, _, metadata = askg_instance.generate_session_key()
    return jsonify({"success": True, "metadata": metadata})


@dashboard_bp.route("/api/keygen/reseed", methods=["POST"])
@login_required
def api_keygen_reseed():
    """Forces an explicit reseed of the HMAC-DRBG generator."""
    askg_instance.reseed(force=True)
    stats = askg_instance.get_key_stats()
    return jsonify({"success": True, "message": "HMAC-DRBG reseeded with fresh OS entropy.", "stats": stats})


@dashboard_bp.route("/api/keygen/rotate", methods=["POST"])
@login_required
def api_keygen_rotate():
    """Forces key rotation and generates a replacement session key."""
    key_id, _, metadata = askg_instance.rotate_key()
    return jsonify({"success": True, "metadata": metadata})


@dashboard_bp.route("/performance")
@login_required
def performance_view():
    """Module 18 & 19: Performance Evaluation and Cryptographic Comparison Page."""
    return render_template("performance.html")


@dashboard_bp.route("/api/performance/run-benchmark", methods=["POST"])
@login_required
def run_benchmark():
    """
    Executes actual live performance measurements on the running machine
    across multiple payload sizes (10KB, 100KB, 1MB, 5MB, 10MB).
    No fabricated numbers — all timings are measured using high-precision timers.
    """
    payload_sizes = [
        {"label": "10 KB", "size": 10 * 1024},
        {"label": "100 KB", "size": 100 * 1024},
        {"label": "1 MB", "size": 1 * 1024 * 1024},
        {"label": "5 MB", "size": 5 * 1024 * 1024},
        {"label": "10 MB", "size": 10 * 1024 * 1024},
    ]

    benchmark_results = []
    pub_key, priv_key = get_or_create_system_kem_keypair()

    for item in payload_sizes:
        data_size = item["size"]
        dummy_data = os.urandom(data_size)

        # 1. ASKG Key Generation
        t0 = time.perf_counter()
        _, session_key, _ = askg_instance.generate_session_key()
        keygen_ms = (time.perf_counter() - t0) * 1000

        # 2. ChaCha20-Poly1305 Encryption
        t0 = time.perf_counter()
        ciphertext, nonce = encrypt_data(dummy_data, session_key)
        enc_ms = (time.perf_counter() - t0) * 1000

        # 3. Post-Quantum ML-KEM Encapsulation + HKDF
        t0 = time.perf_counter()
        c_kem, w_key, w_nonce = wrap_session_key(session_key, pub_key)
        kem_enc_ms = (time.perf_counter() - t0) * 1000

        # 4. SHA3-256 Hashing
        t0 = time.perf_counter()
        data_hash = compute_sha3_256(ciphertext)
        hash_ms = (time.perf_counter() - t0) * 1000

        # 5. Blockchain Block Validation
        t0 = time.perf_counter()
        chain_ok, _ = blockchain_ledger.verify_chain()
        bc_verify_ms = (time.perf_counter() - t0) * 1000

        # 6. Post-Quantum ML-KEM Decapsulation
        t0 = time.perf_counter()
        rec_key = unwrap_session_key(c_kem, w_key, w_nonce, priv_key)
        kem_dec_ms = (time.perf_counter() - t0) * 1000

        # 7. ChaCha20-Poly1305 Decryption
        t0 = time.perf_counter()
        decrypted = decrypt_data(ciphertext, rec_key, nonce)
        dec_ms = (time.perf_counter() - t0) * 1000

        # 8. ML Threat Prediction
        t0 = time.perf_counter()
        feat = create_feature_dict(download_volume_mb=data_size / (1024 * 1024))
        anomaly_detector.evaluate_behavior(feat, username="benchmark", action="BENCHMARK")
        ml_ms = (time.perf_counter() - t0) * 1000

        # Throughput in MB/s for encryption
        throughput_mb_s = round((data_size / (1024 * 1024)) / (enc_ms / 1000.0), 2) if enc_ms > 0 else 0

        benchmark_results.append({
            "size_label": item["label"],
            "size_bytes": data_size,
            "keygen_ms": round(keygen_ms, 3),
            "enc_ms": round(enc_ms, 3),
            "kem_enc_ms": round(kem_enc_ms, 3),
            "hash_ms": round(hash_ms, 3),
            "bc_verify_ms": round(bc_verify_ms, 3),
            "kem_dec_ms": round(kem_dec_ms, 3),
            "dec_ms": round(dec_ms, 3),
            "ml_ms": round(ml_ms, 3),
            "throughput_mb_s": throughput_mb_s
        })

    # Module 19: RNG Mechanism Comparison
    # Measure 50 iterations each
    iters = 50
    # A. OS CSPRNG
    t0 = time.perf_counter()
    for _ in range(iters):
        _ = os.urandom(32)
    os_urandom_avg_ms = round(((time.perf_counter() - t0) / iters) * 1000, 4)

    # B. Pure HMAC-DRBG
    from crypto.hmac_drbg import HMAC_DRBG
    drbg_test = HMAC_DRBG()
    t0 = time.perf_counter()
    for _ in range(iters):
        _ = drbg_test.generate(32)
    hmac_drbg_avg_ms = round(((time.perf_counter() - t0) / iters) * 1000, 4)

    # C. Proposed ASKG Wrapper
    t0 = time.perf_counter()
    for _ in range(iters):
        _ = askg_instance.generate_session_key()
    askg_avg_ms = round(((time.perf_counter() - t0) / iters) * 1000, 4)

    comparison_results = [
        {
            "mechanism": "OS CSPRNG (os.urandom)",
            "avg_time_ms": os_urandom_avg_ms,
            "reseed_support": "Kernel Managed",
            "key_size": "256-bit",
            "security_type": "Direct OS Entropy Trap"
        },
        {
            "mechanism": "Standard HMAC-DRBG",
            "avg_time_ms": hmac_drbg_avg_ms,
            "reseed_support": "Manual Reseed",
            "key_size": "256-bit",
            "security_type": "NIST SP 800-90A Pseudorandom Generator"
        },
        {
            "mechanism": "Proposed ASKG Wrapper",
            "avg_time_ms": askg_avg_ms,
            "reseed_support": "Periodic Auto + Monitored Rotation",
            "key_size": "256-bit",
            "security_type": "HMAC-DRBG + Entropy Mixing + Lifecycle"
        }
    ]

    return jsonify({
        "success": True,
        "benchmarks": benchmark_results,
        "rng_comparison": comparison_results
    })
