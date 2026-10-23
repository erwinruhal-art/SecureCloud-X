"""
SecureCloud-X: Authentication and User Session Management
Implements PBKDF2-HMAC-SHA256 password verification, session tracking,
and security activity logging for ML feature collection.
"""

from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash
from datetime import datetime
from database.database import get_db_connection, log_security_event
from ml.anomaly_detector import anomaly_detector
from ml.feature_engineering import create_feature_dict

auth_bp = Blueprint("auth", __name__)


def login_required(f):
    """Decorator to enforce authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login with behavioral feature logging."""
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard_view"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_addr = request.remote_addr or "127.0.0.1"
        user_agent = request.headers.get("User-Agent", "Unknown")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            # Login successful
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["login_time"] = datetime.now().isoformat()
            session["ip_address"] = ip_addr
            session["failed_logins"] = 0
            session["download_count"] = 0
            session["download_volume_mb"] = 0.0
            session["files_accessed"] = 0

            log_security_event(username, "LOGIN_SUCCESS", ip_address=ip_addr, user_agent=user_agent, details="User authenticated successfully")
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard.dashboard_view"))
        else:
            # Login failure
            current_failed = session.get("failed_logins", 0) + 1
            session["failed_logins"] = current_failed

            log_security_event(username or "unknown", "LOGIN_FAILURE", ip_address=ip_addr, user_agent=user_agent, details=f"Invalid credentials. Attempt #{current_failed}")

            # If repeated failures, evaluate threat
            if current_failed >= 3:
                features = create_feature_dict(
                    failed_login_count=current_failed,
                    access_hour=datetime.now().hour,
                    new_ip_flag=1 if ip_addr != "127.0.0.1" else 0
                )
                threat = anomaly_detector.evaluate_behavior(features, username=username or "unknown", action="LOGIN_ATTEMPT")
                if threat["decision"] == "BLOCK":
                    flash("Access temporarily blocked due to suspicious login patterns.", "danger")
                    return render_template("login.html")

            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    """Clears user session and logs event."""
    username = session.get("username", "anonymous")
    log_security_event(username, "LOGOUT", details="User signed out")
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
