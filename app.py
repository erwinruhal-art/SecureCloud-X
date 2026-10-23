"""
SecureCloud-X: Enhanced Multi-Cloud Storage Security Framework
Using ML-KEM, Blockchain-Based Integrity Verification, and AI-Driven Threat Detection.

Academic B.Tech Engineering Project Entry Point.
Run command: python app.py
Access at: http://127.0.0.1:5000
"""

import os
from flask import Flask, render_template
from config import SECRET_KEY, MAX_CONTENT_LENGTH
from database.database import init_db
from crypto.mlkem_service import mlkem_service

# Import Blueprints
from routes.auth_routes import auth_bp
from routes.upload_routes import upload_bp
from routes.download_routes import download_bp
from routes.dashboard_routes import dashboard_bp
from routes.security_routes import security_bp


def create_app():
    """Application factory for SecureCloud-X."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    # Ensure database tables exist on startup
    init_db()

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(download_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(security_bp)

    # Global context processor to provide ML-KEM status across all templates
    @app.context_processor
    def inject_system_status():
        return {
            "kem_status": mlkem_service.get_status()
        }

    # Error handling to prevent unhandled stack trace leaks to users
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("base.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template("base.html"), 500

    return app


app = create_app()

if __name__ == "__main__":
    print("=" * 65)
    print("SecureCloud-X: Enhanced Multi-Cloud Storage Security Framework")
    print("Academic Final Year B.Tech Project Prototype")
    print("ML-KEM Mode:", mlkem_service.get_status()["status_text"])
    print("Local Server starting at: http://127.0.0.1:5000")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=True)
