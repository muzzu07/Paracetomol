"""
Flask application factory for the Security Scanner backend API.
"""

from flask import Flask

from app.api.routes import api_bp
from app.config import Config


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH
    Config.ensure_dirs()

    app.register_blueprint(api_bp)

    @app.get("/")
    def index():
        return {
            "service": "security-scanner-api",
            "status": "running",
            "endpoints": [
                "/api/health",
                "/api/scan/upload (POST, multipart 'file')",
                "/api/scan/git (POST, JSON {'repo_url': ...})",
                "/api/reports",
                "/api/reports/<scan_id>",
            ],
        }

    return app
