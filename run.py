"""
Entrypoint for running the Flask backend API.

Usage:
    python run.py
"""

from app.config import Config
from app.main import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host=Config.FLASK_HOST, port=Config.FLASK_PORT, debug=Config.FLASK_DEBUG)
