"""
Central configuration for the Security Scanner.

All secrets/config are pulled from environment variables (loaded from .env
via python-dotenv in run.py). Never hardcode secrets here.
"""

import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    # --- Paths ---
    BASE_DIR = BASE_DIR
    UPLOAD_DIR = BASE_DIR / "uploads"
    TEMP_DIR = Path(os.getenv("TEMP_DIR", str(Path(tempfile.gettempdir()) / "paracetomol_temp")))
    PATCH_DIR = BASE_DIR / "patches"
    REPORT_DIR = BASE_DIR / "reports"

    # --- Flask ---
    FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
    FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_MB", "50")) * 1024 * 1024

    # --- DeepSeek API ---
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_API_URL = os.getenv(
        "DEEPSEEK_API_URL", "https://api.deepseek.com/chat/completions"
    )
    DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    # --- Scanners ---
    SEMGREP_CONFIG = os.getenv("SEMGREP_CONFIG", "p/owasp-top-ten")
    SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))

    @classmethod
    def ensure_dirs(cls):
        for d in (cls.UPLOAD_DIR, cls.TEMP_DIR, cls.PATCH_DIR, cls.REPORT_DIR):
            d.mkdir(parents=True, exist_ok=True)
