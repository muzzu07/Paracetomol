"""
Handles ingestion of a project submitted as a ZIP upload.

Extracts into an isolated, uniquely-named temp directory so concurrent
scans never collide, and guards against zip-slip path traversal.
"""

import uuid
import zipfile
from pathlib import Path

from app.config import Config


class ZipExtractionError(Exception):
    pass


def _is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """Prevent zip-slip: ensure extracted path stays inside base_dir."""
    try:
        target_path.resolve().relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False


def extract_zip(zip_file_path: str) -> Path:
    """
    Extract a ZIP archive into a fresh scan workspace.

    Args:
        zip_file_path: path to the uploaded .zip file on disk

    Returns:
        Path to the extracted project directory.
    """
    Config.ensure_dirs()
    scan_id = uuid.uuid4().hex[:12]
    dest_dir = Config.TEMP_DIR / f"scan_{scan_id}"
    dest_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_file_path, "r") as zf:
            for member in zf.infolist():
                extracted_path = dest_dir / member.filename
                if not _is_safe_path(dest_dir, extracted_path):
                    raise ZipExtractionError(
                        f"Unsafe path in archive blocked: {member.filename}"
                    )
            zf.extractall(dest_dir)
    except zipfile.BadZipFile as exc:
        raise ZipExtractionError(f"Invalid ZIP file: {exc}") from exc

    return dest_dir
