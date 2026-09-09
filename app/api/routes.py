"""
Flask API routes for the Security Scanner backend.

Endpoints:
  POST /api/scan/upload   - multipart ZIP upload -> runs full scan
  POST /api/scan/git      - {"repo_url": "...", "branch": "..."} -> runs full scan
  GET  /api/reports       - list past reports
  GET  /api/reports/<id>  - fetch one report by scan_id
  GET  /api/health        - liveness check
"""

import json
import uuid

from flask import Blueprint, jsonify, request

from app.config import Config
from app.ingestion.git_handler import GitCloneError, clone_repository
from app.ingestion.zip_handler import ZipExtractionError, extract_zip
from app.scanner.orchestrator import run_full_scan

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.get("/health")
def health():
    return jsonify({"status": "ok"})


@api_bp.post("/scan/upload")
def scan_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part named 'file' in request."}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "Empty filename."}), 400
    if not uploaded.filename.lower().endswith(".zip"):
        return jsonify({"error": "Only .zip files are supported."}), 400

    Config.ensure_dirs()
    save_path = Config.UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{uploaded.filename}"
    uploaded.save(save_path)

    use_ai = request.args.get("use_ai", "true").lower() != "false"

    try:
        target_dir = extract_zip(str(save_path))
    except ZipExtractionError as exc:
        return jsonify({"error": str(exc)}), 400
    finally:
        save_path.unlink(missing_ok=True)

    report = run_full_scan(target_dir, use_ai=use_ai)
    return jsonify(report), 200


@api_bp.post("/scan/git")
def scan_git():
    payload = request.get_json(silent=True) or {}
    repo_url = payload.get("repo_url")
    branch = payload.get("branch")
    use_ai = payload.get("use_ai", True)

    if not repo_url:
        return jsonify({"error": "'repo_url' is required."}), 400

    try:
        target_dir = clone_repository(repo_url, branch=branch)
    except GitCloneError as exc:
        return jsonify({"error": str(exc)}), 400

    report = run_full_scan(target_dir, use_ai=use_ai)
    return jsonify(report), 200


@api_bp.get("/reports")
def list_reports():
    Config.ensure_dirs()
    reports = []
    for path in sorted(Config.REPORT_DIR.glob("report_*.json"), reverse=True):
        try:
            data = json.loads(path.read_text())
            reports.append(
                {
                    "scan_id": data.get("scan_id"),
                    "total_findings": data.get("total_findings"),
                    "severity_counts": data.get("severity_counts"),
                }
            )
        except (json.JSONDecodeError, OSError):
            continue
    return jsonify(reports)


@api_bp.get("/reports/<scan_id>")
def get_report(scan_id):
    path = Config.REPORT_DIR / f"report_{scan_id}.json"
    if not path.exists():
        return jsonify({"error": "Report not found."}), 404
    return jsonify(json.loads(path.read_text()))
