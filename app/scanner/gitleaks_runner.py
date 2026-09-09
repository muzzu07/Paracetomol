"""
Wraps the Gitleaks CLI to detect hardcoded secrets and return normalized
findings.

Requires Gitleaks to be installed and available on PATH:
    https://github.com/gitleaks/gitleaks#installing
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from app.config import Config


class GitleaksError(Exception):
    pass


def run_gitleaks(target_dir: Path) -> list[dict[str, Any]]:
    """
    Run Gitleaks against target_dir (filesystem mode, not just git history)
    and return a normalized list of findings.

    Each finding dict has: rule_id, description, path, start_line,
    secret_masked, match.
    """
    with tempfile.NamedTemporaryFile(
        suffix=".json", delete=False, dir=Config.TEMP_DIR
    ) as tmp:
        report_path = Path(tmp.name)

    cmd = [
        "gitleaks",
        "detect",
        "--source",
        str(target_dir),
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--exit-code",
        "0",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise GitleaksError(
            "Gitleaks is not installed or not on PATH."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise GitleaksError("Gitleaks scan timed out.") from exc

    if result.returncode not in (0,):
        raise GitleaksError(f"Gitleaks failed: {result.stderr.strip()}")

    findings = []
    if report_path.exists() and report_path.stat().st_size > 0:
        try:
            raw = json.loads(report_path.read_text())
        except json.JSONDecodeError as exc:
            raise GitleaksError(f"Could not parse Gitleaks output: {exc}") from exc

        for item in raw or []:
            secret = item.get("Secret", "")
            masked = secret[:4] + "*" * max(len(secret) - 4, 0)
            findings.append(
                {
                    "tool": "gitleaks",
                    "rule_id": item.get("RuleID"),
                    "description": item.get("Description"),
                    "path": item.get("File"),
                    "start_line": item.get("StartLine"),
                    "end_line": item.get("EndLine"),
                    "secret_masked": masked,
                    "match": item.get("Match"),
                }
            )
        report_path.unlink(missing_ok=True)

    return findings
