"""
Wraps the Semgrep CLI to run SAST scans and return normalized findings.

Requires Semgrep to be installed and available on PATH:
    pip install semgrep
"""

import json
import subprocess
from pathlib import Path
from typing import Any

from app.config import Config


class SemgrepError(Exception):
    pass


def run_semgrep(target_dir: Path, config: str | None = None) -> list[dict[str, Any]]:
    """
    Run Semgrep against target_dir and return a normalized list of findings.

    Each finding dict has: rule_id, message, severity, path, start_line,
    end_line, code_snippet.
    """
    config = config or Config.SEMGREP_CONFIG
    cmd = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--quiet",
        "--timeout",
        str(Config.SCAN_TIMEOUT_SECONDS),
        str(target_dir),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT_SECONDS + 30,
        )
    except FileNotFoundError as exc:
        raise SemgrepError(
            "Semgrep is not installed or not on PATH. Run: pip install semgrep"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise SemgrepError("Semgrep scan timed out.") from exc

    if result.returncode not in (0, 1):  # 1 = findings present, still valid
        raise SemgrepError(f"Semgrep failed: {result.stderr.strip()}")

    try:
        raw = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SemgrepError(f"Could not parse Semgrep output: {exc}") from exc

    findings = []
    for item in raw.get("results", []):
        findings.append(
            {
                "tool": "semgrep",
                "rule_id": item.get("check_id"),
                "message": item.get("extra", {}).get("message", ""),
                "severity": item.get("extra", {}).get("severity", "INFO"),
                "path": item.get("path"),
                "start_line": item.get("start", {}).get("line"),
                "end_line": item.get("end", {}).get("line"),
                "code_snippet": item.get("extra", {}).get("lines", ""),
            }
        )
    return findings
