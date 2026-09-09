"""
Coordinates a full scan: run Semgrep + Gitleaks, optionally enrich each
finding with DeepSeek analysis and generate patch files, then persist a
JSON report.
"""

import json
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from app.ai.deepseek_client import DeepSeekError, analyze_finding
from app.config import Config
from app.remediation.patch_generator import generate_patch
from app.scanner.gitleaks_runner import GitleaksError, run_gitleaks
from app.scanner.semgrep_runner import SemgrepError, run_semgrep


def run_full_scan(
    target_dir: Path, use_ai: bool = True, cleanup: bool = True
) -> dict[str, Any]:
    """
    Run the full scan pipeline against target_dir.

    Returns a report dict and writes it to Config.REPORT_DIR as JSON.
    """
    Config.ensure_dirs()
    started = time.time()
    errors: list[str] = []

    try:
        semgrep_findings = run_semgrep(target_dir)
    except SemgrepError as exc:
        semgrep_findings = []
        errors.append(str(exc))

    try:
        gitleaks_findings = run_gitleaks(target_dir)
    except GitleaksError as exc:
        gitleaks_findings = []
        errors.append(str(exc))

    all_findings = semgrep_findings + gitleaks_findings

    if use_ai:
        for finding in all_findings:
            try:
                analysis = analyze_finding(finding)
                finding["ai_analysis"] = analysis
                patch_path = generate_patch(target_dir, finding, analysis)
                finding["patch_file"] = str(patch_path) if patch_path else None
            except DeepSeekError as exc:
                finding["ai_analysis"] = None
                finding["ai_error"] = str(exc)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in all_findings:
        sev = (
            (f.get("ai_analysis") or {}).get("severity_assessment")
            or f.get("severity", "")
        ).lower()
        severity_counts[sev if sev in severity_counts else "unknown"] += 1

    report = {
        "scan_id": uuid.uuid4().hex[:12],
        "duration_seconds": round(time.time() - started, 2),
        "total_findings": len(all_findings),
        "semgrep_findings": len(semgrep_findings),
        "gitleaks_findings": len(gitleaks_findings),
        "severity_counts": severity_counts,
        "findings": all_findings,
        "errors": errors,
    }

    report_path = Config.REPORT_DIR / f"report_{report['scan_id']}.json"
    report_path.write_text(json.dumps(report, indent=2, default=str))
    report["report_path"] = str(report_path)

    if cleanup:
        shutil.rmtree(target_dir, ignore_errors=True)

    return report
