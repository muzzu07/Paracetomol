"""
Generates unified-diff .patch files from a finding + AI-suggested fix,
so users can review and apply remediations with `git apply`.
"""

import difflib
import uuid
from pathlib import Path
from typing import Any

from app.config import Config


def generate_patch(
    project_root: Path, finding: dict[str, Any], analysis: dict[str, Any]
) -> Path | None:
    """
    Create a .patch file for one finding, if a fixed_code snippet was
    provided by the AI analysis step.

    Returns the path to the patch file, or None if no fix was available.
    """
    fixed_code = (analysis or {}).get("fixed_code", "").strip()
    if not fixed_code:
        return None

    rel_path = finding.get("path")
    if not rel_path:
        return None

    file_path = project_root / rel_path
    if not file_path.exists():
        return None

    original_lines = file_path.read_text(errors="ignore").splitlines(keepends=True)

    start = (finding.get("start_line") or 1) - 1
    end = finding.get("end_line") or (start + 1)
    start = max(start, 0)
    end = min(end, len(original_lines))

    new_lines = (
        original_lines[:start]
        + [line + "\n" for line in fixed_code.splitlines()]
        + original_lines[end:]
    )

    diff = difflib.unified_diff(
        original_lines,
        new_lines,
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
    )
    diff_text = "".join(diff)
    if not diff_text:
        return None

    Config.ensure_dirs()
    patch_name = f"{Path(rel_path).stem}_{uuid.uuid4().hex[:8]}.patch"
    patch_path = Config.PATCH_DIR / patch_name
    patch_path.write_text(diff_text)
    return patch_path
