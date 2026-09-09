"""
Handles ingestion of a project from a public Git repository URL.
"""

import re
import uuid
from pathlib import Path

import git

from app.config import Config

_ALLOWED_URL_PATTERN = re.compile(
    r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[\w.\-]+/[\w.\-]+(\.git)?/?$"
)


class GitCloneError(Exception):
    pass


def clone_repository(repo_url: str, branch: str | None = None) -> Path:
    """
    Clone a public repository into an isolated scan workspace.

    Args:
        repo_url: HTTPS URL of a public repo (GitHub/GitLab/Bitbucket).
        branch: optional branch name to check out.

    Returns:
        Path to the cloned repository directory.
    """
    if not _ALLOWED_URL_PATTERN.match(repo_url.strip()):
        raise GitCloneError(
            "Only public https:// GitHub/GitLab/Bitbucket URLs are allowed."
        )

    Config.ensure_dirs()
    scan_id = uuid.uuid4().hex[:12]
    dest_dir = Config.TEMP_DIR / f"scan_{scan_id}"

    try:
        clone_kwargs = {"depth": 1}
        if branch:
            clone_kwargs["branch"] = branch
        git.Repo.clone_from(repo_url, dest_dir, **clone_kwargs)
    except git.GitCommandError as exc:
        raise GitCloneError(f"Failed to clone repository: {exc}") from exc

    return dest_dir
