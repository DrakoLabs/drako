"""Git diff integration for `drako scan --diff`.

Filters scan findings to only include files changed since a given git ref.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.policies.base import Finding


def get_changed_files(directory: str, ref: str) -> set[str] | None:
    """Run ``git diff --name-only`` and return changed ``.py`` file paths.

    Returns ``None`` if git is not available or the command fails,
    so the caller can fall back to a full scan.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", ref, "--diff-filter=ACMR", "--", "*.py"],
            capture_output=True,
            text=True,
            cwd=directory,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        files: set[str] = set()
        for line in result.stdout.strip().splitlines():
            # Normalize to forward-slash relative paths
            files.add(line.strip().replace("\\", "/"))
        return files
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def filter_findings_by_files(
    findings: list[Finding],
    changed_files: set[str],
) -> list[Finding]:
    """Keep only findings whose ``file_path`` is in *changed_files*.

    Findings without a ``file_path`` (project-level findings) are always kept.
    """
    filtered: list[Finding] = []
    for f in findings:
        if f.file_path is None:
            # Project-level finding — always include
            filtered.append(f)
        elif f.file_path.replace("\\", "/") in changed_files:
            filtered.append(f)
    return filtered
