"""Scan result caching for `drako init` to consume.

Saves the last scan result to `.drako/.last_scan.json` so that
`drako init` can pre-populate the YAML config with real project data
without requiring the user to run scan and init in the same process.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.scanner import ScanResult

_CACHE_DIR = ".drako"
_CACHE_FILE = ".last_scan.json"


def save_scan_cache(result: ScanResult, directory: str = ".") -> Path:
    """Serialize a ScanResult to `.drako/.last_scan.json`.

    Creates the `.drako/` directory if it doesn't exist.
    Returns the path to the cache file.
    """
    cache_dir = Path(directory) / _CACHE_DIR
    cache_dir.mkdir(exist_ok=True)

    primary_fw = result.bom.frameworks[0] if result.bom.frameworks else None

    data = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "project_name": result.metadata.root.name,
        "framework": primary_fw.name if primary_fw else None,
        "framework_version": primary_fw.version if primary_fw else None,
        "score": result.score,
        "grade": result.grade,
        "agents": [
            {
                "name": a.name,
                "file_path": a.file_path,
                "line_number": a.line_number,
                "framework": a.framework,
                "tools": a.tools,
                "model": a.model,
            }
            for a in result.bom.agents
        ],
        "tools": [
            {
                "name": t.name,
                "file_path": t.file_path,
                "has_filesystem_access": t.has_filesystem_access,
                "has_network_access": t.has_network_access,
                "has_code_execution": t.has_code_execution,
            }
            for t in result.bom.tools
        ],
        "models": [
            {"name": m.name, "file_path": m.file_path}
            for m in result.bom.models
        ],
        "mcp_servers": result.bom.mcp_servers,
        "findings_summary": {
            "critical": sum(1 for f in result.findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in result.findings if f.severity == "HIGH"),
            "medium": sum(1 for f in result.findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in result.findings if f.severity == "LOW"),
            "total": len(result.findings),
        },
    }

    cache_path = cache_dir / _CACHE_FILE
    cache_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return cache_path


def load_scan_cache(
    directory: str = ".",
    max_age_seconds: int = 3600,
) -> dict | None:
    """Load cached scan results, or return None if missing/stale/corrupt.

    Args:
        directory: Project root directory.
        max_age_seconds: Maximum age in seconds before the cache is
            considered stale (default: 1 hour).
    """
    cache_path = Path(directory) / _CACHE_DIR / _CACHE_FILE
    if not cache_path.exists():
        return None

    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    # Check staleness
    scanned_at = data.get("scanned_at")
    if scanned_at:
        try:
            scan_time = datetime.fromisoformat(scanned_at)
            age = (datetime.now(timezone.utc) - scan_time).total_seconds()
            if age > max_age_seconds:
                return None
        except (ValueError, TypeError):
            pass  # If we can't parse the timestamp, use the cache anyway

    return data


def ensure_gitignore_cache(directory: str = ".") -> None:
    """Add `.drako/` to `.gitignore` if not already present.

    This ensures the scan cache (which contains local paths) is not
    committed to version control. The `.drako.yaml` config file
    itself should be committed — only the cache dir is ignored.
    """
    gitignore = Path(directory) / ".gitignore"

    if gitignore.exists():
        content = gitignore.read_text(encoding="utf-8")
        if ".drako/" in content:
            return
        with open(gitignore, "a", encoding="utf-8") as f:
            f.write("\n# Drako scan cache (local paths, not for VCS)\n.drako/\n")
    else:
        gitignore.write_text(
            "# Drako scan cache (local paths, not for VCS)\n.drako/\n",
            encoding="utf-8",
        )
