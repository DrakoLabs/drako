"""Baseline management for `drako scan`.

Allows teams to acknowledge existing findings and only surface NEW
issues on subsequent scans. Critical for adoption in existing projects.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.policies.base import Finding

BASELINE_DIR = ".drako"
BASELINE_FILE = ".baseline.json"
BASELINE_VERSION = 1


def fingerprint(finding: Finding) -> str:
    """Compute a stable fingerprint for a finding.

    SHA-256 of: rule_id + normalized_file_path + stripped_code_snippet.
    Line numbers are intentionally excluded so that code movement within
    a file does not create a "new" finding.

    When code_snippet is None, the finding message is used as a fallback
    differentiator to avoid collisions between findings from the same
    rule in the same file.
    """
    rule_id = finding.policy_id
    file_path = (finding.file_path or "").replace("\\", "/")
    snippet = finding.code_snippet
    snippet = "".join(snippet.split()) if snippet is not None else finding.message

    raw = f"{rule_id}|{file_path}|{snippet}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Baseline:
    """Manages the .drako/.baseline.json file."""

    def __init__(self, project_dir: str = ".") -> None:
        self._dir = Path(project_dir) / BASELINE_DIR
        self.path = self._dir / BASELINE_FILE

    def exists(self) -> bool:
        return self.path.exists()

    def save(self, findings: list[Finding]) -> Path:
        """Save current findings as the baseline.

        Only hashes are stored — no raw code snippets — to prevent
        accidental commit of secrets that were baselined.
        """
        from drako import __version__

        fingerprints: dict[str, dict] = {}
        for f in findings:
            fp = fingerprint(f)
            snippet_hash = ""
            if f.code_snippet:
                snippet_hash = "sha256:" + hashlib.sha256(
                    f.code_snippet.encode("utf-8")
                ).hexdigest()[:16]

            fingerprints[fp] = {
                "rule_id": f.policy_id,
                "file": (f.file_path or "").replace("\\", "/"),
                "line": f.line_number,
                "snippet_hash": snippet_hash,
                "severity": f.severity,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

        data = {
            "version": BASELINE_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "drako_version": __version__,
            "finding_count": len(findings),
            "fingerprints": fingerprints,
        }

        self._dir.mkdir(exist_ok=True)
        self.path.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )
        return self.path

    def load(self) -> dict | None:
        """Load baseline data. Returns None if missing or corrupt."""
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        # Validate minimal structure
        if not isinstance(data, dict):
            return None
        if "fingerprints" not in data or not isinstance(data["fingerprints"], dict):
            return None

        return data

    def filter_findings(
        self, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding], list[str]]:
        """Partition findings against baseline.

        Returns:
            (new_findings, baselined_findings, resolved_fingerprints)
        """
        data = self.load()
        if data is None:
            return findings, [], []

        baseline_fps = set(data["fingerprints"].keys())

        new: list[Finding] = []
        baselined: list[Finding] = []
        current_fps: set[str] = set()

        for f in findings:
            fp = fingerprint(f)
            current_fps.add(fp)
            if fp in baseline_fps:
                baselined.append(f)
            else:
                new.append(f)

        resolved = [fp for fp in baseline_fps if fp not in current_fps]

        return new, baselined, resolved

    def reset(self) -> bool:
        """Delete baseline file. Returns True if it existed."""
        if self.path.exists():
            self.path.unlink()
            return True
        return False

    def summary(self) -> dict | None:
        """Return baseline summary for display."""
        data = self.load()
        if data is None:
            return None

        fps = data.get("fingerprints", {})
        severity_counts: dict[str, int] = {}
        for info in fps.values():
            sev = info.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "version": data.get("version", 0),
            "created_at": data.get("created_at", ""),
            "drako_version": data.get("drako_version", ""),
            "total_findings": len(fps),
            "severity_counts": severity_counts,
        }
