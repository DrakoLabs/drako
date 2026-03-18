"""Main scan orchestrator for `drako scan`.

Ties together discovery, BOM generation, policy evaluation, and scoring
into a single `run_scan()` call. 100% offline — no network calls.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from drako.cli.discovery import collect_project_files, detect_frameworks, ProjectMetadata
from drako.cli.bom import generate_bom, AgentBOM
from drako.cli.policies import evaluate_all_policies
from drako.cli.policies.base import Finding
from drako.cli.scoring import calculate_score, score_to_grade, findings_summary


@dataclass
class ScanResult:
    """Complete scan result — everything needed for report/upload."""
    metadata: ProjectMetadata
    bom: AgentBOM
    findings: list[Finding]
    score: int | None
    grade: str | None
    scan_duration_ms: int


def run_scan(
    directory: str = ".",
    framework_filter: list[str] | None = None,
    include_tests: bool = False,
) -> ScanResult:
    """Execute a full offline governance scan.

    Args:
        directory: Path to the project directory to scan.
        framework_filter: If provided, only detect these frameworks.
        include_tests: If True, include tests/test/fixtures dirs in scan.

    Returns:
        ScanResult with all analysis data.
    """
    start = time.monotonic()

    # Phase 1: Collect project files & detect frameworks
    root = Path(directory).resolve()
    metadata = collect_project_files(root, include_tests=include_tests)
    metadata.frameworks = detect_frameworks(metadata)

    # Apply framework filter if specified
    if framework_filter:
        allowed = {f.lower() for f in framework_filter}
        metadata.frameworks = [
            fw for fw in metadata.frameworks if fw.name.lower() in allowed
        ]

    # Phase 2: Generate Agent BOM
    bom = generate_bom(metadata)

    # Phase 3: Evaluate all policies
    # Skip policy evaluation when no agent frameworks detected
    if not metadata.frameworks and not bom.agents:
        findings: list[Finding] = []
        score = None
        grade = None
    else:
        findings = evaluate_all_policies(bom, metadata)
        score = calculate_score(findings)
        grade = score_to_grade(score)

    duration_ms = int((time.monotonic() - start) * 1000)

    return ScanResult(
        metadata=metadata,
        bom=bom,
        findings=findings,
        score=score,
        grade=grade,
        scan_duration_ms=duration_ms,
    )
