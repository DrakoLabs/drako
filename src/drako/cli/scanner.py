"""Main scan orchestrator for `drako scan`.

Ties together discovery, BOM generation, policy evaluation, scoring,
reachability analysis, and advisory matching into a single `run_scan()`
call. 100% offline — no network calls.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from drako.cli.discovery import collect_project_files, detect_frameworks, ProjectMetadata
from drako.cli.bom import generate_bom, AgentBOM
from drako.cli.policies import evaluate_all_policies
from drako.cli.policies.base import Finding
from drako.cli.scoring import (
    calculate_score,
    calculate_determinism_score,
    score_to_grade,
    findings_summary,
)

if TYPE_CHECKING:
    from drako.advisories import Advisory
    from drako.heuristic_reachability import ToolReachability


@dataclass
class ScanResult:
    """Complete scan result — everything needed for report/upload."""
    metadata: ProjectMetadata
    bom: AgentBOM
    findings: list[Finding]
    score: int
    grade: str
    scan_duration_ms: int
    # Block 1: Advisory matching
    matched_advisories: dict[str, list[Advisory]] = field(default_factory=dict)
    # Block 2: Determinism score + Reachability
    determinism_score: int = 100
    determinism_grade: str = "A"
    reachability: list[ToolReachability] = field(default_factory=list)
    languages: set[str] = field(default_factory=set)
    # U-4 (2026-09-04): files the AST-based rules could not parse and
    # therefore SKIPPED. Observable by contract: a scanner that skips
    # silently is un-auditable. Shown in terminal + JSON output.
    skipped_files: list[str] = field(default_factory=list)


def find_unparseable_files(file_contents: dict[str, str]) -> list[str]:
    """Return .py paths whose content fails ast.parse (U-4, 2026-09-04).

    Single canonical pre-pass: every policy's `except SyntaxError: continue`
    skips exactly this set, so the counter is the scan-level observable
    for all of them.
    """
    skipped: list[str] = []
    for path, content in file_contents.items():
        if not path.endswith(".py"):
            continue
        try:
            ast.parse(content)
        except SyntaxError:
            skipped.append(path)
    return skipped


def run_scan(
    directory: str = ".",
    framework_filter: list[str] | None = None,
) -> ScanResult:
    """Execute a full offline governance scan.

    Args:
        directory: Path to the project directory to scan.
        framework_filter: If provided, only detect these frameworks.

    Returns:
        ScanResult with all analysis data.
    """
    start = time.monotonic()

    # Phase 1: Collect project files & detect frameworks
    root = Path(directory).resolve()
    metadata = collect_project_files(root)
    metadata.frameworks = detect_frameworks(metadata)

    # Apply framework filter if specified
    if framework_filter:
        allowed = {f.lower() for f in framework_filter}
        metadata.frameworks = [
            fw for fw in metadata.frameworks if fw.name.lower() in allowed
        ]

    # Phase 2: Generate Agent BOM
    bom = generate_bom(metadata)

    # Phase 2.4 (U-4): canonical skipped-files pre-pass — AST-based rules
    # `except SyntaxError: continue` on exactly this set.
    skipped_files = find_unparseable_files(metadata.file_contents)

    # Phase 2.5: Heuristic reachability analysis (string-match, not dataflow)
    from drako.heuristic_reachability import analyze_reachability
    reachability = analyze_reachability(bom, metadata)

    # Phase 3: Evaluate all policies
    findings = evaluate_all_policies(bom, metadata)

    # Phase 4: Calculate scores
    score = calculate_score(findings)
    grade = score_to_grade(score)
    det_score = calculate_determinism_score(findings)
    det_grade = score_to_grade(det_score)

    # Phase 5: Match advisories
    from drako.advisories import match_advisories_bulk
    matched_advisories = match_advisories_bulk(findings)

    duration_ms = int((time.monotonic() - start) * 1000)

    # Detect languages present
    languages: set[str] = set()
    if metadata.python_files:
        languages.add("python")
    if metadata.ts_files:
        languages.add("typescript")

    return ScanResult(
        metadata=metadata,
        bom=bom,
        findings=findings,
        score=score,
        grade=grade,
        scan_duration_ms=duration_ms,
        matched_advisories=matched_advisories,
        determinism_score=det_score,
        determinism_grade=det_grade,
        reachability=reachability,
        languages=languages,
        skipped_files=skipped_files,
    )
