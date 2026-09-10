"""JSON output format for `drako scan --format json`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.benchmark import BenchmarkResult
    from drako.cli.scanner import ScanResult


def format_json(
    result: ScanResult,
    benchmark: BenchmarkResult | None = None,
) -> str:
    """Serialize scan result to a JSON string (pretty-printed)."""
    data = {
        "version": "1.0.0",
        "scanner": "drako",
        "project": {
            "name": result.metadata.root.name,
            "path": str(result.metadata.root),
            "files_scanned": len(result.metadata.python_files),
        },
        "frameworks": [
            {
                "name": fw.name,
                "version": fw.version,
                "confidence": fw.confidence,
            }
            for fw in result.bom.frameworks
        ],
        "score": result.score,
        "grade": result.grade,
        "scan_duration_ms": result.scan_duration_ms,
        "skipped_files": list(getattr(result, "skipped_files", [])),
        "findings": [
            {
                "policy_id": f.policy_id,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "message": f.message,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
                "fix_snippet": f.fix_snippet,
                "impact": f.impact,
                "attack_scenario": f.attack_scenario,
                "references": f.references,
                "remediation_effort": f.remediation_effort,
                "finding_type": getattr(f, "finding_type", "vulnerability"),
            }
            for f in result.findings
        ],
        "agent_bom": {
            "agents": [
                {
                    "name": a.name,
                    "class_name": a.class_name,
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
                    "line_number": t.line_number,
                    "has_filesystem_access": t.has_filesystem_access,
                    "has_network_access": t.has_network_access,
                    "has_code_execution": t.has_code_execution,
                }
                for t in result.bom.tools
            ],
            "models": [
                {
                    "name": m.name,
                    "file_path": m.file_path,
                    "line_number": m.line_number,
                }
                for m in result.bom.models
            ],
            "mcp_servers": result.bom.mcp_servers,
            "prompts_count": len(result.bom.prompts),
            "permissions": result.bom.permissions,
        },
        "summary": {
            "critical": sum(1 for f in result.findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in result.findings if f.severity == "HIGH"),
            "medium": sum(1 for f in result.findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in result.findings if f.severity == "LOW"),
            "total": len(result.findings),
        },
        "determinism_score": result.determinism_score,
        "determinism_grade": result.determinism_grade,
        "advisories": [
            {
                "id": adv.id,
                "title": adv.title,
                "category": adv.category,
                "severity": adv.severity,
                "matched_rules": adv.drako_rules,
                "references": [
                    {"type": ref.get("type", ""), "id": ref.get("id", "")}
                    for ref in adv.references
                ],
            }
            for advs in result.matched_advisories.values()
            for adv in advs
        ],
        "reachability": [
            {
                "tool_name": tr.tool_name,
                "status": tr.status.value,
                "referencing_agents": tr.referencing_agents,
                "file_path": tr.file_path,
                "line_number": tr.line_number,
            }
            for tr in result.reachability
        ],
    }

    if benchmark is not None:
        data["benchmark"] = {
            "percentile": benchmark.percentile,
            "framework_percentile": benchmark.framework_percentile,
            "framework": benchmark.framework,
            "projects_in_benchmark": benchmark.projects_in_benchmark,
            "grade_distribution": benchmark.grade_distribution,
        }

    return json.dumps(data, indent=2, default=str)
