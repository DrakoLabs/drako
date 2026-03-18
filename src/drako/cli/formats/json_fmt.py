"""JSON output format for `drako scan --format json`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.scanner import ScanResult


def format_json(result: ScanResult) -> str:
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
    }

    return json.dumps(data, indent=2, default=str)
