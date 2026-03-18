"""Upload scan results to the Drako backend.

Sends pre-computed results (score, findings, BOM) to the backend
for storage and sharing. Does NOT send raw source code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from drako.cli.scanner import ScanResult


def _build_payload(result: ScanResult, project_name: str | None = None) -> dict:
    """Convert ScanResult into the upload payload."""
    return {
        "project_name": project_name or result.metadata.root.name,
        "framework": result.bom.frameworks[0].name if result.bom.frameworks else "unknown",
        "framework_version": result.bom.frameworks[0].version if result.bom.frameworks else None,
        "scan_duration_ms": result.scan_duration_ms,
        "score": result.score,
        "grade": result.grade,
        "findings": [
            {
                "policy_id": f.policy_id,
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
            "frameworks": [
                {"name": fw.name, "version": fw.version}
                for fw in result.bom.frameworks
            ],
            "agents": [
                {
                    "name": a.name,
                    "role": a.class_name or a.name,
                    "tools": a.tools,
                    "mcp_servers": [],
                    "data_sources": [],
                    "governance": {},
                }
                for a in result.bom.agents
            ],
            "tools_total": len(result.bom.tools),
            "mcp_servers": result.bom.mcp_servers,
            "risk_level": "low" if result.score >= 70 else ("medium" if result.score >= 40 else "high"),
        },
        "recommendations": [],
    }


def upload_results(
    result: ScanResult,
    api_key: str | None = None,
    endpoint: str = "https://api.useagentmesh.com",
    project_name: str | None = None,
) -> dict:
    """Upload scan results to the Drako backend.

    Args:
        result: The ScanResult to upload.
        api_key: API key for authenticated upload. None for anonymous.
        endpoint: Backend URL.
        project_name: Override project name (defaults to directory name).

    Returns:
        dict with ``scan_id`` and ``url`` keys.

    Raises:
        httpx.HTTPStatusError: On 4xx/5xx responses.
        httpx.ConnectError: If backend is unreachable.
    """
    payload = _build_payload(result, project_name=project_name)

    if api_key:
        url = f"{endpoint.rstrip('/')}/api/v1/scans"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    else:
        url = f"{endpoint.rstrip('/')}/api/v1/scans/anonymous"
        headers = {"Content-Type": "application/json"}

    with httpx.Client(timeout=60.0) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()
