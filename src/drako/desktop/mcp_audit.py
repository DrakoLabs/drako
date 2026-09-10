"""`drako mcp audit` — audit configured MCP servers (P1-07, Sprint 2 P1).

The pin (`drako mcp pin`) fixes what SHOULD run; audit inspects what
IS configured: desktop client configs + project .mcp.json, crossed
against the lock. Verdicts per server:

- unpinned  — declared but absent from mcp.lock (pin it or remove it)
- unlisted  — not in the operator allowlist (when one is configured)
- risky     — any MCP-00x rule fires (shell/fs/net/plaintext-creds…)
- ok        — pinned, listed, no rule fires

Exit code: 0 when every server is ok, 1 otherwise (CI-usable).
Offline; never spawns servers.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServerAudit:
    """One server's audit verdict (pure data, testable)."""

    name: str
    package: str
    source_file: str
    verdict: str  # "ok" | "unpinned" | "unlisted" | "risky"
    details: list[str] = field(default_factory=list)


def audit_servers(
    servers: list,
    lock: dict[str, dict] | None = None,
    allowed_packages: list[str] | None = None,
    rule_findings: dict[str, list[str]] | None = None,
) -> list[ServerAudit]:
    """Audit server configs against lock + allowlist + rules (pure).

    servers: MCPServerConfig-like (name/package_name/source_file).
    lock: {package: {...}} or None (no lock = everything unpinned).
    rule_findings: {server_name: [rule_ids]} from evaluate_mcp_rules.
    Deny-closed ordering: unpinned > unlisted > risky > ok — the first
    hit decides, but ALL details are recorded.
    """
    lock = lock or {}
    rule_findings = rule_findings or {}
    out: list[ServerAudit] = []
    for server in servers:
        name = getattr(server, "name", "?")
        package = ""
        try:
            package = server.package_name or ""
        except Exception:
            package = ""
        details: list[str] = []
        verdict = "ok"
        if not package or package not in lock:
            verdict = "unpinned"
            details.append(
                f"{package or name!r} absent from mcp.lock — "
                "pin it (`drako mcp pin`) or remove the server"
            )
        if allowed_packages is not None and package not in allowed_packages:
            if verdict == "ok":
                verdict = "unlisted"
            details.append(
                f"{package!r} outside the operator allowlist "
                f"({len(allowed_packages)} admitted)"
            )
        hits = rule_findings.get(name, [])
        if hits:
            if verdict == "ok":
                verdict = "risky"
            details.append(f"rules fired: {', '.join(sorted(hits))}")
        out.append(ServerAudit(name=name, package=package,
                               source_file=getattr(server, "source_file", ""),
                               verdict=verdict, details=details))
    return out
