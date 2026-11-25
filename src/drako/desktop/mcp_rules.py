"""MCP Server security rules.

Evaluate MCP server configurations discovered on the desktop or in
project ``.mcp.json`` files.  These rules apply to
:class:`~drako.desktop.discovery.MCPServerConfig` objects — they are
evaluated by the desktop scanner, not by the project policy engine.

Rule inventory (8 rules):

==========  ========  ============================================
Rule ID     Severity  Description
==========  ========  ============================================
MCP-001     HIGH      Filesystem access without path restriction
MCP-002     CRITICAL  Shell / exec capability
MCP-003     MEDIUM    Server from unverified source
MCP-004     MEDIUM    Network access without domain allowlist
MCP-005     CRITICAL  Credentials stored in plaintext config
MCP-006     HIGH      Unencrypted transport (HTTP, not HTTPS)
MCP-007     CRITICAL  Running with elevated privileges
MCP-008     HIGH      Multiple high-risk capabilities combined
==========  ========  ============================================
"""

from __future__ import annotations

from dataclasses import dataclass

from drako.desktop.discovery import DesktopBOM, MCPServerConfig


@dataclass
class MCPFinding:
    """A single finding from MCP rule evaluation."""

    rule_id: str
    severity: str
    title: str
    description: str
    server_name: str
    client: str
    config_file: str
    remediation: str
    finding_type: str = "vulnerability"


# ---------------------------------------------------------------------------
# Trusted-source prefixes (MCP-003)
# ---------------------------------------------------------------------------

_KNOWN_TRUSTED_PREFIXES: frozenset[str] = frozenset({
    "@modelcontextprotocol/",
    "mcp-server-",
    "@anthropic/",
    "@langchain/",
    "@vercel/",
})

# ---------------------------------------------------------------------------
# Sensitive env-var key fragments (MCP-005)
# ---------------------------------------------------------------------------

_SENSITIVE_KEY_FRAGMENTS: frozenset[str] = frozenset({
    "api_key", "apikey", "token", "secret", "password",
    "credential", "auth",
})

# ---------------------------------------------------------------------------
# Elevated commands (MCP-007)
# ---------------------------------------------------------------------------

_ELEVATED_COMMANDS: frozenset[str] = frozenset({"sudo", "doas", "runas"})


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------


def evaluate_mcp_rules(bom: DesktopBOM) -> list[MCPFinding]:
    """Run all 8 MCP rules against a :class:`DesktopBOM`.

    Returns a list of :class:`MCPFinding` objects sorted by severity
    (CRITICAL first).
    """
    findings: list[MCPFinding] = []
    for agent in bom.agents:
        for server in agent.mcp_servers:
            findings.extend(_evaluate_server(server))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return findings


def _evaluate_server(server: MCPServerConfig) -> list[MCPFinding]:
    """Evaluate all MCP rules against a single server configuration."""
    findings: list[MCPFinding] = []

    # MCP-001: Filesystem access without path restriction
    if server.has_filesystem_access:
        has_restriction = any(
            arg.startswith("/") or arg.startswith("~") or arg.startswith("C:\\")
            for arg in server.args[1:]  # skip package name
        )
        if not has_restriction:
            findings.append(MCPFinding(
                rule_id="MCP-001",
                severity="HIGH",
                title="MCP server with unrestricted filesystem access",
                description=(
                    f"Server '{server.name}' has filesystem capabilities "
                    f"without explicit path restrictions. It can read/write "
                    f"any file the user has access to."
                ),
                server_name=server.name,
                client=server.client,
                config_file=server.source_file,
                remediation=(
                    "Add explicit allowed paths to the server args. "
                    "Example: [\"npx\", \"@modelcontextprotocol/server-filesystem\", "
                    "\"/Users/me/safe-directory\"]"
                ),
            ))

    # MCP-002: Shell / exec capability
    if server.has_shell_access:
        findings.append(MCPFinding(
            rule_id="MCP-002",
            severity="CRITICAL",
            title="MCP server with shell/exec capability",
            description=(
                f"Server '{server.name}' can execute shell commands. "
                f"A compromised or malicious prompt can execute arbitrary "
                f"commands on your machine through this server."
            ),
            server_name=server.name,
            client=server.client,
            config_file=server.source_file,
            remediation=(
                "Use a sandboxed execution environment or remove this "
                "server if not strictly needed. Consider using Drako's "
                "proxy to intercept and audit all commands."
            ),
        ))

    # MCP-003: Server from untrusted source
    pkg = server.package_name
    is_trusted = any(pkg.startswith(prefix) for prefix in _KNOWN_TRUSTED_PREFIXES)
    is_local = (
        pkg.startswith("/")
        or pkg.startswith("./")
        or pkg.startswith("~")
        or pkg.startswith("C:\\")
    )
    if not is_trusted and not is_local:
        findings.append(MCPFinding(
            rule_id="MCP-003",
            severity="MEDIUM",
            title="MCP server from unverified source",
            description=(
                f"Server '{server.name}' uses package '{pkg}' which "
                f"is not from a known MCP registry. Verify the source "
                f"before trusting it with your data."
            ),
            server_name=server.name,
            client=server.client,
            config_file=server.source_file,
            remediation=(
                "Verify the package on npm/pypi. Check the source "
                "repository for security issues. Consider running "
                "drako desktop scan regularly to monitor changes."
            ),
        ))

    # MCP-004: Network access without domain allowlist
    if server.has_network_access:
        findings.append(MCPFinding(
            rule_id="MCP-004",
            severity="MEDIUM",
            title="MCP server with unrestricted network access",
            description=(
                f"Server '{server.name}' can make network requests "
                f"without a configured domain allowlist. It could "
                f"exfiltrate data to any endpoint."
            ),
            server_name=server.name,
            client=server.client,
            config_file=server.source_file,
            remediation=(
                "Configure network restrictions in Drako's proxy mode "
                "or use ODD policies to restrict allowed domains."
            ),
        ))

    # MCP-005: Credentials in plaintext config
    for key, value in server.env.items():
        key_lower = key.lower()
        has_sensitive_fragment = any(
            s in key_lower for s in _SENSITIVE_KEY_FRAGMENTS
        )
        if (
            has_sensitive_fragment
            and value
            and not value.startswith("${")
            and not value.startswith("$")
        ):
            findings.append(MCPFinding(
                rule_id="MCP-005",
                severity="CRITICAL",
                title="Credentials stored in plaintext MCP config",
                description=(
                    f"Server '{server.name}' has credential '{key}' "
                    f"stored as plaintext in the config file. Anyone "
                    f"with access to this file can read the credential."
                ),
                server_name=server.name,
                client=server.client,
                config_file=server.source_file,
                remediation=(
                    f"Use environment variable references instead: "
                    f'"{key}": "${{{key.upper()}}}" and set the '
                    f"value in your shell profile or secrets manager."
                ),
            ))
            break  # one finding per server for credentials

    # MCP-006: SSE/HTTP transport without TLS
    if (
        server.transport in ("sse", "streamable-http")
        and server.url
        and server.url.startswith("http://")
        and "localhost" not in server.url
    ):
        findings.append(MCPFinding(
            rule_id="MCP-006",
            severity="HIGH",
            title="MCP server using unencrypted transport",
            description=(
                f"Server '{server.name}' communicates over HTTP "
                f"(not HTTPS) to {server.url}. All data including "
                f"prompts and tool results is transmitted in cleartext."
            ),
            server_name=server.name,
            client=server.client,
            config_file=server.source_file,
            remediation="Use HTTPS for all non-localhost MCP connections.",
        ))

    # MCP-007: Server running with elevated command
    if server.command in _ELEVATED_COMMANDS:
        findings.append(MCPFinding(
            rule_id="MCP-007",
            severity="CRITICAL",
            title="MCP server running with elevated privileges",
            description=(
                f"Server '{server.name}' runs via '{server.command}', "
                f"giving it elevated system privileges. A compromise "
                f"of this server means full system compromise."
            ),
            server_name=server.name,
            client=server.client,
            config_file=server.source_file,
            remediation="Run MCP servers with minimum required privileges.",
        ))

    # MCP-008: Multiple high-risk capabilities
    risk_count = sum([
        server.has_filesystem_access,
        server.has_shell_access,
        server.has_network_access,
    ])
    if risk_count >= 2:
        findings.append(MCPFinding(
            rule_id="MCP-008",
            severity="HIGH",
            title="MCP server with multiple high-risk capabilities",
            description=(
                f"Server '{server.name}' has {risk_count} high-risk "
                f"capabilities (filesystem + shell + network). Combined "
                f"access creates a compound attack surface."
            ),
            server_name=server.name,
            client=server.client,
            config_file=server.source_file,
            remediation=(
                "Split into separate servers with single responsibilities. "
                "Use Drako's proxy to monitor and restrict each one."
            ),
        ))

    return findings
