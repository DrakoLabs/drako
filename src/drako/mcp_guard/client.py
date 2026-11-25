"""Stateless MCP 2026-07-28 GA HTTP client with SSRF guard and tools/list drift detection.

Local-first, database-free client:
  - Defaults to `MCP-Protocol-Version: 2026-07-28` (stateless core).
  - Emits self-describing routing headers (`Mcp-Method`, `Mcp-Name`) so
    stateless gateways can route without stateful sessions.
  - Validates EVERY request URL and EVERY redirect hop through
    `drako.kernel.egress.assert_public_url()` (fail-closed SSRF defense).
  - Enforces `drako.mcp_guard.drift.check_tools_drift()` on every `tools/list`
    response to catch mid-session Deadbugz-class rug-pulls.
"""

from __future__ import annotations

from typing import Any

import httpx

from drako.kernel.egress import assert_public_url, resolve_redirect
from drako.mcp_guard.drift import check_tools_drift

MCP_GA_PROTOCOL_VERSION = "2026-07-28"


class MCPClientError(RuntimeError):
    """MCP transport or protocol error."""


class MCPGAClient:
    """Stateless-first MCP 2026-07-28 HTTP client with SSRF + drift protection."""

    def __init__(
        self,
        endpoint: str,
        *,
        server_id: str | None = None,
        protocol_version: str = MCP_GA_PROTOCOL_VERSION,
        bearer_token: str | None = None,
        allowlist: list[str] | None = None,
        allow_private: bool = False,
        timeout: float = 15.0,
    ) -> None:
        self.endpoint = assert_public_url(
            endpoint,
            allow_private=allow_private,
            allowlist=allowlist,
        )
        self.server_id = server_id or self.endpoint
        self.protocol_version = protocol_version
        self.bearer_token = bearer_token
        self.allowlist = allowlist
        self.allow_private = allow_private
        self.timeout = timeout
        self._tools_baseline: str | None = None
        self._req_id = 0

    @property
    def tools_baseline(self) -> str | None:
        return self._tools_baseline

    def _headers(self, rpc_method: str, tool_name: str | None = None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "MCP-Protocol-Version": self.protocol_version,
            "Mcp-Method": rpc_method,
        }
        if tool_name:
            headers["Mcp-Name"] = tool_name
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers

    def _post_with_egress_guard(
        self,
        payload: dict[str, Any],
        headers: dict[str, str],
        *,
        client: httpx.Client | None = None,
    ) -> dict[str, Any]:
        url = assert_public_url(
            self.endpoint,
            allow_private=self.allow_private,
            allowlist=self.allowlist,
        )
        owns_client = client is None
        http = client or httpx.Client(timeout=self.timeout, follow_redirects=False)
        try:
            current_headers = dict(headers)
            for hop in range(4):
                resp = http.post(url, json=payload, headers=current_headers)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        raise MCPClientError("redirect response missing Location header")
                    url = resolve_redirect(url, location, hop, allowlist=self.allowlist)
                    # Never forward bearer credentials across redirects
                    current_headers.pop("Authorization", None)
                    continue
                resp.raise_for_status()
                body = resp.json()
                if not isinstance(body, dict):
                    raise MCPClientError("MCP response must be a JSON object")
                if "error" in body and body["error"] is not None:
                    raise MCPClientError(f"MCP RPC error: {body['error']}")
                return body.get("result", {})
            raise MCPClientError("too many redirects")
        finally:
            if owns_client:
                http.close()

    def list_tools(self, *, client: httpx.Client | None = None) -> list[dict[str, Any]]:
        """Invoke stateless `tools/list` and fail-closed on mid-session drift."""
        self._req_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": "tools/list",
            "params": {},
        }
        result = self._post_with_egress_guard(
            payload,
            self._headers("tools/list"),
            client=client,
        )
        tools = result.get("tools", [])
        if not isinstance(tools, list):
            raise MCPClientError("tools/list response missing 'tools' array")
        self._tools_baseline = check_tools_drift(self._tools_baseline, tools, self.server_id)
        return tools

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        client: httpx.Client | None = None,
    ) -> dict[str, Any]:
        """Invoke stateless `tools/call` with Mcp-Method/Mcp-Name routing headers."""
        self._req_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments or {}},
        }
        return self._post_with_egress_guard(
            payload,
            self._headers("tools/call", tool_name=tool_name),
            client=client,
        )
