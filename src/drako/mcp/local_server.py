"""Local MCP compliance server that proxies tool calls to the Drako backend.

Supports STDIO and SSE transports. Designed for use with Claude Desktop,
Cursor, and other MCP-compatible clients.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from drako import __version__ as _SERVER_VERSION
from drako.client import DrakoClient
from drako.utils.logger import log

_PROTOCOL_VERSION = "2024-11-05"
_SERVER_NAME = "drako-local"

# MCP tool definitions exposed by this local server
_TOOLS = [
    {
        "name": "audit_log_action",
        "description": "Log an agent action to the immutable audit hash chain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_did": {"type": "string", "description": "The agent's DID"},
                "action_type": {"type": "string", "description": "Type of action performed"},
                "action_description": {"type": "string", "description": "Human-readable description"},
                "metadata": {"type": "object", "description": "Optional metadata"},
            },
            "required": ["agent_did", "action_type", "action_description"],
        },
    },
    {
        "name": "verify_agent_identity",
        "description": "Verify an agent's identity and get its trust score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_name": {"type": "string", "description": "Name of the agent"},
                "agent_role": {"type": "string", "description": "Role/purpose of the agent"},
                "metadata": {"type": "object", "description": "Optional metadata"},
            },
            "required": ["agent_name", "agent_role"],
        },
    },
    {
        "name": "evaluate_policy",
        "description": "Evaluate if an action is allowed by governance policies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "The action to evaluate"},
                "agent_did": {"type": "string", "description": "The agent's DID"},
                "context": {"type": "object", "description": "Optional context for evaluation"},
            },
            "required": ["action", "agent_did"],
        },
    },
    {
        "name": "verify_audit_chain",
        "description": "Verify the integrity of the audit hash chain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "last_n": {"type": "integer", "description": "Only verify last N entries"},
            },
        },
    },
    {
        "name": "check_quota",
        "description": "Check the tenant's current usage quota.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def _jsonrpc_response(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _jsonrpc_error(id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


class LocalMCPHandler:
    """Handles MCP JSON-RPC requests by proxying to Drako backend."""

    def __init__(self, api_key: str, endpoint: str, tenant_id: str):
        self._client = DrakoClient(api_key=api_key, endpoint=endpoint, tenant_id=tenant_id)

    def handle(self, request: dict) -> dict:
        """Handle a single JSON-RPC request synchronously."""
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return _jsonrpc_response(req_id, {
                "protocolVersion": _PROTOCOL_VERSION,
                "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
                "capabilities": {"tools": {}},
            })

        if method == "initialized":
            return _jsonrpc_response(req_id, {})

        if method == "ping":
            return _jsonrpc_response(req_id, {})

        if method == "tools/list":
            return _jsonrpc_response(req_id, {"tools": _TOOLS})

        if method == "tools/call":
            return self._handle_tool_call(req_id, params)

        return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")

    def _handle_tool_call(self, req_id: Any, params: dict) -> dict:
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        try:
            if tool_name == "audit_log_action":
                result = self._client.audit_log_sync(
                    action=args["action_type"],
                    agent_did=args["agent_did"],
                    metadata=args.get("metadata"),
                )
            elif tool_name == "verify_agent_identity":
                result = self._client.verify_agent_identity_sync(
                    agent_name=args["agent_name"],
                    agent_role=args["agent_role"],
                    metadata=args.get("metadata"),
                )
            elif tool_name == "evaluate_policy":
                result = self._client.evaluate_policy_sync(
                    action=args["action"],
                    agent_did=args["agent_did"],
                    context=args.get("context"),
                )
            elif tool_name == "verify_audit_chain":
                result = self._client.verify_chain_sync(last_n=args.get("last_n"))
            elif tool_name == "check_quota":
                result = self._client.check_quota_sync()
            else:
                return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}")

            return _jsonrpc_response(req_id, {
                "content": [{"type": "text", "text": json.dumps(result)}],
            })
        except Exception as exc:
            log.error("Tool call %s failed: %s", tool_name, exc)
            return _jsonrpc_error(req_id, -32000, str(exc))


def run_stdio(api_key: str, endpoint: str, tenant_id: str) -> None:
    """Run the MCP server over STDIO (one JSON-RPC request per line)."""
    handler = LocalMCPHandler(api_key=api_key, endpoint=endpoint, tenant_id=tenant_id)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            response = _jsonrpc_error(None, -32700, "Parse error")
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            continue

        response = handler.handle(request)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


def run_sse(api_key: str, endpoint: str, tenant_id: str, port: int = 3100) -> None:
    """Run the MCP server over HTTP+SSE.

    Uses a minimal HTTP server — no heavy framework dependency.
    """
    import http.server
    import threading

    handler_instance = LocalMCPHandler(api_key=api_key, endpoint=endpoint, tenant_id=tenant_id)

    class MCPHTTPHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/mcp":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                request = json.loads(body)
            except json.JSONDecodeError:
                self._send_json(_jsonrpc_error(None, -32700, "Parse error"))
                return
            response = handler_instance.handle(request)
            self._send_json(response)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json({"status": "ok"})
            elif self.path == "/":
                self._send_json({
                    "name": _SERVER_NAME,
                    "version": _SERVER_VERSION,
                    "protocol": _PROTOCOL_VERSION,
                })
            else:
                self.send_error(404)

        def _send_json(self, data: dict) -> None:
            payload = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            log.info(format, *args)

    server = http.server.HTTPServer(("0.0.0.0", port), MCPHTTPHandler)
    log.info("MCP SSE server listening on http://0.0.0.0:%d", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Server stopped")
        server.server_close()
