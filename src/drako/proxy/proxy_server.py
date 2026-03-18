"""Drako Enforcement Proxy.

Intercepts LLM API calls at the network layer.
Runs as a separate process — the agent cannot bypass it.

Usage:
    drako proxy start                    # starts on localhost:8990
    drako proxy start --port 9000        # custom port

Agent configuration (env vars):
    OPENAI_BASE_URL=http://localhost:8990/openai/v1
    ANTHROPIC_BASE_URL=http://localhost:8990/anthropic/v1
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("drako.proxy")

# Target API mappings
TARGETS: dict[str, str] = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}

# Known model cost estimates (input $/1K tokens, output $/1K tokens)
MODEL_COSTS: dict[str, tuple[float, float]] = {
    "gpt-4o": (0.0025, 0.01),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-4-turbo": (0.01, 0.03),
    "gpt-4": (0.03, 0.06),
    "gpt-3.5-turbo": (0.0005, 0.0015),
    "claude-3-opus": (0.015, 0.075),
    "claude-3-sonnet": (0.003, 0.015),
    "claude-3-haiku": (0.00025, 0.00125),
    "claude-3.5-sonnet": (0.003, 0.015),
    "claude-4-sonnet": (0.003, 0.015),
    "claude-4-opus": (0.015, 0.075),
}


def _load_config(config_path: str = ".drako.yaml") -> dict[str, Any]:
    """Load the Drako config for governance evaluation."""
    path = Path(config_path)
    if not path.exists():
        # Walk up to find config
        current = Path.cwd()
        while current != current.parent:
            candidate = current / ".drako.yaml"
            if candidate.exists():
                path = candidate
                break
            current = current.parent

    if not path.exists():
        logger.warning("No .drako.yaml found, proxy running with defaults")
        return {}

    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError) as exc:
        logger.error("Failed to load config: %s", exc)
        return {}


def _resolve_target(path: str) -> tuple[str, str]:
    """Resolve the target API URL from the request path prefix.

    Returns (target_base_url, stripped_path).
    """
    for prefix, target_url in TARGETS.items():
        if path.startswith(f"/{prefix}/") or path.startswith(f"{prefix}/"):
            stripped = path.split(f"/{prefix}", 1)[-1]
            if not stripped.startswith("/"):
                stripped = "/" + stripped
            return target_url, stripped

    raise ValueError(f"Unknown API target for path: {path}")


def _extract_tool_call(body: dict[str, Any]) -> str | None:
    """Extract the tool/function being called from the request body."""
    # OpenAI format
    if "function_call" in body:
        fc = body["function_call"]
        if isinstance(fc, dict):
            return fc.get("name")
        return str(fc) if fc else None

    # OpenAI tool_choice
    if "tool_choice" in body:
        tc = body["tool_choice"]
        if isinstance(tc, dict):
            fn = tc.get("function", {})
            return fn.get("name") if isinstance(fn, dict) else None

    # Check messages for tool calls
    messages = body.get("messages", [])
    for msg in reversed(messages):
        if isinstance(msg, dict) and msg.get("role") == "assistant":
            tool_calls = msg.get("tool_calls", [])
            if tool_calls and isinstance(tool_calls, list):
                first = tool_calls[0]
                if isinstance(first, dict):
                    fn = first.get("function", {})
                    return fn.get("name") if isinstance(fn, dict) else None

    return None


def _extract_tool_args(body: dict[str, Any]) -> dict[str, Any]:
    """Extract tool arguments from the request body."""
    messages = body.get("messages", [])
    for msg in reversed(messages):
        if isinstance(msg, dict) and msg.get("role") == "assistant":
            tool_calls = msg.get("tool_calls", [])
            if tool_calls and isinstance(tool_calls, list):
                first = tool_calls[0]
                if isinstance(first, dict):
                    fn = first.get("function", {})
                    args_str = fn.get("arguments", "{}") if isinstance(fn, dict) else "{}"
                    try:
                        return json.loads(args_str)
                    except (json.JSONDecodeError, TypeError):
                        return {}
    return {}


def _check_odd(agent_id: str | None, tool_name: str | None,
               config: dict[str, Any]) -> dict[str, Any] | None:
    """Check ODD constraints. Returns rejection dict or None if allowed."""
    odd = config.get("odd")
    if not odd or not isinstance(odd, dict):
        return None

    enforcement = odd.get("enforcement_mode", "audit")
    if enforcement == "off":
        return None

    if not agent_id or not tool_name:
        return None

    agents = odd.get("agents", {})
    agent_odd = agents.get(agent_id)
    if not agent_odd or not isinstance(agent_odd, dict):
        return None

    forbidden = agent_odd.get("forbidden_tools", [])
    permitted = agent_odd.get("permitted_tools", [])

    violation = None
    if tool_name in forbidden:
        violation = f"Tool '{tool_name}' is forbidden for agent '{agent_id}'"
    elif permitted and tool_name not in permitted:
        violation = f"Tool '{tool_name}' is not in permitted list for agent '{agent_id}'"

    if violation:
        if enforcement == "enforce":
            return {"decision": "rejected", "reason": violation, "rule": "ODD"}
        else:
            logger.warning("[ODD audit] %s", violation)

    return None


def _check_magnitude(agent_id: str | None, config: dict[str, Any],
                     session_state: dict[str, Any]) -> dict[str, Any] | None:
    """Check magnitude limits. Returns rejection dict or None if allowed."""
    mag = config.get("magnitude")
    if not mag or not isinstance(mag, dict):
        return None

    max_actions = mag.get("max_actions_per_minute", 999999)
    agent_key = agent_id or "unknown"

    # Track actions per minute
    now = time.time()
    actions_key = f"actions_{agent_key}"
    actions = session_state.get(actions_key, [])
    actions = [t for t in actions if now - t < 60]
    actions.append(now)
    session_state[actions_key] = actions

    if len(actions) > max_actions:
        enforcement = mag.get("enforcement_mode", "audit")
        reason = f"Agent '{agent_key}' exceeded {max_actions} actions/minute (current: {len(actions)})"
        if enforcement == "enforce":
            return {"decision": "rejected", "reason": reason, "rule": "MAGNITUDE"}
        else:
            logger.warning("[MAGNITUDE audit] %s", reason)

    return None


def _check_dlp(body: dict[str, Any], config: dict[str, Any]) -> dict[str, Any] | None:
    """Scan request body for PII patterns. Returns rejection or None."""
    import re

    dlp = config.get("dlp")
    if not dlp or not isinstance(dlp, dict):
        return None

    mode = dlp.get("mode", "off")
    if mode == "off":
        return None

    # Serialize messages to text for scanning
    messages = body.get("messages", [])
    text = json.dumps(messages) if messages else ""

    # Basic PII patterns
    patterns = {
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "email_pii": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    }

    findings = []
    for name, pattern in patterns.items():
        if re.search(pattern, text):
            findings.append(name)

    if findings:
        reason = f"PII detected in payload: {', '.join(findings)}"
        if mode == "enforce":
            return {"decision": "rejected", "reason": reason, "rule": "DLP"}
        else:
            logger.warning("[DLP audit] %s", reason)

    return None


def _check_hitl(tool_name: str | None, config: dict[str, Any]) -> dict[str, Any] | None:
    """Check if HITL approval is needed. Returns pending dict or None."""
    hitl = config.get("hitl")
    if not hitl or not isinstance(hitl, dict):
        return None

    mode = hitl.get("mode", "off")
    if mode == "off":
        return None

    if not tool_name:
        return None

    triggers = hitl.get("triggers", {})
    trigger_tools = triggers.get("tools", [])
    trigger_types = triggers.get("tool_types", [])

    # For proxy mode, we can only check tool names directly
    if tool_name in trigger_tools:
        timeout_action = hitl.get("timeout_action", "allow")
        if timeout_action == "allow":
            logger.info("[HITL] Tool '%s' would require approval (auto-allowing)", tool_name)
            return None
        if mode == "enforce":
            approval_id = hashlib.sha256(
                f"{tool_name}:{time.time()}".encode()
            ).hexdigest()[:16]
            return {
                "decision": "pending_approval",
                "reason": f"Tool '{tool_name}' requires human approval",
                "approval_id": approval_id,
                "rule": "HITL",
            }

    return None


def _estimate_cost(model: str, response_body: dict[str, Any]) -> float | None:
    """Estimate cost from response usage data."""
    usage = response_body.get("usage")
    if not usage or not isinstance(usage, dict):
        return None

    input_tokens = usage.get("prompt_tokens", 0)
    output_tokens = usage.get("completion_tokens", 0)

    # Find cost rates
    costs = None
    for model_prefix, rates in MODEL_COSTS.items():
        if model_prefix in model.lower():
            costs = rates
            break

    if not costs:
        return None

    cost = (input_tokens / 1000 * costs[0]) + (output_tokens / 1000 * costs[1])
    return round(cost, 6)


def create_app(config_path: str = ".drako.yaml") -> Any:
    """Create the FastAPI proxy application."""
    try:
        from fastapi import FastAPI, Request, Response
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError:
        raise ImportError(
            "FastAPI is required for the proxy. Install with: "
            "pip install 'drako[proxy]'"
        )

    app = FastAPI(
        title="Drako Enforcement Proxy",
        version="2.0.0",
        description="Intercepts LLM API calls at the network layer for governance enforcement.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Shared state
    config = _load_config(config_path)
    session_state: dict[str, Any] = {}
    audit_log: list[dict[str, Any]] = []

    @app.get("/health")
    async def health():
        return {
            "status": "healthy",
            "governance_level": config.get("governance_level", "custom"),
            "targets": list(TARGETS.keys()),
            "audit_entries": len(audit_log),
        }

    @app.get("/status")
    async def status():
        return {
            "proxy": "drako-proxy",
            "version": "2.0.0",
            "config_loaded": bool(config),
            "governance_level": config.get("governance_level", "custom"),
            "targets": TARGETS,
            "session_stats": {
                k: len(v) if isinstance(v, list) else v
                for k, v in session_state.items()
            },
        }

    @app.get("/audit")
    async def get_audit():
        return {"entries": audit_log[-100:]}  # Last 100 entries

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy_handler(request: Request, path: str):
        import httpx

        start_time = time.time()

        # 1. Resolve target API
        try:
            target_url, stripped_path = _resolve_target(path)
        except ValueError:
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"[Drako] Unknown API target: {path}",
                        "type": "proxy_error",
                        "code": "drako_unknown_target",
                    }
                }),
                status_code=400,
                media_type="application/json",
            )

        # 2. Parse request body
        body_bytes = await request.body()
        body_dict: dict[str, Any] = {}
        if body_bytes:
            try:
                body_dict = json.loads(body_bytes)
            except json.JSONDecodeError:
                pass

        # 3. Extract governance context
        agent_id = request.headers.get("X-Drako-Agent")
        tool_name = _extract_tool_call(body_dict)
        model = body_dict.get("model", "unknown")

        # 4. Run governance pipeline
        # 4a. ODD check
        odd_result = _check_odd(agent_id, tool_name, config)
        if odd_result and odd_result["decision"] == "rejected":
            _log_audit(audit_log, agent_id, tool_name, model, "rejected",
                       odd_result["reason"], time.time() - start_time)
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"[Drako] Blocked: {odd_result['reason']}",
                        "type": "governance_violation",
                        "code": "drako_blocked",
                    }
                }),
                status_code=403,
                media_type="application/json",
            )

        # 4b. Magnitude check
        mag_result = _check_magnitude(agent_id, config, session_state)
        if mag_result and mag_result["decision"] == "rejected":
            _log_audit(audit_log, agent_id, tool_name, model, "rejected",
                       mag_result["reason"], time.time() - start_time)
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"[Drako] Blocked: {mag_result['reason']}",
                        "type": "governance_violation",
                        "code": "drako_rate_limited",
                    }
                }),
                status_code=429,
                media_type="application/json",
            )

        # 4c. DLP check
        dlp_result = _check_dlp(body_dict, config)
        if dlp_result and dlp_result["decision"] == "rejected":
            _log_audit(audit_log, agent_id, tool_name, model, "rejected",
                       dlp_result["reason"], time.time() - start_time)
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"[Drako] Blocked: {dlp_result['reason']}",
                        "type": "governance_violation",
                        "code": "drako_dlp",
                    }
                }),
                status_code=403,
                media_type="application/json",
            )

        # 4d. HITL check
        hitl_result = _check_hitl(tool_name, config)
        if hitl_result and hitl_result["decision"] == "pending_approval":
            _log_audit(audit_log, agent_id, tool_name, model, "pending_approval",
                       hitl_result["reason"], time.time() - start_time)
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"[Drako] Awaiting human approval. ID: {hitl_result['approval_id']}",
                        "type": "hitl_pending",
                        "code": "drako_hitl",
                    }
                }),
                status_code=202,
                media_type="application/json",
            )

        # 5. Forward to real API
        forward_url = f"{target_url}{stripped_path}"
        forward_headers = dict(request.headers)
        # Remove hop-by-hop headers
        for h in ("host", "x-drako-agent", "transfer-encoding"):
            forward_headers.pop(h, None)

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.request(
                    method=request.method,
                    url=forward_url,
                    headers=forward_headers,
                    content=body_bytes,
                )
        except httpx.ConnectError as exc:
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"[Drako] Upstream connection failed: {exc}",
                        "type": "proxy_error",
                        "code": "drako_upstream_error",
                    }
                }),
                status_code=502,
                media_type="application/json",
            )
        except httpx.ReadTimeout:
            return Response(
                content=json.dumps({
                    "error": {
                        "message": "[Drako] Upstream request timed out",
                        "type": "proxy_error",
                        "code": "drako_timeout",
                    }
                }),
                status_code=504,
                media_type="application/json",
            )

        # 6. Cost tracking
        elapsed = time.time() - start_time
        cost = None
        if response.status_code == 200:
            try:
                resp_json = response.json()
                cost = _estimate_cost(model, resp_json)
                if cost is not None:
                    cost_key = f"cost_{agent_id or 'unknown'}"
                    session_state[cost_key] = session_state.get(cost_key, 0.0) + cost
            except (json.JSONDecodeError, ValueError):
                pass

        # 7. Audit log
        _log_audit(audit_log, agent_id, tool_name, model, "allowed",
                   None, elapsed, cost=cost,
                   upstream_status=response.status_code)

        # 8. Return response
        resp_headers = dict(response.headers)
        resp_headers.pop("transfer-encoding", None)
        resp_headers.pop("content-encoding", None)
        resp_headers["X-Drako-Proxy"] = "true"
        resp_headers["X-Drako-Latency-Ms"] = str(int(elapsed * 1000))
        if cost is not None:
            resp_headers["X-Drako-Cost-USD"] = str(cost)

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=resp_headers,
            media_type=response.headers.get("content-type"),
        )

    return app


def _log_audit(
    audit_log: list,
    agent_id: str | None,
    tool_name: str | None,
    model: str,
    decision: str,
    reason: str | None,
    elapsed_seconds: float,
    cost: float | None = None,
    upstream_status: int | None = None,
) -> None:
    """Append an entry to the in-memory audit log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "tool_name": tool_name,
        "model": model,
        "decision": decision,
        "reason": reason,
        "latency_ms": round(elapsed_seconds * 1000, 1),
        "cost_usd": cost,
        "upstream_status": upstream_status,
    }
    audit_log.append(entry)

    # Keep max 10000 entries in memory
    if len(audit_log) > 10000:
        audit_log.pop(0)

    level = logging.WARNING if decision == "rejected" else logging.INFO
    logger.log(
        level,
        "[%s] agent=%s tool=%s model=%s reason=%s latency=%.1fms cost=$%s",
        decision.upper(), agent_id, tool_name, model, reason,
        elapsed_seconds * 1000, cost,
    )


def run_server(port: int = 8990, host: str = "0.0.0.0",
               config_path: str = ".drako.yaml") -> None:
    """Start the proxy server."""
    try:
        import uvicorn
    except ImportError:
        raise ImportError(
            "uvicorn is required for the proxy. Install with: "
            "pip install 'drako[proxy]'"
        )

    app = create_app(config_path)
    logger.info("Starting Drako Proxy on %s:%d", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")
