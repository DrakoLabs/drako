"""Test utilities for Drako governance in CI/CD pipelines.

Provides ``test_mode()`` and ``MockHITLResolver`` so governance middleware
never blocks automated test runs.  All operations are fully offline — no
backend connection required.

Quick start::

    import drako

    with drako.test_mode(hitl="auto-approve"):
        crew = drako.govern(crew)
        result = crew.kickoff()  # HITL won't block

Environment variables::

    DRAKO_TEST_MODE=true      — govern() auto-uses audit enforcement
    DRAKO_HITL_DEFAULT=approve — default HITL resolution in test mode
"""

from __future__ import annotations

import contextlib
import os
import time
import uuid
from typing import Any, Dict, Optional, Union
from unittest.mock import patch


class MockHITLResolver:
    """Pluggable HITL resolver for test environments.

    Usage::

        resolver = MockHITLResolver(
            default_action="approve",
            rules={
                "delete_records": "deny",
                "transfer_funds": "approve",
            },
        )
        with drako.test_mode(hitl=resolver):
            crew = drako.govern(crew)
            result = crew.kickoff()
    """

    def __init__(
        self,
        default_action: str = "approve",
        rules: Dict[str, str] | None = None,
    ) -> None:
        if default_action not in ("approve", "deny"):
            raise ValueError(f"default_action must be 'approve' or 'deny', got '{default_action}'")
        self.default_action = default_action
        self.rules: Dict[str, str] = rules or {}
        self.call_log: list[Dict[str, Any]] = []

    def resolve(
        self,
        tool_name: str,
        agent_id: str = "",
        context: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Return an immediate HITL decision for *tool_name*."""
        action = self.rules.get(tool_name, self.default_action)
        decision = "allowed" if action == "approve" else "rejected"
        entry = {
            "tool_name": tool_name,
            "agent_id": agent_id,
            "decision": decision,
            "resolved_at": time.time(),
        }
        self.call_log.append(entry)
        return {"decision": decision, "reason": f"test_mode:{action}"}


# ---------------------------------------------------------------------------
# Mock client that replaces DrakoClient during test_mode
# ---------------------------------------------------------------------------

def _build_mock_evaluate(hitl_setting: Union[str, MockHITLResolver], dlp: str, enforcement: str):
    """Return a replacement for ``DrakoClient.evaluate_policy`` / ``evaluate_policy_sync``."""

    def _resolve_hitl(tool_name: str, agent_id: str) -> Dict[str, Any]:
        if isinstance(hitl_setting, MockHITLResolver):
            return hitl_setting.resolve(tool_name, agent_id)
        if hitl_setting == "auto-approve":
            return {"decision": "allowed", "reason": "test_mode:auto-approve"}
        if hitl_setting == "auto-deny":
            return {"decision": "rejected", "reason": "test_mode:auto-deny"}
        # "skip" → no HITL evaluation at all
        return {"decision": "allowed", "reason": "test_mode:skip"}

    async def mock_evaluate_policy(self, *, agent_id="", tool_name="", **kwargs):
        hitl = _resolve_hitl(tool_name, agent_id)
        decision = hitl["decision"]
        return {
            "request_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "decision": decision,
            "trust_score": 0.85,
            "reasoning": [f"test_mode: {hitl['reason']}"],
            "policy_version": "test",
            "audit_hash": "0" * 64,
            "evaluated_at": time.time(),
        }

    def mock_evaluate_policy_sync(self, *, agent_id="", tool_name="", **kwargs):
        hitl = _resolve_hitl(tool_name, agent_id)
        decision = hitl["decision"]
        return {
            "request_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "decision": decision,
            "trust_score": 0.85,
            "reasoning": [f"test_mode: {hitl['reason']}"],
            "policy_version": "test",
            "audit_hash": "0" * 64,
            "evaluated_at": time.time(),
        }

    return mock_evaluate_policy, mock_evaluate_policy_sync


def _noop_async(self, *args, **kwargs):
    """No-op coroutine for methods that should be silenced in test mode."""
    import asyncio
    f = asyncio.get_event_loop().create_future()
    f.set_result({})
    return f


def _noop_sync(self, *args, **kwargs):
    """No-op sync stub."""
    return {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def test_mode(
    hitl: Union[str, MockHITLResolver] = "auto-approve",
    dlp: str = "audit",
    enforcement: str = "audit",
):
    """Context manager for testing governed agents without blocking.

    Args:
        hitl: ``"auto-approve"`` | ``"auto-deny"`` | ``"skip"`` or a
              :class:`MockHITLResolver` instance for per-tool rules.
        dlp: ``"audit"`` (log but don't block) | ``"off"``
        enforcement: ``"audit"`` (log but don't block) | ``"off"``
    """
    if isinstance(hitl, str) and hitl not in ("auto-approve", "auto-deny", "skip"):
        raise ValueError(f"hitl must be 'auto-approve', 'auto-deny', 'skip', or MockHITLResolver, got '{hitl}'")

    mock_eval, mock_eval_sync = _build_mock_evaluate(hitl, dlp, enforcement)

    patches = [
        patch("drako.client.DrakoClient.evaluate_policy", mock_eval),
        patch("drako.client.DrakoClient.evaluate_policy_sync", mock_eval_sync),
        patch("drako.client.DrakoClient.audit_log", _noop_async),
        patch("drako.client.DrakoClient.audit_log_sync", _noop_sync),
        patch("drako.client.DrakoClient.execute_hooks", _noop_async),
        patch("drako.client.DrakoClient.execute_hooks_sync", _noop_sync),
        patch("drako.client.DrakoClient.verify_chain", _noop_async),
        patch("drako.client.DrakoClient.verify_chain_sync", _noop_sync),
    ]

    old_env: Dict[str, Optional[str]] = {}
    env_vars = {
        "DRAKO_TEST_MODE": "true",
    }

    # Save and set env vars
    for key, value in env_vars.items():
        old_env[key] = os.environ.get(key)
        os.environ[key] = value

    started = []
    try:
        for p in patches:
            p.start()
            started.append(p)
        yield
    finally:
        for p in reversed(started):
            p.stop()
        # Restore env vars
        for key, old_value in old_env.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value


def is_test_mode() -> bool:
    """Return ``True`` if ``DRAKO_TEST_MODE`` env var is set to a truthy value."""
    return os.environ.get("DRAKO_TEST_MODE", "").lower() in ("true", "1", "yes")


def get_hitl_default() -> str:
    """Return the default HITL action from env, or ``"approve"``."""
    return os.environ.get("DRAKO_HITL_DEFAULT", "approve")
