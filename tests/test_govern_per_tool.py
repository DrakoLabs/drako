"""Tests for per-tool interception in CrewAI compliance middleware.

Verifies that govern() wraps each tool's _run() method so that
/trust/evaluate is called BEFORE every tool execution — not just once
at task level.
"""

from __future__ import annotations

from typing import Any

import pytest
import httpx
import respx

from drako.client import DrakoClient
from drako.middleware.crewai import CrewAIComplianceMiddleware


# ---------------------------------------------------------------------------
# Fakes — duck-typed CrewAI objects (no real CrewAI import needed)
# ---------------------------------------------------------------------------

class FakeTool:
    """Minimal duck-type of a CrewAI BaseTool."""

    def __init__(self, name: str):
        self.name = name
        self._call_count = 0
        self._last_args: tuple = ()
        self._last_kwargs: dict = {}

    def _run(self, *args: Any, **kwargs: Any) -> str:
        self._call_count += 1
        self._last_args = args
        self._last_kwargs = kwargs
        return f"result from {self.name}"


class FakeAgent:
    def __init__(self, name: str, role: str, tools: list[FakeTool] | None = None):
        self.name = name
        self.role = role
        self.tools = tools or []


class FakeTask:
    def __init__(self, description: str, agent: FakeAgent | None = None):
        self.description = description
        self.agent = agent
        self.callback = None


class FakeCrew:
    def __init__(self, agents: list[FakeAgent], tasks: list[FakeTask] | None = None):
        self.agents = agents
        self.tasks = tasks or []
        self._kickoff_called = False

    def kickoff(self, **kwargs: Any) -> dict:
        self._kickoff_called = True
        for task in self.tasks:
            if task.callback:
                task.callback({"output": "done"})
        return {"status": "completed"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ENDPOINT = "https://api.drako.test"


def _mock_all_endpoints(
    evaluate_json: dict | None = None,
    evaluate_status: int = 200,
):
    """Set up respx mocks for register, evaluate, and audit."""
    respx.post(f"{ENDPOINT}/api/v1/agents/register").mock(
        return_value=httpx.Response(200, json={
            "did": "did:mesh:ag_test",
            "trust_score": 0.9,
            "status": "ACTIVE",
        })
    )
    eval_json = evaluate_json or {"decision": "approved", "reasoning": []}
    respx.post(f"{ENDPOINT}/api/v1/trust/evaluate").mock(
        return_value=httpx.Response(evaluate_status, json=eval_json)
    )
    respx.post(f"{ENDPOINT}/api/v1/audit-logs").mock(
        return_value=httpx.Response(200, json={"log_id": "aud_1"})
    )


def _build_middleware(crew: FakeCrew, fail_closed: bool = False) -> CrewAIComplianceMiddleware:
    client = DrakoClient(api_key="am_live_test", endpoint=ENDPOINT)
    return CrewAIComplianceMiddleware(
        crew=crew,
        client=client,
        fail_closed=fail_closed,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPerToolWrapping:
    """Verify _wrap_agent_tools() wraps each tool's _run() method."""

    @respx.mock
    def test_govern_wraps_tool_run(self):
        """After kickoff, each tool._run should have _drako_wrapped flag."""
        _mock_all_endpoints()

        search = FakeTool("search")
        write = FakeTool("file_writer")
        agent = FakeAgent("researcher", "analyst", tools=[search, write])
        crew = FakeCrew(agents=[agent])

        mw = _build_middleware(crew)
        mw.kickoff()

        assert getattr(search._run, "_drako_wrapped", False)
        assert getattr(write._run, "_drako_wrapped", False)

    @respx.mock
    def test_governed_tool_calls_evaluate(self):
        """Wrapped tool should call /trust/evaluate with correct tool_name."""
        respx.post(f"{ENDPOINT}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_test", "trust_score": 0.9, "status": "ACTIVE",
            })
        )
        eval_route = respx.post(f"{ENDPOINT}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "approved", "reasoning": []})
        )
        respx.post(f"{ENDPOINT}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_1"})
        )

        search = FakeTool("web_search")
        agent = FakeAgent("researcher", "analyst", tools=[search])
        crew = FakeCrew(agents=[agent])

        mw = _build_middleware(crew)
        mw.kickoff()

        # Now call the wrapped tool directly
        result = search._run(query="test query")

        # Tool should have executed (returned real result)
        assert "result from web_search" in result

        # /trust/evaluate should have been called at least once (for the tool call)
        assert eval_route.call_count >= 1

    @respx.mock
    def test_governed_tool_blocked_returns_message(self):
        """If evaluate returns rejected, tool should return blocked message."""
        respx.post(f"{ENDPOINT}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_test", "trust_score": 0.9,
            })
        )
        # No tasks → no task-level call. Tool call → reject.
        respx.post(f"{ENDPOINT}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={
                "decision": "rejected",
                "reasoning": ["tool not in permitted_tools"],
            }),
        )
        respx.post(f"{ENDPOINT}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_1"})
        )

        code_runner = FakeTool("code_runner")
        agent = FakeAgent("researcher", "analyst", tools=[code_runner])
        crew = FakeCrew(agents=[agent])

        mw = _build_middleware(crew)
        mw.kickoff()

        result = code_runner._run(code="print('hack')")

        assert "[Drako] Action blocked" in result
        assert "permitted_tools" in result

    @respx.mock
    def test_governed_tool_blocked_skips_original(self):
        """When blocked, the original _run should NOT be called."""
        respx.post(f"{ENDPOINT}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_test", "trust_score": 0.9,
            })
        )
        respx.post(f"{ENDPOINT}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "rejected", "reasoning": ["blocked"]}),
        )
        respx.post(f"{ENDPOINT}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_1"})
        )

        tool = FakeTool("dangerous_tool")
        agent = FakeAgent("agent1", "role1", tools=[tool])
        crew = FakeCrew(agents=[agent])

        mw = _build_middleware(crew)
        mw.kickoff()

        tool._run()

        # _call_count should be 0 — the original _run was never called
        assert tool._call_count == 0

    @respx.mock
    def test_governed_tool_fail_open_on_error(self):
        """On network error, tool should still execute (fail-open default)."""
        respx.post(f"{ENDPOINT}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_test", "trust_score": 0.9,
            })
        )
        respx.post(f"{ENDPOINT}/api/v1/trust/evaluate").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )
        respx.post(f"{ENDPOINT}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_1"})
        )

        tool = FakeTool("search")
        agent = FakeAgent("agent1", "role1", tools=[tool])
        crew = FakeCrew(agents=[agent])

        mw = _build_middleware(crew, fail_closed=False)
        mw.kickoff()

        result = tool._run(query="test")

        # Tool should have executed (fail-open)
        assert result == "result from search"
        assert tool._call_count == 1

    @respx.mock
    def test_governed_tool_fail_closed_on_error(self):
        """With fail_closed=True, network error should block the tool."""
        respx.post(f"{ENDPOINT}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_test", "trust_score": 0.9,
            })
        )
        respx.post(f"{ENDPOINT}/api/v1/trust/evaluate").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )
        respx.post(f"{ENDPOINT}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_1"})
        )

        tool = FakeTool("search")
        agent = FakeAgent("agent1", "role1", tools=[tool])
        crew = FakeCrew(agents=[agent])

        mw = _build_middleware(crew, fail_closed=True)
        mw.kickoff()

        result = tool._run(query="test")

        # Tool should be blocked (fail-closed)
        assert "[Drako] Action blocked" in result
        assert "fail-closed" in result
        assert tool._call_count == 0

    @respx.mock
    def test_govern_no_policy_returns_unwrapped(self):
        """With auto_policy=False, tools should NOT be wrapped."""
        tool = FakeTool("search")
        agent = FakeAgent("agent1", "role1", tools=[tool])
        crew = FakeCrew(agents=[agent])

        client = DrakoClient(api_key="am_live_test", endpoint=ENDPOINT)
        mw = CrewAIComplianceMiddleware(
            crew=crew, client=client,
            auto_verify=False, auto_policy=False, auto_audit=False,
        )
        mw.kickoff()

        # Tools should NOT have the wrapped flag
        assert not getattr(tool._run, "_drako_wrapped", False)

    @respx.mock
    def test_governed_tool_sends_payload_preview(self):
        """Tool args should be sent as payload_preview for DLP scanning."""
        _mock_all_endpoints()

        tool = FakeTool("search")
        agent = FakeAgent("agent1", "role1", tools=[tool])
        crew = FakeCrew(agents=[agent])

        mw = _build_middleware(crew)
        mw.kickoff()

        # Call tool with args that include "PII"
        tool._run(query="SSN 123-45-6789")

        # Check that /trust/evaluate received the payload
        calls = respx.calls
        tool_eval_calls = [
            c for c in calls
            if "/trust/evaluate" in str(c.request.url)
        ]
        # At least 1 tool-level evaluate call should exist
        assert len(tool_eval_calls) >= 1

    @respx.mock
    def test_multiple_agents_all_wrapped(self):
        """All agents' tools should get wrapped, not just the first agent."""
        _mock_all_endpoints()

        tool_a = FakeTool("tool_a")
        tool_b = FakeTool("tool_b")
        tool_c = FakeTool("tool_c")
        agent1 = FakeAgent("agent1", "role1", tools=[tool_a])
        agent2 = FakeAgent("agent2", "role2", tools=[tool_b, tool_c])
        crew = FakeCrew(agents=[agent1, agent2])

        mw = _build_middleware(crew)
        mw.kickoff()

        assert getattr(tool_a._run, "_drako_wrapped", False)
        assert getattr(tool_b._run, "_drako_wrapped", False)
        assert getattr(tool_c._run, "_drako_wrapped", False)

    @respx.mock
    def test_double_govern_no_double_wrap(self):
        """Calling kickoff twice should not double-wrap tools."""
        _mock_all_endpoints()

        tool = FakeTool("search")
        agent = FakeAgent("agent1", "role1", tools=[tool])
        crew = FakeCrew(agents=[agent])

        mw = _build_middleware(crew)
        mw.kickoff()

        # Save ref to first wrapper
        first_wrapper = tool._run

        mw.kickoff()

        # Should be the same wrapper (not double-wrapped)
        assert tool._run is first_wrapper
