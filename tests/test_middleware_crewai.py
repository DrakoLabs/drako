"""Tests for the CrewAI compliance middleware."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from typing import Any

import pytest
import httpx
import respx

from drako.client import DrakoClient
from drako.exceptions import PolicyViolationError
from drako.middleware.crewai import CrewAIComplianceMiddleware


# ---------------------------------------------------------------------------
# Helpers — fake CrewAI objects
# ---------------------------------------------------------------------------

class FakeAgent:
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role


class FakeTask:
    def __init__(self, description: str, agent: FakeAgent | None = None):
        self.description = description
        self.agent = agent
        self.callback = None


class FakeCrew:
    def __init__(self, agents: list[FakeAgent], tasks: list[FakeTask]):
        self.agents = agents
        self.tasks = tasks
        self._kickoff_called = False

    def kickoff(self, **kwargs: Any) -> dict:
        self._kickoff_called = True
        # Simulate running tasks and calling callbacks
        for task in self.tasks:
            if task.callback:
                task.callback({"output": f"Result of {task.description}"})
        return {"status": "completed", "tasks_completed": len(self.tasks)}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCrewAIMiddleware:
    @respx.mock
    def test_kickoff_verifies_agents(self):
        endpoint = "https://api.drako.test"
        # Mock verify identity for each agent
        respx.post(f"{endpoint}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_test",
                "trust_score": 0.9,
                "status": "ACTIVE",
            })
        )
        # Mock policy evaluation
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "ALLOWED"})
        )
        # Mock audit log
        respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_1"})
        )

        agents = [FakeAgent("researcher", "data_analyst"), FakeAgent("writer", "content_creator")]
        tasks = [
            FakeTask("Research market trends", agents[0]),
            FakeTask("Write report", agents[1]),
        ]
        crew = FakeCrew(agents=agents, tasks=tasks)

        client = DrakoClient(api_key="am_live_t_s", endpoint=endpoint)
        mw = CrewAIComplianceMiddleware(crew=crew, client=client)
        result = mw.kickoff()

        assert result["status"] == "completed"
        assert crew._kickoff_called

    @respx.mock
    def test_kickoff_blocks_on_policy_violation(self):
        endpoint = "https://api.drako.test"
        respx.post(f"{endpoint}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_1",
                "trust_score": 0.9,
            })
        )
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(403, json={
                "detail": "Action blocked",
                "policy_id": "pol_block",
            })
        )

        agents = [FakeAgent("agent1", "role1")]
        tasks = [FakeTask("Dangerous action", agents[0])]
        crew = FakeCrew(agents=agents, tasks=tasks)

        client = DrakoClient(api_key="am_live_t_s", endpoint=endpoint)
        mw = CrewAIComplianceMiddleware(crew=crew, client=client)

        with pytest.raises(PolicyViolationError):
            mw.kickoff()

    @respx.mock
    def test_kickoff_records_audit_logs(self):
        endpoint = "https://api.drako.test"
        respx.post(f"{endpoint}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={"did": "did:mesh:ag_1", "trust_score": 0.9})
        )
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "ALLOWED"})
        )
        audit_route = respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_1"})
        )

        agent = FakeAgent("worker", "executor")
        task = FakeTask("Process data", agent)
        crew = FakeCrew(agents=[agent], tasks=[task])

        client = DrakoClient(api_key="am_live_t_s", endpoint=endpoint)
        mw = CrewAIComplianceMiddleware(crew=crew, client=client)
        mw.kickoff()

        assert audit_route.called

    @respx.mock
    def test_proxy_passthrough(self):
        endpoint = "https://api.drako.test"
        agent = FakeAgent("a", "r")
        task = FakeTask("t", agent)
        crew = FakeCrew(agents=[agent], tasks=[task])
        crew.custom_attr = "custom_value"

        client = DrakoClient(api_key="am_live_t_s", endpoint=endpoint)
        mw = CrewAIComplianceMiddleware(crew=crew, client=client, auto_verify=False, auto_policy=False, auto_audit=False)

        # __getattr__ should proxy to crew
        assert mw.custom_attr == "custom_value"
        assert mw.agents == [agent]

    @respx.mock
    def test_kickoff_without_auto_features(self):
        endpoint = "https://api.drako.test"
        agent = FakeAgent("a", "r")
        task = FakeTask("t", agent)
        crew = FakeCrew(agents=[agent], tasks=[task])

        client = DrakoClient(api_key="am_live_t_s", endpoint=endpoint)
        mw = CrewAIComplianceMiddleware(
            crew=crew, client=client,
            auto_verify=False, auto_policy=False, auto_audit=False,
        )
        result = mw.kickoff()
        assert result["status"] == "completed"


class TestCrewAIMiddlewareAsync:
    @respx.mock
    @pytest.mark.asyncio
    async def test_akickoff(self):
        endpoint = "https://api.drako.test"
        respx.post(f"{endpoint}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={"did": "did:mesh:ag_a", "trust_score": 0.8})
        )
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={"decision": "ALLOWED"})
        )
        respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_a"})
        )

        agent = FakeAgent("async_agent", "tester")
        task = FakeTask("Async task", agent)
        crew = FakeCrew(agents=[agent], tasks=[task])

        client = DrakoClient(api_key="am_live_t_s", endpoint=endpoint)
        mw = CrewAIComplianceMiddleware(crew=crew, client=client)
        result = await mw.akickoff()

        assert result["status"] == "completed"
        await client.close()
