"""Hermetic tests for all 6 unified offline adapters over `drako.kernel.Host`."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from drako import govern
from drako.adapters.claude_agent import ClaudeAgentAdapter, wrap_claude_agent
from drako.adapters.crewai import wrap_crew
from drako.adapters.google_adk import wrap_adk_agent
from drako.adapters.maf import MAFAdapter, wrap_maf_agent
from drako.adapters.openai_agents import OpenAIAgentsAdapter
from drako.exceptions import PolicyViolationError
from drako.kernel import ACS_SPEC_PIN
from drako.kernel.envelope import Guardian
from drako.kernel.host import Host, HostConfig
from drako.kernel.receipts import generate_keypair, verify_receipt


def _make_host():
    priv, pub = generate_keypair()
    profile = {
        "spec_pin": ACS_SPEC_PIN,
        "default_effect": "deny",
        "tools": {
            "read_doc": {"id": "rule:read", "effect": "allow"},
            "sanitized_query": {
                "id": "rule:san",
                "effect": "modify",
                "modifications": {"limit": 10},
                "conditions": [{"id": "c-ok", "when": "limit == 10", "effect": "allow"}],
            },
            "drop_table": {"id": "rule:drop", "effect": "deny", "reason": "destructive"},
        },
    }
    host = Host(
        Guardian(profile),
        HostConfig(agent_id="adapter-test", private_pem=priv, public_pem=pub),
    )
    return host, pub


def test_openai_agents_adapter_permit_modify_deny():
    host, pub = _make_host()
    adapter = OpenAIAgentsAdapter(host)
    seen = []

    async def invoke_ok(_ctx, raw):
        seen.append(json.loads(raw))
        return "ok"

    t_allow = SimpleNamespace(name="read_doc", on_invoke_tool=invoke_ok)
    t_mod = SimpleNamespace(name="sanitized_query", on_invoke_tool=invoke_ok)
    t_deny = SimpleNamespace(name="drop_table", on_invoke_tool=invoke_ok)
    agent = SimpleNamespace(tools=[t_allow, t_mod, t_deny])

    adapter.wrap_agent(agent)
    assert asyncio.run(agent.tools[0].on_invoke_tool(None, json.dumps({"id": 1}))) == "ok"
    assert verify_receipt(adapter.last_receipt, pub)

    assert asyncio.run(agent.tools[1].on_invoke_tool(None, json.dumps({"limit": 999}))) == "ok"
    assert seen[-1]["limit"] == 10  # modified & re-governed!

    with pytest.raises(PolicyViolationError):
        asyncio.run(agent.tools[2].on_invoke_tool(None, json.dumps({"table": "users"})))


def test_maf_adapter_middleware_and_hook():
    host, pub = _make_host()
    adapter = MAFAdapter(host)

    # Pre-tool hook
    assert adapter.pre_tool_hook("read_doc", {"k": "v"}) == {"k": "v"}
    assert verify_receipt(adapter.last_receipt, pub)
    with pytest.raises(PolicyViolationError):
        adapter.pre_tool_hook("drop_table", {})

    # Async middleware
    agent = SimpleNamespace(middleware=[])
    wrap_maf_agent(agent, host)
    assert len(agent.middleware) == 1
    ctx = SimpleNamespace(function=SimpleNamespace(name="sanitized_query"), arguments={"limit": 500})

    async def next_call(c):
        return c.arguments

    result = asyncio.run(agent.middleware[0](ctx, next_call))
    assert result["limit"] == 10


def test_claude_agent_adapter_pre_tool_use_hook():
    host, pub = _make_host()
    adapter = ClaudeAgentAdapter(host)

    res_ok = adapter.pre_tool_use_hook({"tool_name": "sanitized_query", "tool_input": {"limit": 500}})
    assert res_ok["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert res_ok["hookSpecificOutput"]["updatedInput"]["limit"] == 10
    assert verify_receipt(adapter.last_receipt, pub)

    res_deny = adapter.pre_tool_use_hook({"tool_name": "drop_table", "tool_input": {}})
    assert res_deny["hookSpecificOutput"]["permissionDecision"] == "deny"

    opts = wrap_claude_agent({}, host)
    assert len(opts["hooks"]["PreToolUse"]) == 1


def test_google_adk_adapter_before_tool_callback():
    host, pub = _make_host()
    agent = SimpleNamespace(before_tool_callback=None)
    wrap_adk_agent(agent, host)

    args_ok = {"limit": 999}
    assert agent.before_tool_callback(SimpleNamespace(name="sanitized_query"), args_ok, None) is None
    assert args_ok["limit"] == 10  # mutated in-place post re-govern

    denied = agent.before_tool_callback(SimpleNamespace(name="drop_table"), {}, None)
    assert isinstance(denied, dict) and "error" in denied


def test_crewai_adapter_and_govern_dispatch():
    host, pub = _make_host()

    class FakeTool:
        def __init__(self, name):
            self.name = name

        def _run(self, **kwargs):
            return kwargs

    t_ok = FakeTool("read_doc")
    t_deny = FakeTool("drop_table")
    crew = SimpleNamespace(agents=[SimpleNamespace(tools=[t_ok, t_deny])])
    wrap_crew(crew, host)

    assert t_ok._run(q="hello") == {"q": "hello"}
    with pytest.raises(PolicyViolationError):
        t_deny._run(table="prod")

    # Plain callable via drako.govern()
    def read_doc(q: str) -> str:
        return q.upper()

    wrapped = govern(read_doc, host=host)
    assert wrapped(q="hi") == "HI"
