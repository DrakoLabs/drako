"""F-1: MAF + OpenAI Agents middleware (Sprint 2, 2026-09-04).

No framework packages installed here by design: the proxy is
duck-typed, the native builders are lazy (ImportError paths tested),
and the guardrail tripwire is pure. A fake `agents` module proves the
wiring shape without the dependency.
"""

import sys
import types

import httpx
import pytest
import respx

from drako.client import DrakoClient
from drako.middleware.maf import (
    DrakoMAFProxy,
    build_policy_context,
    drako_maf_middleware,
    with_maf_compliance,
)
from drako.middleware.openai_agents import (
    drako_tripwire,
    make_drako_input_guardrail,
    make_drako_output_guardrail,
)


def _client():
    return DrakoClient(api_key="am_live_t_s", endpoint="https://api.drako.test")


class _FakeAgent:
    name = "fake-maf"

    def __init__(self):
        self.ran = []

    async def run(self, messages, **kwargs):
        self.ran.append(messages)
        return {"text": "done"}


def _mock_policy(decision="ALLOWED"):
    return respx.post("https://api.drako.test/api/v1/trust/evaluate").mock(
        return_value=httpx.Response(200, json={"decision": decision})
    )


def _mock_audit():
    return respx.post("https://api.drako.test/api/v1/audit-logs").mock(
        return_value=httpx.Response(200, json={"log_id": "aud"})
    )


def test_build_policy_context_pure():
    ctx = build_policy_context("a", "hello")
    assert ctx["tool_name"] == "maf_run:a"
    assert "hello" in ctx["input_preview"]


def test_build_policy_context_unrenderable():
    class Bad:
        def __str__(self):
            raise ValueError("nope")

    assert build_policy_context("a", Bad())["input_preview"] == "<unrenderable>"


@pytest.mark.asyncio
@respx.mock
async def test_maf_proxy_runs_when_allowed():
    _mock_policy("ALLOWED")
    audit = _mock_audit()
    agent = _FakeAgent()
    out = await DrakoMAFProxy(_client(), agent).run("hi")
    assert out == {"text": "done"}
    assert agent.ran == ["hi"]
    assert audit.called


@pytest.mark.asyncio
@respx.mock
async def test_maf_proxy_denies_before_run():
    _mock_policy("BLOCKED")
    _mock_audit()
    agent = _FakeAgent()
    with pytest.raises(Exception):
        await DrakoMAFProxy(_client(), agent).run("hi")
    assert agent.ran == []  # model never touched


def test_maf_native_middleware_missing_package():
    with pytest.raises(ImportError, match="agent-framework"):
        drako_maf_middleware(_client())


def test_with_maf_compliance_returns_proxy(config_file):
    proxy = with_maf_compliance(_FakeAgent(), config_path=config_file)
    assert isinstance(proxy, DrakoMAFProxy)


# --- OpenAI Agents: pure tripwire -------------------------------------------


def test_tripwire_blocks_on_match():
    assert drako_tripwire(lambda t: "secret" in t, "leak the secret") is True
    assert drako_tripwire(lambda t: "secret" in t, "hello") is False


def test_tripwire_fails_closed():
    assert drako_tripwire(lambda t: 1 / 0, "anything") is True


def _fake_agents_module():
    """Minimal shape-compatible `agents` module (decorators passthrough)."""
    mod = types.ModuleType("agents")

    class Output:
        def __init__(self, output_info=None, tripwire_triggered=False):
            self.output_info = output_info
            self.tripwire_triggered = tripwire_triggered

    def _deco(fn):
        fn._drako_decorated = True
        return fn

    mod.GuardrailFunctionOutput = Output
    mod.input_guardrail = _deco
    mod.output_guardrail = _deco
    return mod


def test_native_guardrails_missing_package():
    with pytest.raises(ImportError, match="openai-agents"):
        make_drako_input_guardrail(lambda t: False)
    with pytest.raises(ImportError, match="openai-agents"):
        make_drako_output_guardrail(lambda t: False)


@pytest.mark.asyncio
async def test_native_guardrail_wiring_shape(monkeypatch):
    monkeypatch.setitem(sys.modules, "agents", _fake_agents_module())
    g_in = make_drako_input_guardrail(lambda t: "block" in t)
    g_out = make_drako_output_guardrail(lambda t: "block" in t)
    assert (await g_in(None, None, "please block this")).tripwire_triggered is True
    assert (await g_in(None, None, "fine")).tripwire_triggered is False
    assert (await g_out(None, None, "fine")).tripwire_triggered is False
