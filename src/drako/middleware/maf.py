"""Microsoft Agent Framework compliance wrapper (F-1, Sprint 2).

Verified against agent_framework 1.0 GA (2026-04-03): Agent.run(messages,
middleware=[...]) accepts per-run middleware; framework-native middleware
shapes are AgentMiddleware/FunctionMiddleware/ChatMiddleware with
`process(context, call_next)`; termination via MiddlewareTermination.
This module never imports agent_framework at top level (it is an
optional dependency): the native middleware is built lazily, and
run-governance works duck-typed so it is testable without the package.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from drako.client import DrakoClient
from drako.middleware.base import ComplianceMiddleware


def build_policy_context(agent_name: str, messages: Any) -> dict[str, Any]:
    """Pure shaping (testable): MAF run inputs → policy context."""
    try:
        text = messages if isinstance(messages, str) else str(messages)
    except Exception:
        text = "<unrenderable>"
    return {"tool_name": f"maf_run:{agent_name}", "scope": "default",
            "input_preview": text[:500]}


class DrakoMAFProxy(ComplianceMiddleware):
    """Duck-typed governed run for an agent_framework Agent.

    Policy-gates before delegating to agent.run, audits after. Works
    with any object exposing an async run() (real Agent or test double)
    — no framework import required.
    """

    def __init__(self, client: DrakoClient, agent: Any,
                 agent_name: str = "maf-agent",
                 auto_audit: bool = True, auto_policy: bool = True):
        super().__init__(client=client, auto_audit=auto_audit,
                         auto_verify=False, auto_policy=auto_policy)
        self._agent = agent
        self._agent_name = getattr(agent, "name", agent_name) or agent_name

    async def run(self, messages: Any, **kwargs: Any) -> Any:
        """Policy-gated run: deny raises before the model is touched."""
        context = build_policy_context(self._agent_name, messages)
        if self._auto_policy:
            await self._check_policy_async(f"maf_run:{self._agent_name}",
                                           self._agent_name, context=context)
        result = await self._agent.run(messages, **kwargs)
        if self._auto_audit:
            try:
                await self._record_audit_async(
                    f"maf_run:{self._agent_name}", self._agent_name,
                    {"input_preview": context["input_preview"]})
            except Exception:
                pass
        return result


def drako_maf_middleware(client: DrakoClient):
    """Build a NATIVE agent_framework FunctionMiddleware (lazy import).

    Policy-checks every tool call; a deny terminates the chain via the
    framework's own MiddlewareTermination. Raises an informative
    ImportError when agent_framework is not installed — install the
    framework extra instead of silently running ungoverned.
    """
    try:
        from agent_framework import FunctionMiddleware, MiddlewareTermination
    except ImportError:
        raise ImportError(
            "drako[maf] requires the 'agent-framework' package "
            "(pip install agent-framework) — refusing to run ungoverned"
        )

    class _DrakoFunctionMiddleware(FunctionMiddleware):
        async def process(self, context: Any,
                          call_next: Callable[[], Awaitable[None]]) -> None:
            fn = getattr(getattr(context, "function", None), "name", "unknown")
            decision = await client.evaluate_policy(
                action=f"maf_tool:{fn}", agent_did="maf-agent",
                context={"tool_name": fn, "scope": "default"},
            )
            allowed = decision.get("decision", decision.get("allowed", True))
            # Same denial set as ComplianceMiddleware._check_policy.
            if allowed in (False, "BLOCKED", "rejected"):
                raise MiddlewareTermination(f"drako denied tool call: {fn}")
            await call_next()
            try:
                await client.audit_log(
                    action=f"maf_tool:{fn}", agent_did="maf-agent",
                    result={"result_preview": str(getattr(context, "result", ""))[:500]},
                )
            except Exception:
                pass

    return _DrakoFunctionMiddleware()


def with_maf_compliance(agent: Any, config_path: str = ".drako.yaml",
                        auto_audit: bool = True,
                        auto_policy: bool = True) -> DrakoMAFProxy:
    """Wrap an agent_framework Agent with governance.

    Usage::

        from drako.middleware.maf import with_maf_compliance
        governed = with_maf_compliance(my_agent)
        result = await governed.run("hello")
    """
    from drako.client import DrakoClient as _Client

    client = _Client.from_config(config_path)
    return DrakoMAFProxy(client=client, agent=agent,
                         auto_audit=auto_audit, auto_policy=auto_policy)
