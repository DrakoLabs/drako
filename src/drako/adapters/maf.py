"""Microsoft Agent Framework (MAF) offline adapter over `drako.kernel.Host` (ADR-0009).

Targets MAF's Agent Hooks boundary (fail-closed pre-tool hook).
Honest boundary declaration (F-1): MAF Workflows orchestration graphs sit
outside the single-agent tool hook boundary unless each node invokes the
governed hook.
"""

from __future__ import annotations

from typing import Any, Callable

from drako.adapters.base import BaseAdapter
from drako.kernel.host import Host


class MAFAdapter(BaseAdapter):
    origin_prefix = "tool:maf-hook"

    def pre_tool_hook(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        side_effect_class: str = "write",
    ) -> dict[str, Any]:
        """Fail-closed pre-tool hook compatible with MAF Agent Hooks."""
        return self.check_tool(tool_name, dict(arguments or {}), side_effect_class=side_effect_class)

    def build_middleware(self, *, side_effect_class: str = "write") -> Callable[..., Any]:
        """Return an async MAF function-invocation middleware closure."""

        async def drako_maf_middleware(context: Any, next_call: Callable[..., Any]) -> Any:
            fn = getattr(context, "function", None)
            tool_name = getattr(fn, "name", None) or getattr(context, "tool_name", "maf_tool")
            raw_args = getattr(context, "arguments", {}) or {}
            args = dict(raw_args) if isinstance(raw_args, dict) else {"value": raw_args}
            final_args = self.check_tool(tool_name, args, side_effect_class=side_effect_class)
            if hasattr(context, "arguments") and isinstance(context.arguments, dict):
                context.arguments = final_args
            return await next_call(context)

        return drako_maf_middleware

    def wrap_agent(self, agent: Any, *, side_effect_class: str = "write") -> Any:
        mw = self.build_middleware(side_effect_class=side_effect_class)
        if hasattr(agent, "middleware") and isinstance(agent.middleware, list):
            agent.middleware.insert(0, mw)
        elif hasattr(agent, "add_hook") and callable(agent.add_hook):
            agent.add_hook("pre_tool_call", self.pre_tool_hook)
        elif hasattr(agent, "tools") and isinstance(agent.tools, list):
            agent.tools = [
                self.wrap_callable(t, side_effect_class=side_effect_class) if callable(t) else t
                for t in agent.tools
            ]
        return agent


def wrap_maf_agent(agent: Any, host: Host, *, side_effect_class: str = "write") -> Any:
    """Attach fail-closed Drako Authority Kernel hooks to a Microsoft Agent Framework agent."""
    return MAFAdapter(host, default_side_effect=side_effect_class).wrap_agent(
        agent, side_effect_class=side_effect_class
    )
