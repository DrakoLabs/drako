"""OpenAI Agents SDK offline adapter over `drako.kernel.Host` (ADR-0009).

Wraps function tools (`tool.on_invoke_tool` or callable) and agent tool lists
through `BaseAdapter.check_tool()`, minting Ed25519 receipts offline.
"""

from __future__ import annotations

import json
from typing import Any

from drako.adapters.base import BaseAdapter
from drako.kernel.host import Host


class OpenAIAgentsAdapter(BaseAdapter):
    origin_prefix = "tool:openai-agents"

    def wrap_tool(self, tool: Any, *, side_effect_class: str = "write") -> Any:
        name = getattr(tool, "name", getattr(tool, "__name__", "openai_tool"))

        if hasattr(tool, "on_invoke_tool") and callable(tool.on_invoke_tool):
            orig = tool.on_invoke_tool

            async def guarded_invoke(ctx: Any, input_json: str) -> Any:
                try:
                    parsed = json.loads(input_json) if isinstance(input_json, str) else dict(input_json or {})
                except (ValueError, TypeError):
                    parsed = {"raw": str(input_json)}
                final_args = self.check_tool(name, parsed, side_effect_class=side_effect_class)
                return await orig(ctx, json.dumps(final_args))

            tool.on_invoke_tool = guarded_invoke
            return tool

        if callable(tool):
            return self.wrap_callable(tool, tool_name=name, side_effect_class=side_effect_class)
        return tool

    def wrap_agent(self, agent: Any, *, side_effect_class: str = "write") -> Any:
        tools = getattr(agent, "tools", None)
        if isinstance(tools, list):
            agent.tools = [self.wrap_tool(t, side_effect_class=side_effect_class) for t in tools]
        return agent


def wrap_openai_agent(agent: Any, host: Host, *, side_effect_class: str = "write") -> Any:
    """Wrap an OpenAI Agents SDK Agent (or tool list) with Drako Host governance."""
    return OpenAIAgentsAdapter(host, default_side_effect=side_effect_class).wrap_agent(
        agent, side_effect_class=side_effect_class
    )
