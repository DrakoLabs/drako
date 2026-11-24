"""CrewAI offline adapter over `drako.kernel.Host` (ADR-0009).

Wraps tool `_run` / `run` methods on each agent in a Crew through
`BaseAdapter.check_tool()`, replacing the retired v3 SaaS CrewAI middleware.
"""

from __future__ import annotations

from typing import Any

from drako.adapters.base import BaseAdapter
from drako.kernel.host import Host


class CrewAIAdapter(BaseAdapter):
    origin_prefix = "tool:crewai"

    def wrap_tool(self, tool: Any, *, side_effect_class: str = "write") -> Any:
        name = getattr(tool, "name", getattr(tool, "__name__", "crewai_tool"))
        if hasattr(tool, "_run") and callable(tool._run):
            orig = tool._run

            def guarded_run(*args: Any, **kwargs: Any) -> Any:
                arg_dict = dict(kwargs)
                if args:
                    arg_dict["_positional"] = list(args)
                final_args = self.check_tool(name, arg_dict, side_effect_class=side_effect_class)
                call_kwargs = {k: v for k, v in final_args.items() if k != "_positional"}
                call_args = tuple(final_args.get("_positional", args))
                return orig(*call_args, **call_kwargs)

            tool._run = guarded_run
            return tool
        if callable(tool):
            return self.wrap_callable(tool, tool_name=name, side_effect_class=side_effect_class)
        return tool

    def wrap_crew(self, crew: Any, *, side_effect_class: str = "write") -> Any:
        for agent in getattr(crew, "agents", []) or []:
            tools = getattr(agent, "tools", None)
            if isinstance(tools, list):
                agent.tools = [self.wrap_tool(t, side_effect_class=side_effect_class) for t in tools]
        return crew


def wrap_crew(crew: Any, host: Host, *, side_effect_class: str = "write") -> Any:
    """Wrap a CrewAI Crew's agent tools with offline Drako Authority Kernel enforcement."""
    return CrewAIAdapter(host, default_side_effect=side_effect_class).wrap_crew(
        crew, side_effect_class=side_effect_class
    )
