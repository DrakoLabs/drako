"""Google ADK (Agent Development Kit) offline adapter over `drako.kernel.Host` (ADR-0009).

Implements Google ADK's `before_tool_callback(tool, args, tool_context)`
contract: returns `None` to allow execution (updating `args` in-place on
`modify`) or returns an error dict to short-circuit and deny the tool call.
"""

from __future__ import annotations

from typing import Any

from drako.adapters.base import BaseAdapter, govern_with_remodify
from drako.kernel.host import Host


class GoogleADKAdapter(BaseAdapter):
    origin_prefix = "tool:google-adk"

    def before_tool_callback(
        self,
        tool: Any,
        args: dict[str, Any],
        tool_context: Any = None,
        *,
        side_effect_class: str = "write",
    ) -> dict[str, Any] | None:
        """ADK before_tool_callback: None = allow, dict = deny short-circuit."""
        tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", str(tool))
        decision, receipt, _sup, final_args = govern_with_remodify(
            self.host,
            str(tool_name),
            dict(args or {}),
            side_effect_class=side_effect_class,
            origin=self.origin_prefix,
        )
        self.last_receipt = receipt
        if decision.verdict == "deny" or final_args is None:
            return {
                "error": f"Blocked by Drako Authority Kernel: {decision.reason}",
                "policy_id": decision.policy_id,
                "receipt_id": receipt["receipt_id"] if receipt else None,
            }
        # Propagate verified post-modify args back into ADK's mutable args dict
        if isinstance(args, dict):
            args.clear()
            args.update(final_args)
        return None

    def wrap_agent(self, agent: Any, *, side_effect_class: str = "write") -> Any:
        existing = getattr(agent, "before_tool_callback", None)

        def chained(tool: Any, args: dict[str, Any], tool_context: Any = None) -> dict[str, Any] | None:
            denied = self.before_tool_callback(
                tool, args, tool_context, side_effect_class=side_effect_class
            )
            if denied is not None:
                return denied
            if callable(existing):
                return existing(tool, args, tool_context)
            return None

        agent.before_tool_callback = chained
        return agent


def wrap_adk_agent(agent: Any, host: Host, *, side_effect_class: str = "write") -> Any:
    """Attach Drako's fail-closed before_tool_callback to a Google ADK Agent."""
    return GoogleADKAdapter(host, default_side_effect=side_effect_class).wrap_agent(
        agent, side_effect_class=side_effect_class
    )
