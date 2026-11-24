"""Claude Agent SDK offline adapter over `drako.kernel.Host` (ADR-0009).

Provides `PreToolUse` / `SubagentStart` hook callables matching the Claude
Agent SDK hook contract (returns allow/deny/updatedInput decision dicts)
plus `wrap_claude_agent()` helper.
"""

from __future__ import annotations

from typing import Any

from drako.adapters.base import BaseAdapter, govern_with_remodify
from drako.kernel.host import Host


class ClaudeAgentAdapter(BaseAdapter):
    origin_prefix = "tool:claude-agent"

    def pre_tool_use_hook(
        self,
        hook_input: dict[str, Any],
        *,
        side_effect_class: str = "write",
    ) -> dict[str, Any]:
        """Evaluate a Claude Agent SDK PreToolUse payload and return a hook decision."""
        tool_name = str(hook_input.get("tool_name", ""))
        tool_input = dict(hook_input.get("tool_input") or {})
        decision, receipt, _sup, final_args = govern_with_remodify(
            self.host,
            tool_name,
            tool_input,
            side_effect_class=side_effect_class,
            origin=self.origin_prefix,
        )
        self.last_receipt = receipt
        if decision.verdict == "deny" or final_args is None:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": decision.reason,
                },
                "drako_receipt_id": receipt["receipt_id"] if receipt else None,
            }
        out: dict[str, Any] = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": final_args,
            },
            "drako_receipt_id": receipt["receipt_id"] if receipt else None,
        }
        return out

    def wrap_agent(self, agent_options: Any, *, side_effect_class: str = "write") -> Any:
        """Register Drako's PreToolUse hook on a ClaudeAgentOptions-like object or dict."""
        hook_fn = lambda payload: self.pre_tool_use_hook(payload, side_effect_class=side_effect_class)  # noqa: E731
        if isinstance(agent_options, dict):
            hooks = agent_options.setdefault("hooks", {})
            hooks.setdefault("PreToolUse", []).insert(0, hook_fn)
            return agent_options
        hooks = getattr(agent_options, "hooks", None)
        if hooks is None:
            agent_options.hooks = {"PreToolUse": [hook_fn]}
        elif isinstance(hooks, dict):
            hooks.setdefault("PreToolUse", []).insert(0, hook_fn)
        return agent_options


def wrap_claude_agent(agent_options: Any, host: Host, *, side_effect_class: str = "write") -> Any:
    """Attach Drako Authority Kernel PreToolUse hook to Claude Agent SDK options."""
    return ClaudeAgentAdapter(host, default_side_effect=side_effect_class).wrap_agent(
        agent_options, side_effect_class=side_effect_class
    )
