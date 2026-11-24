"""LangGraph adapter: ToolNode calls governed through `drako.kernel.Host`.

Thin translator only: LangGraph tool-call shape -> Proposal -> (Decision, Receipt).
`langgraph` is strictly optional (lazy import). Tested hermetically with fakes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from drako.adapters.base import govern_with_remodify as _base_remodify
from drako.kernel.authority import Label, TrustLevel
from drako.kernel.host import Host


def _require_langgraph() -> None:
    try:
        import langgraph  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "langgraph is required for this adapter. "
            "Install with: pip install 'drako[langgraph]'."
        ) from e


def require_langgraph() -> None:
    _require_langgraph()


def tool_call_to_provenance(tool_name: str, origin: str = "tool:langgraph-node") -> list[Label]:
    return [
        Label(
            origin=f"{origin}:{tool_name}",
            trust=TrustLevel.TOOL,
            scope=frozenset({"read", "write", "external_comms"}),
        )
    ]


def govern_tool_node_call(
    host: Host,
    tool_name: str,
    args: dict[str, Any],
    *,
    side_effect_class: str = "write",
    origin: str = "tool:langgraph-node",
) -> tuple[Any, dict[str, Any] | None]:
    """Govern one LangGraph tool invocation. Returns (decision, receipt)."""
    return host.govern_tool_call(
        tool_name,
        args,
        provenance=tool_call_to_provenance(tool_name, origin),
        side_effect_class=side_effect_class,
    )


def govern_with_remodify(
    host: Host,
    tool_name: str,
    args: dict[str, Any],
    *,
    side_effect_class: str = "write",
    origin: str = "tool:langgraph-node",
) -> tuple[Any, dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    return _base_remodify(
        host,
        tool_name,
        args,
        side_effect_class=side_effect_class,
        origin=origin,
        provenance=tool_call_to_provenance(tool_name, origin),
    )


def wrap_tool_node(node_fn: Callable, host: Host, *, side_effect_class: str = "write"):
    """Wrap a ToolNode-style callable `fn(state) -> state` with Host governance."""

    def governed(state: dict[str, Any]) -> dict[str, Any]:
        state = dict(state)
        denials = []
        kept = []
        for tc in state.get("tool_calls", []):
            name, args = tc.get("name", ""), dict(tc.get("args", {}))
            decision, receipt, superseded, final_args = govern_with_remodify(
                host, name, args, side_effect_class=side_effect_class
            )
            if decision.verdict == "deny" or final_args is None:
                entry: dict[str, Any] = {
                    "id": tc.get("id"),
                    "name": name,
                    "reason": decision.reason,
                    "receipt_id": receipt["receipt_id"] if receipt else None,
                }
                if superseded is not None:
                    entry["supersedes_receipt_id"] = superseded["receipt_id"]
                denials.append(entry)
                continue
            kept.append({**tc, "args": final_args})
        state["tool_calls"] = kept
        if denials:
            state["drako_denials"] = denials
        return node_fn(state)

    return governed
