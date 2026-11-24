"""Shared offline adapter base over `drako.kernel.Host` (ADR-0009).

Every framework adapter (LangGraph, OpenAI Agents SDK, Microsoft Agent
Framework, Claude Agent SDK, Google ADK, CrewAI) is a thin translator that
converts framework tool invocations into `Proposal`s evaluated by `Host` and
enforces the T-5 re-govern-after-modify invariant.

Zero network calls. Zero remote backend client. Optional framework imports are lazy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

from drako.exceptions import ConfigError, PolicyViolationError
from drako.kernel.authority import ConsentToken, Label, TrustLevel
from drako.kernel.envelope import Decision
from drako.kernel.host import Host, HostConfig
from drako.kernel.policies import guardian_from_yaml


def default_tool_provenance(
    tool_name: str,
    *,
    origin_prefix: str = "tool:adapter",
    host: Optional[Host] = None,
) -> list[Label]:
    """Build a TOOL-capped provenance label (attested when Host is provided)."""
    origin = f"{origin_prefix}:{tool_name}"
    scope = frozenset({"read", "write", "external_comms"})
    if host is not None:
        return [host.attest_label(origin=origin, trust=TrustLevel.TOOL, scope=scope)]
    return [Label(origin=origin, trust=TrustLevel.TOOL, scope=scope)]


def govern_with_remodify(
    host: Host,
    tool_name: str,
    args: dict[str, Any],
    *,
    side_effect_class: str = "write",
    origin: str = "tool:adapter",
    provenance: Optional[list[Label]] = None,
    consent_token: Optional[ConsentToken] = None,
) -> tuple[Decision, Optional[dict[str, Any]], Optional[dict[str, Any]], Optional[dict[str, Any]]]:
    """Govern a tool call, apply at most ONE modify round, and re-govern (T-5).

    Returns (decision, receipt, superseded_receipt, final_args):
    - permit, no modify  -> (permit, r1, None, original_args)
    - permit post-modify -> (permit, r2, r1, modified_args)
    - deny               -> (deny, rN, rN-1|None, None)
    """
    prov = provenance if provenance is not None else default_tool_provenance(
        tool_name, origin_prefix=origin, host=host
    )
    decision, receipt = host.govern_tool_call(
        tool_name,
        args,
        provenance=prov,
        side_effect_class=side_effect_class,
        consent_token=consent_token,
    )
    if decision.verdict != "modify" or not decision.modifications:
        return decision, receipt, None, (dict(args) if decision.verdict == "permit" else None)

    new_args = {**args, **decision.modifications}
    d2, r2 = host.govern_tool_call(
        tool_name,
        new_args,
        provenance=prov,
        side_effect_class=side_effect_class,
        consent_token=consent_token,
        supersedes_receipt_id=receipt["receipt_id"] if receipt is not None else None,
    )
    if d2.verdict == "deny":
        return d2, r2, receipt, None
    if d2.verdict == "modify":
        loop = Decision(
            verdict="deny",
            reason="modify-on-modify denied (loop guard)",
            policy_id="kernel:loop-guard",
        )
        loop_rcpt = dict(r2) if r2 is not None else None
        if loop_rcpt is not None:
            loop_rcpt["reason"] = loop.reason
        return loop, loop_rcpt, receipt, None
    return d2, r2, receipt, new_args


class BaseAdapter:
    """Thin offline adapter base wiring any tool callable to `drako.kernel.Host`."""

    origin_prefix: str = "tool:adapter"

    def __init__(self, host: Host, *, default_side_effect: str = "write") -> None:
        self.host = host
        self.default_side_effect = default_side_effect
        self.last_receipt: Optional[dict[str, Any]] = None

    def check_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        side_effect_class: Optional[str] = None,
        provenance: Optional[list[Label]] = None,
        consent_token: Optional[ConsentToken] = None,
    ) -> dict[str, Any]:
        """Evaluate tool call through Host. Raises PolicyViolationError on deny.

        Returns the verified final_args dict that is safe to pass to the tool.
        """
        decision, receipt, _sup, final_args = govern_with_remodify(
            self.host,
            tool_name,
            args,
            side_effect_class=side_effect_class or self.default_side_effect,
            origin=self.origin_prefix,
            provenance=provenance,
            consent_token=consent_token,
        )
        self.last_receipt = receipt
        if decision.verdict == "deny" or final_args is None:
            raise PolicyViolationError(
                detail=decision.reason,
                policy_id=decision.policy_id,
                receipt=receipt,
            )
        return final_args

    def wrap_callable(
        self,
        fn: Callable[..., Any],
        *,
        tool_name: Optional[str] = None,
        side_effect_class: Optional[str] = None,
    ) -> Callable[..., Any]:
        """Wrap a plain Python tool callable so arguments pass through Host."""
        name = tool_name or getattr(fn, "__name__", "unknown_tool")

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            arg_dict = dict(kwargs)
            if args:
                arg_dict["_positional"] = list(args)
            final_args = self.check_tool(
                name, arg_dict, side_effect_class=side_effect_class
            )
            call_kwargs = {k: v for k, v in final_args.items() if k != "_positional"}
            call_args = tuple(final_args.get("_positional", args))
            return fn(*call_args, **call_kwargs)

        wrapped.__name__ = name
        return wrapped


def host_from_profile(profile_path: str, *, agent_id: str = "default-agent") -> Host:
    """Build an offline Host from an ACS YAML profile file."""
    p = Path(profile_path)
    if not p.exists():
        raise ConfigError(f"ACS policy profile not found: {profile_path}")
    guardian = guardian_from_yaml(p.read_text(encoding="utf-8"))
    return Host(guardian, HostConfig(agent_id=agent_id))


def wrap_agent(
    obj: Any,
    *,
    host: Optional[Host] = None,
    profile_path: Optional[str] = None,
    framework: Optional[str] = None,
) -> Any:
    """Dispatch an agent/tool object to the matching offline adapter."""
    resolved_host = host or (host_from_profile(profile_path) if profile_path else None)
    if resolved_host is None:
        raise ConfigError("wrap_agent() requires `host` or `profile_path`")

    fw = (framework or "").lower().strip()
    cls_name = type(obj).__name__.lower()
    mod_name = type(obj).__module__.lower()

    if fw == "langgraph" or "langgraph" in mod_name:
        from drako.adapters.langgraph import wrap_tool_node

        return wrap_tool_node(obj, resolved_host)
    if fw in ("openai", "openai-agents", "openai_agents") or "agents" == mod_name.split(".")[0]:
        from drako.adapters.openai_agents import wrap_openai_agent

        return wrap_openai_agent(obj, resolved_host)
    if fw == "maf" or "agent_framework" in mod_name:
        from drako.adapters.maf import wrap_maf_agent

        return wrap_maf_agent(obj, resolved_host)
    if fw in ("claude", "claude-agent", "claude_agent") or "claude" in mod_name:
        from drako.adapters.claude_agent import wrap_claude_agent

        return wrap_claude_agent(obj, resolved_host)
    if fw in ("adk", "google-adk", "google_adk") or "google.adk" in mod_name:
        from drako.adapters.google_adk import wrap_adk_agent

        return wrap_adk_agent(obj, resolved_host)
    if fw == "crewai" or "crew" in cls_name or "crewai" in mod_name:
        from drako.adapters.crewai import wrap_crew

        return wrap_crew(obj, resolved_host)
    if callable(obj):
        return BaseAdapter(resolved_host).wrap_callable(obj)
    raise ConfigError(
        f"Unsupported agent object type {type(obj).__name__!r}. "
        "Pass framework='langgraph|openai-agents|maf|claude|adk|crewai' or use Host directly."
    )
