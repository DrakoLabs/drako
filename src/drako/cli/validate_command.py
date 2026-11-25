"""`drako validate` — Validate .drako.yaml and optional ACS policy profile.

100% offline. Checks:
  1. YAML parseability
  2. Pydantic v4 schema validation
  3. Cross-references (agents, tools, A2A, hooks, fallback)
  4. Logical consistency & budget math
  5. Authority Kernel / ACS profile & mcp.lock hygiene
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import yaml


@click.command()
@click.argument("file", type=click.Path(exists=True))
def validate(file: str) -> None:
    """Validate a .drako.yaml configuration file (100% offline)."""
    path = Path(file)
    errors: list[str] = []
    warnings: list[str] = []

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        _fail(f"YAML parse error: {exc}")
        return
    except OSError as exc:
        _fail(f"Cannot read file: {exc}")
        return

    if not isinstance(data, dict):
        _fail(f"Expected a YAML mapping, got {type(data).__name__}")
        return

    _ok("YAML parseable")

    # Flag all retired v3 fields clearly
    _retired_v3_keys = (
        "api_key", "api_key_env", "endpoint", "governance", "bft", "chaos", "topology",
    )
    legacy_keys = [k for k in _retired_v3_keys if k in data]
    if legacy_keys:
        warnings.append(
            f"Deprecated v3 key(s) present: {', '.join(legacy_keys)} — run `drako upgrade --v4`"
        )

    # Resolve template inheritance (`extends:`) before schema validation
    resolved_data = data
    if data.get("extends"):
        from drako.exceptions import ConfigError
        from drako.templates import deep_merge, load_template

        try:
            template_data = load_template(str(data["extends"]))
            resolved_data = deep_merge(template_data, data)
            _ok(f"Template inherited ({data['extends']})")
        except ConfigError as exc:
            errors.append(f"Template resolution failed: {exc}")
            _err(f"Template resolution: {exc}")
            _summary(errors, warnings)
            sys.exit(1)

    try:
        from drako.config import DrakoConfig

        config = DrakoConfig.model_validate(resolved_data)
        _ok("Schema valid")
    except Exception as exc:
        errors.append(f"Schema validation failed: {exc}")
        _err(f"Schema validation: {exc}")
        _summary(errors, warnings)
        sys.exit(1)

    agent_names = set(config.agents.keys())
    tool_names = set(config.detected_tools.keys())

    if config.hitl.triggers.tools:
        for tool in config.hitl.triggers.tools:
            if tool_names and tool not in tool_names:
                warnings.append(f"HITL trigger references unknown tool: '{tool}'")

    for hook_list_name in ("pre_action", "post_action", "on_error", "on_session_end"):
        for hook in getattr(config.hooks, hook_list_name, []):
            if hook.condition and "agent:" in hook.condition:
                ref_agent = hook.condition.split("agent:")[1].split()[0].strip("'\"")
                if agent_names and ref_agent not in agent_names:
                    warnings.append(f"Hook '{hook.name}' references unknown agent: '{ref_agent}'")

    for channel in config.a2a.channels:
        if agent_names:
            if channel.from_agent != "*" and channel.from_agent not in agent_names:
                warnings.append(f"A2A channel references unknown from-agent: '{channel.from_agent}'")
            if channel.to_agent != "*" and channel.to_agent not in agent_names:
                warnings.append(f"A2A channel references unknown to-agent: '{channel.to_agent}'")

    for tool_name in config.fallback.tools:
        if tool_names and tool_name not in tool_names:
            warnings.append(f"Fallback references unknown tool: '{tool_name}'")

    _ok("Cross-references valid")

    cb = config.circuit_breaker.agent_level
    if cb.recovery_timeout_seconds > cb.time_window_seconds:
        warnings.append(
            f"Circuit breaker recovery ({cb.recovery_timeout_seconds}s) "
            f"> time window ({cb.time_window_seconds}s)"
        )

    if config.kernel.default_effect not in ("deny", "permit"):
        errors.append(f"kernel.default_effect must be 'deny' or 'permit', got {config.kernel.default_effect!r}")
    elif config.kernel.default_effect == "permit":
        warnings.append("kernel.default_effect=permit (fail-open) — prefer 'deny' (fail-closed)")

    if config.kernel.profile_path:
        prof = Path(config.kernel.profile_path)
        if not prof.is_absolute():
            prof = path.parent / prof
        if prof.exists():
            try:
                from drako.kernel.policies import compile_profile

                compile_profile(yaml.safe_load(prof.read_text(encoding="utf-8")))
                _ok(f"ACS policy profile valid ({prof.name})")
            except ImportError:
                pass
            except Exception as exc:
                errors.append(f"ACS policy profile error ({prof.name}): {exc}")
                _err(f"ACS policy profile: {exc}")
        else:
            warnings.append(f"Referenced kernel.profile_path not found: {config.kernel.profile_path}")

    if config.mcp.allow_auto_install and not config.mcp.enforce_pin:
        warnings.append("mcp.allow_auto_install=true without enforce_pin exposes unverified supply chain")

    budgets = config.finops.budgets
    if budgets.daily_usd and budgets.weekly_usd and budgets.daily_usd * 7 > budgets.weekly_usd * 1.1:
        warnings.append(
            f"Daily budget ({budgets.daily_usd:.2f}) x 7 exceeds weekly budget (${budgets.weekly_usd:.2f})"
        )
    if budgets.weekly_usd and budgets.monthly_usd and budgets.weekly_usd * 4.33 > budgets.monthly_usd * 1.1:
        warnings.append(
            f"Weekly budget ({budgets.weekly_usd:.2f}) x 4.33 exceeds monthly budget (${budgets.monthly_usd:.2f})"
        )

    if config.dlp.mode == "off" and config.hitl.mode == "off":
        warnings.append("Both DLP and HITL are off")

    write_tools = [
        name for name, entry in config.detected_tools.items()
        if entry.type in ("write", "execute", "payment")
    ]
    if write_tools and config.hitl.mode == "off":
        warnings.append(
            f"HITL is off but write/execute/payment tools detected: "
            f"{write_tools[:3]}{'...' if len(write_tools) > 3 else ''}"
        )

    if not errors:
        _ok("Logical consistency valid")

    _summary(errors, warnings)
    if errors:
        sys.exit(1)


def _ok(msg: str) -> None:
    click.echo(click.style("  [OK] ", fg="green") + msg)


def _err(msg: str) -> None:
    click.echo(click.style("  [FAIL] ", fg="red") + msg)


def _warn(msg: str) -> None:
    click.echo(click.style("  ! ", fg="yellow") + msg)


def _fail(msg: str) -> None:
    _err(msg)
    click.echo()
    click.secho("Result: INVALID", fg="red", bold=True)
    sys.exit(1)


def _summary(errors: list[str], warnings: list[str]) -> None:
    click.echo()
    for w in warnings:
        _warn(w)

    if errors:
        click.echo()
        click.secho(
            f"Result: INVALID ({len(errors)} error(s), {len(warnings)} warning(s))",
            fg="red", bold=True,
        )
    elif warnings:
        click.echo()
        click.secho(f"Result: VALID ({len(warnings)} warning(s))", fg="green", bold=True)
    else:
        click.echo()
        click.secho("Result: VALID", fg="green", bold=True)
