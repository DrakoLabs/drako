"""`drako init` — Offline local-first initialization for Drako v4.

Generates `.drako.yaml` (v4 schema) and an optional ACS policy profile
(`drako-policy.yaml` pinned to `AGENT-HOOKS-0.1`). Zero network calls,
zero API keys, zero telemetry prompts.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any

import click
import yaml

_CONFIG_FILENAME = ".drako.yaml"
_POLICY_FILENAME = "drako-policy.yaml"
_PAYMENT_KEYWORDS = ("pay", "payment", "transfer", "charge", "invoice", "wire", "withdraw", "refund")


def classify_tool_type(tool: Any) -> str:
    """Derive canonical Drako v4 tool type from a DetectedTool or scan-cache dict."""
    if isinstance(tool, dict):
        name = str(tool.get("name", "")).lower()
        has_code = bool(tool.get("has_code_execution", False))
        has_fs = bool(tool.get("has_filesystem_access", False))
        has_net = bool(tool.get("has_network_access", False))
        explicit = tool.get("type") or tool.get("category")
    else:
        name = str(getattr(tool, "name", "")).lower()
        has_code = bool(getattr(tool, "has_code_execution", False))
        has_fs = bool(getattr(tool, "has_filesystem_access", False))
        has_net = bool(getattr(tool, "has_network_access", False))
        explicit = getattr(tool, "type", None) or getattr(tool, "category", None)

    if has_code:
        return "execute"
    if any(kw in name for kw in _PAYMENT_KEYWORDS):
        return "payment"
    if has_fs:
        return "write"
    if has_net:
        return "network"
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()
    return "read"


def expected_effect_for_tool(tool_type: str, governance_level: str = "balanced") -> str:
    """Return baseline ACS effect ('allow' or 'deny') for a tool type & posture."""
    if tool_type in ("payment", "execute"):
        return "deny"
    if tool_type == "write" and governance_level == "strict":
        return "deny"
    return "allow"


def _restrict_permissions(path: Path) -> None:
    """Apply owner-only permissions (0600) on POSIX platforms."""
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def _build_v4_config(
    *,
    project_id: str,
    framework: str,
    governance_level: str,
    extends: str | None,
    explicit_level: bool = False,
    detected_agents: dict[str, dict[str, str]],
    detected_tools: dict[str, dict[str, str]],
    profile_path: str | None,
) -> dict[str, Any]:
    default_effect = "deny" if governance_level in ("balanced", "strict") else "permit"
    cfg: dict[str, Any] = {
        "version": "4.0",
        "project_id": project_id,
    }
    if extends:
        cfg["extends"] = extends
        if explicit_level:
            cfg["governance_level"] = governance_level
        cfg["framework"] = framework
        cfg["kernel"] = {
            "spec_pin": "AGENT-HOOKS-0.1",
            "profile_path": profile_path or _POLICY_FILENAME,
        }
        if detected_agents:
            cfg["agents"] = detected_agents
        if detected_tools:
            cfg["detected_tools"] = detected_tools
        return cfg

    cfg["governance_level"] = governance_level
    cfg["framework"] = framework
    cfg["kernel"] = {
        "spec_pin": "AGENT-HOOKS-0.1",
        "default_effect": default_effect,
        "profile_path": profile_path or _POLICY_FILENAME,
        "receipt_store": ".drako/receipts.jsonl",
        "tiers": {
            "read": "auto",
            "write": "audit",
            "external_comms": "audit",
            "irreversible": "consent",
        },
    }
    cfg["loop_breaker"] = {
        "enabled": True,
        "trip_threshold": 10,
        "window_seconds": 300.0,
    }
    cfg["audit"] = {
        "enabled": True,
        "cryptographic": True,
        "receipt_store": ".drako/receipts.jsonl",
        "retention_days": 90,
    }
    cfg["mcp"] = {
        "lockfile": "mcp.lock",
        "enforce_pin": True,
        "env_allowlist": [],
        "allow_auto_install": False,
        "protocol_version": "2026-07-28",
    }
    cfg["egress"] = {
        "allowed_domains": [],
    }
    cfg["a2a"] = {
        "mode": "enforce" if governance_level != "autopilot" else "audit",
        "require_signed_cards": True,
    }
    if detected_agents:
        cfg["agents"] = detected_agents
    if detected_tools:
        cfg["detected_tools"] = detected_tools
    return cfg


def _build_acs_profile(
    *,
    governance_level: str,
    detected_tools: dict[str, dict[str, str]],
) -> dict[str, Any]:
    tools_section: dict[str, Any] = {}
    for name, info in detected_tools.items():
        ttype = info.get("type", "read")
        effect = expected_effect_for_tool(ttype, governance_level)
        if effect == "deny":
            reason = (
                f"High-impact tool '{name}' ({ttype}) requires explicit operator consent"
                if ttype in ("payment", "execute")
                else f"Strict mode: {ttype} tool '{name}' requires explicit approval"
            )
            liftable = True
        else:
            reason = f"Baseline-discovered {ttype} tool '{name}'"
            liftable = False
        tools_section[name] = {
            "id": f"tool:{name}",
            "effect": effect,
            "reason": reason,
            "approval_liftable": liftable,
        }
    return {
        "spec_pin": "AGENT-HOOKS-0.1",
        "default_effect": "deny" if governance_level in ("balanced", "strict") else "permit",
        "tiers": {
            "read": "auto",
            "write": "audit",
            "external_comms": "audit",
            "irreversible": "consent",
        },
        "tools": tools_section,
    }


@click.command()
@click.option("--framework", default=None, help="Framework override (langgraph, openai-agents, maf, claude, adk, crewai)")
@click.option(
    "--level",
    "governance_level",
    type=click.Choice(["autopilot", "balanced", "strict"], case_sensitive=False),
    default=None,
    help="Initial governance posture (default: balanced, or inherited from --template)",
)
@click.option("--template", "extends", default=None, help="Optional policy template to inherit (e.g. fintech, eu-ai-act)")
@click.option("--config", "config_path", default=_CONFIG_FILENAME, help="Output config path (default: .drako.yaml)")
@click.option("--profile", "profile_path", default=_POLICY_FILENAME, help="Output ACS policy profile path")
@click.option("--yes", "-y", is_flag=True, help="Overwrite existing files without prompting")
def init(
    framework: str | None,
    governance_level: str | None,
    extends: str | None,
    config_path: str,
    profile_path: str,
    yes: bool,
) -> None:
    """Initialize local Drako v4 configuration and ACS policy profile (100% offline)."""
    cfg_file = Path(config_path)
    prof_file = Path(profile_path)

    # Validate --template before touching disk
    template_data: dict[str, Any] | None = None
    if extends:
        from drako.exceptions import ConfigError
        from drako.templates import load_template

        try:
            template_data = load_template(extends)
        except ConfigError as exc:
            raise click.ClickException(str(exc)) from exc

    explicit_level = governance_level is not None
    effective_level = (
        governance_level.lower()
        if governance_level is not None
        else str((template_data or {}).get("governance_level", "balanced")).lower()
    )

    click.echo()
    click.secho("  Drako Init — Local-First Authority Kernel Setup", fg="cyan", bold=True)
    click.echo()

    if cfg_file.exists() and not yes and not click.confirm(f"  {cfg_file} already exists. Overwrite?", default=False):
        click.echo("  Aborted.")
        return

    project_id = Path.cwd().name or "default"
    detected_fw = framework or "generic"
    detected_agents: dict[str, dict[str, str]] = {}
    detected_tools: dict[str, dict[str, str]] = {}

    # Reuse cached scan results if available; otherwise run offline live discovery
    from drako.cli.scan_cache import load_scan_cache

    cached = load_scan_cache(".")
    if cached:
        if not framework:
            if cached.get("framework"):
                detected_fw = str(cached["framework"])
            elif cached.get("frameworks"):
                fw0 = cached["frameworks"][0]
                detected_fw = fw0.get("name", "generic") if isinstance(fw0, dict) else str(fw0)
        for a in cached.get("agents", []):
            name = a.get("name") if isinstance(a, dict) else str(a)
            if name:
                detected_agents[name] = {
                    "source": a.get("file_path", "") if isinstance(a, dict) else "",
                    "description": (a.get("role") or a.get("description") or "") if isinstance(a, dict) else "",
                }
        for t in cached.get("tools", []):
            name = t.get("name") if isinstance(t, dict) else str(t)
            if name:
                detected_tools[name] = {
                    "source": t.get("file_path", "") if isinstance(t, dict) else "",
                    "type": classify_tool_type(t) if isinstance(t, dict) else "read",
                }
        click.echo(
            click.style("  [scan]   ", fg="green")
            + f"Loaded cached BOM ({len(detected_agents)} agent(s), {len(detected_tools)} tool(s))"
        )
    else:
        try:
            from drako.cli.scanner import run_scan

            live = run_scan(".")
            if not framework and live.bom.frameworks:
                detected_fw = live.bom.frameworks[0].name
            for a in live.bom.agents:
                if a.name:
                    detected_agents[a.name] = {
                        "source": a.file_path or "",
                        "description": getattr(a, "role", "") or "",
                    }
            for t in live.bom.tools:
                if t.name:
                    detected_tools[t.name] = {
                        "source": t.file_path or "",
                        "type": classify_tool_type(t),
                    }
            click.echo(
                click.style("  [scan]   ", fg="green")
                + f"Discovered {len(detected_agents)} agent(s), {len(detected_tools)} tool(s) ({detected_fw})"
            )
        except Exception:
            try:
                from drako.utils.detection import detect_frameworks

                fws = detect_frameworks(".")
                if not framework and fws:
                    detected_fw = fws[0]
            except Exception:
                pass

    cfg_doc = _build_v4_config(
        project_id=project_id,
        framework=detected_fw,
        governance_level=effective_level,
        extends=extends,
        explicit_level=explicit_level,
        detected_agents=detected_agents,
        detected_tools=detected_tools,
        profile_path=str(prof_file),
    )

    header = (
        "# Drako v4 Configuration (local-first, zero-network-by-default)\n"
        "# Spec pin: AGENT-HOOKS-0.1 | Validate with: drako validate .drako.yaml\n\n"
    )
    cfg_file.write_text(
        header + yaml.dump(cfg_doc, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    _restrict_permissions(cfg_file)
    click.echo(click.style("  [write]  ", fg="green") + f"Wrote {cfg_file} (mode 0600)")

    if not prof_file.exists() or yes:
        prof_doc = _build_acs_profile(
            governance_level=effective_level,
            detected_tools=detected_tools,
        )
        prof_header = (
            "# Drako ACS Policy Profile (spec_pin: AGENT-HOOKS-0.1)\n"
            "# Compiled by drako.kernel.policies.guardian_from_yaml()\n\n"
        )
        prof_file.write_text(
            prof_header + yaml.dump(prof_doc, default_flow_style=False, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        click.echo(click.style("  [write]  ", fg="green") + f"Wrote {prof_file}")

    click.echo()
    click.secho("  Next steps:", fg="white", bold=True)
    click.echo("    1. " + click.style(f"drako validate {cfg_file}", fg="cyan") + "     Verify config & policy grammar")
    click.echo("    2. " + click.style("drako scan . --baseline", fg="cyan") + "        Save authority baseline")
    click.echo("    3. " + click.style("drako mcp audit", fg="cyan") + "                Audit MCP server pins")
    click.echo()
