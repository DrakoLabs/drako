"""`drako init` — Initialize Drako in an existing project.

Generates a rich `.drako.yaml` pre-populated with real agents, tools,
and models discovered by the scanner.

Supports governance levels:
  --autopilot (default): smart defaults from scan, audit-first
  --balanced: enforcement active with escape hatches
  --strict: maximum governance for enterprise
  --manual: full YAML with all sections for manual editing
  --template NAME: start from an industry template (fintech, healthcare, etc.)
"""

from __future__ import annotations

import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import click
import yaml

from drako.utils.detection import detect_framework

_CONFIG_FILENAME = ".drako.yaml"


# ------------------------------------------------------------------
# Tool type inference
# ------------------------------------------------------------------

def _infer_tool_type(tool: dict) -> str:
    """Infer a tool type label from scan BOM permissions."""
    if tool.get("has_code_execution"):
        return "execute"
    if tool.get("has_network_access"):
        return "network"
    if tool.get("has_filesystem_access"):
        return "write"
    return "read"


# ------------------------------------------------------------------
# Autopilot smart defaults builder
# ------------------------------------------------------------------

def _build_autopilot_odd(agents: list[dict], tools: list[dict]) -> dict:
    """Build ODD config: each agent locked to its discovered tools."""
    odd: dict = {"enforcement_mode": "audit"}
    agents_odd: dict = {}

    tool_name_set = {t["name"] for t in tools}

    for agent in agents:
        agent_tools = agent.get("tools", [])
        if agent_tools:
            permitted = [t for t in agent_tools if t in tool_name_set]
            forbidden = [t for t in tool_name_set if t not in agent_tools]
        else:
            permitted = list(tool_name_set)
            forbidden = []

        agents_odd[agent["name"]] = {
            "permitted_tools": permitted,
            "forbidden_tools": forbidden,
            "max_actions_per_minute": 30,
        }

    if agents_odd:
        odd["agents"] = agents_odd
    return odd


def _compute_magnitude_defaults(agents: list[dict], tools: list[dict],
                                models: list[dict]) -> dict:
    """Compute sensible magnitude limits based on project analysis."""
    n_agents = max(len(agents), 1)
    n_tools = max(len(tools), 1)

    model_names = [m.get("name", "") for m in models]
    has_expensive = any(
        n.startswith(("gpt-4", "claude-3-opus", "claude-3.5", "claude-4", "o1", "o3"))
        for n in model_names
    )

    max_spend = 20.00 if has_expensive else 5.00
    max_actions = n_agents * n_tools * 5

    return {
        "max_spend_per_action_usd": round(max_spend / 10, 2),
        "max_spend_per_session_usd": max_spend,
        "max_actions_per_minute": max(max_actions, 30),
        "max_records_per_action": 100,
    }


def _build_autopilot_hitl(tools: list[dict]) -> dict:
    """Build HITL config: active for write/execute/payment tools."""
    critical_types = {"write", "execute", "payment"}
    critical_tools = [
        t["name"] for t in tools if _infer_tool_type(t) in critical_types
    ]

    return {
        "mode": "audit",
        "triggers": {
            "tool_types": list(critical_types),
            "tools": critical_tools,
        },
        "timeout_action": "allow",
        "approval_timeout_minutes": 30,
    }


# ------------------------------------------------------------------
# YAML generators per governance level
# ------------------------------------------------------------------

def _generate_autopilot_yaml(
    tenant_id: str,
    endpoint: str,
    framework: str | None,
    scan_data: dict | None,
) -> str:
    """Generate autopilot config with smart defaults from scan."""
    agents = scan_data.get("agents", []) if scan_data else []
    tools = scan_data.get("tools", []) if scan_data else []
    models = scan_data.get("models", []) if scan_data else []
    project_name = scan_data.get("project_name", "my-project") if scan_data else "my-project"
    score = scan_data.get("score", "?") if scan_data else "?"

    config: dict = {
        "governance_level": "autopilot",
        "version": "1.0",
        "api_key_env": "DRAKO_API_KEY",
        "tenant_id": tenant_id,
        "endpoint": endpoint,
        "framework": framework or "generic",
    }

    # Agents section
    agents_dict = {}
    for a in agents:
        agents_dict[a["name"]] = {
            "source": a.get("file_path", ""),
            "description": "",
        }
    config["agents"] = agents_dict

    # Tools section
    tools_dict = {}
    for t in tools:
        tools_dict[t["name"]] = {
            "source": t.get("file_path", ""),
            "type": _infer_tool_type(t),
        }
    config["tools"] = tools_dict

    # ODD: each agent locked to discovered tools
    if agents and tools:
        config["odd"] = _build_autopilot_odd(agents, tools)

    # Magnitude: smart defaults
    config["magnitude"] = _compute_magnitude_defaults(agents, tools, models)

    # DLP: audit mode (safe default)
    config["dlp"] = {"mode": "audit"}

    # Circuit breaker: industry defaults
    config["circuit_breaker"] = {
        "agent_level": {
            "failure_threshold": 5,
            "time_window_seconds": 60,
            "recovery_timeout_seconds": 30,
        }
    }

    # HITL: active for critical tools, auto-allow on timeout
    if tools:
        config["hitl"] = _build_autopilot_hitl(tools)

    # Audit: enabled
    config["audit"] = {"enabled": True}

    # FinOps: tracking only
    config["finops"] = {
        "tracking": {"enabled": True},
        "routing": {"enabled": False},
        "cache": {"enabled": False},
    }

    # Build YAML with header comment
    fw_label = framework or "unknown"
    header = textwrap.dedent(f"""\
        # Drako Autopilot Configuration
        # Generated automatically from scan results.
        # Project: {project_name} ({fw_label}) | Score: {score}/100
        #
        # This config uses safe defaults based on YOUR project.
        # Everything is in audit mode - logging, not blocking.
        #
        # Ready for more control? Edit any section below or see:
        # https://docs.useagentmesh.com/config
        #
        # Switch to manual mode:
        #   drako init --manual
        #
        # Upgrade enforcement:
        #   drako upgrade --balanced
        #   drako upgrade --strict
        #
    """)

    yaml_body = yaml.dump(config, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return header + yaml_body


def _generate_manual_yaml(
    tenant_id: str,
    endpoint: str,
    framework: str | None,
    framework_version: str | None,
    scan_data: dict | None,
) -> str:
    """Generate full YAML with all sections (original behavior)."""
    agents = scan_data.get("agents", []) if scan_data else []
    tools = scan_data.get("tools", []) if scan_data else []
    project_name = scan_data.get("project_name", "my-project") if scan_data else "my-project"

    fw_label = framework or "unknown"
    if framework_version:
        fw_label = f"{framework} {framework_version}"

    header = textwrap.dedent(f"""\
        # Drako Configuration
        # Generated from scan of: {project_name} ({fw_label})
        # Docs: https://docs.useagentmesh.com/config

        version: "1.0"
        governance_level: custom
        api_key_env: DRAKO_API_KEY
        tenant_id: {tenant_id}
        endpoint: {endpoint}
        framework: {framework or 'generic'}

    """)

    # Build agents section
    if agents:
        lines = ["# AGENTS - discovered by scan", "agents:"]
        for a in agents:
            name = a["name"]
            source = a.get("file_path", "")
            lines.append(f"  {name}:")
            lines.append(f"    source: {source}")
            lines.append(f'    description: ""')
            lines.append("")
    else:
        lines = ["agents: {}  # no agents detected"]
    agents_section = "\n".join(lines) + "\n\n"

    # Build tools section
    if tools:
        tlines = ["# TOOLS - discovered by scan", "tools:"]
        for t in tools:
            name = t["name"]
            source = t.get("file_path", "")
            tool_type = _infer_tool_type(t)
            tlines.append(f"  {name}:")
            tlines.append(f"    source: {source}")
            tlines.append(f"    type: {tool_type}")
            tlines.append("")
    else:
        tlines = ["tools: {}  # no tools detected"]
    tools_section = "\n".join(tlines) + "\n\n"

    # Build ODD section (commented)
    tool_names = [t["name"] for t in tools]
    odd_section = textwrap.dedent("""\
        # ODD (Operational Boundaries)              [requires Pro]
        # odd:
        #   enforcement_mode: enforce
        #   agents:
        #     agent_name:
        #       permitted_tools: [tool_a, tool_b]
        #       forbidden_tools: [tool_c]
        #       max_actions_per_minute: 30

    """)

    magnitude_section = textwrap.dedent("""\
        # MAGNITUDE LIMITS                          [requires Pro]
        # magnitude:
        #   max_spend_per_action_usd: 10.00
        #   max_spend_per_session_usd: 50.00
        #   max_tokens_per_call: 4000
        #   max_records_per_action: 100

    """)

    dlp_section = textwrap.dedent("""\
        # DLP (Data Loss Prevention)
        dlp:
          mode: audit        # audit | enforce | off

    """)

    cb_section = textwrap.dedent("""\
        # CIRCUIT BREAKER
        circuit_breaker:
          agent_level:
            failure_threshold: 10
            time_window_seconds: 300
            recovery_timeout_seconds: 60

    """)

    injection_section = textwrap.dedent("""\
        # PROMPT INJECTION DETECTION                [requires Pro]
        # injection_detection:
        #   mode: enforce
        #   sensitivity: medium

    """)

    audit_section = textwrap.dedent("""\
        # AUDIT TRAIL
        audit:
          enabled: true

    """)

    hitl_section = textwrap.dedent("""\
        # HITL (Human-in-the-Loop)                  [requires Pro]
        # hitl:
        #   mode: enforce
        #   triggers:
        #     tool_types: [write, execute, payment]
        #   timeout_action: reject
        #   approval_timeout_minutes: 30

    """)

    ci_section = textwrap.dedent("""\
        # CI/CD                                     [requires Starter]
        # ci:
        #   threshold: 70
        #   fail_on: [critical, high]
    """)

    return (
        header
        + agents_section
        + tools_section
        + odd_section
        + magnitude_section
        + dlp_section
        + cb_section
        + injection_section
        + audit_section
        + hitl_section
        + ci_section
    )


def _apply_balanced_overrides(config: dict) -> dict:
    """Apply balanced preset overrides to a config dict."""
    config["governance_level"] = "balanced"

    # DLP: audit -> enforce
    if "dlp" not in config:
        config["dlp"] = {}
    config["dlp"]["mode"] = "enforce"

    # ODD: audit -> enforce
    if "odd" in config and isinstance(config["odd"], dict):
        config["odd"]["enforcement_mode"] = "enforce"

    # HITL: timeout_action -> reject
    if "hitl" in config and isinstance(config["hitl"], dict):
        config["hitl"]["timeout_action"] = "reject"
        if config["hitl"].get("mode") == "audit":
            config["hitl"]["mode"] = "enforce"

    return config


def _apply_strict_overrides(config: dict) -> dict:
    """Apply strict preset overrides to a config dict."""
    config["governance_level"] = "strict"

    # DLP enforce
    if "dlp" not in config:
        config["dlp"] = {}
    config["dlp"]["mode"] = "enforce"

    # ODD enforce
    if "odd" in config and isinstance(config["odd"], dict):
        config["odd"]["enforcement_mode"] = "enforce"

    # HITL enforce + reject
    if "hitl" not in config:
        config["hitl"] = {}
    config["hitl"]["mode"] = "enforce"
    config["hitl"]["timeout_action"] = "reject"

    # Intent verification enforce
    if "intent_verification" not in config:
        config["intent_verification"] = {}
    config["intent_verification"]["mode"] = "enforce"
    config["intent_verification"]["anti_replay"] = True

    # Audit cryptographic
    if "audit" not in config:
        config["audit"] = {}
    config["audit"]["enabled"] = True
    config["audit"]["cryptographic"] = True
    config["audit"]["retention_days"] = 90

    # Magnitude enforce
    if "magnitude" in config and isinstance(config["magnitude"], dict):
        config["magnitude"]["enforcement_mode"] = "enforce"

    return config


# ------------------------------------------------------------------
# CLI Command
# ------------------------------------------------------------------

@click.command()
@click.option("--api-key", envvar="DRAKO_API_KEY", help="API key (or set DRAKO_API_KEY)")
@click.option(
    "--framework",
    type=click.Choice(["crewai", "langgraph", "autogen", "generic"], case_sensitive=False),
    help="Override framework auto-detection",
)
@click.option("--endpoint", default="https://api.useagentmesh.com", help="Custom endpoint")
@click.option("--autopilot", "mode", flag_value="autopilot", help="Smart defaults from scan (default)")
@click.option("--balanced", "mode", flag_value="balanced", help="Enforcement active with escape hatches")
@click.option("--strict", "mode", flag_value="strict", help="Maximum governance for enterprise")
@click.option("--manual", "mode", flag_value="manual", help="Full YAML with all sections for editing")
@click.option("--template", "template_name", default=None, help="Start from industry template (fintech, healthcare, etc.)")
def init(api_key: str | None, framework: str | None, endpoint: str,
         mode: str | None, template_name: str | None) -> None:
    """Initialize Drako in your current project."""

    # Default mode is autopilot
    if not mode:
        mode = "autopilot"

    click.echo()
    click.secho("  Drako Init", fg="cyan", bold=True)
    mode_label = mode if not template_name else f"{mode} + template:{template_name}"
    click.echo(click.style(f"  Mode: {mode_label}", fg="white"))
    click.echo()

    # ---- Step 1: detect framework ----
    if not framework:
        detected = detect_framework(".")
        if detected:
            framework = detected
            click.echo(click.style("  [detect] ", fg="green") + f"Detected {framework} project")
        else:
            framework = "generic"
            click.echo(click.style("  [detect] ", fg="yellow") + "No specific framework detected. Using generic setup.")
    else:
        click.echo(click.style("  [detect] ", fg="green") + f"Using framework: {framework}")

    # ---- Step 2: load or run scan ----
    from drako.cli.scan_cache import load_scan_cache, save_scan_cache, ensure_gitignore_cache

    scan_data = load_scan_cache(".")
    if scan_data:
        scanned_at = scan_data.get("scanned_at", "")
        age_label = "recently"
        try:
            scan_time = datetime.fromisoformat(scanned_at)
            age_seconds = (datetime.now(timezone.utc) - scan_time).total_seconds()
            if age_seconds < 120:
                age_label = f"{int(age_seconds)} seconds ago"
            else:
                age_label = f"{int(age_seconds / 60)} minutes ago"
        except (ValueError, TypeError):
            pass

        n_agents = len(scan_data.get("agents", []))
        n_tools = len(scan_data.get("tools", []))
        n_models = len(scan_data.get("models", []))
        score = scan_data.get("score", "?")
        fw_name = scan_data.get("framework", framework) or framework
        fw_ver = scan_data.get("framework_version", "")

        click.echo(click.style("  [scan]   ", fg="green") + f"Found cached scan results ({age_label})")
        fw_display = f"{fw_name} {fw_ver}".strip() if fw_ver else fw_name
        click.echo(f"           Project: {scan_data.get('project_name', '.')} | Framework: {fw_display}")
        click.echo(f"           Agents: {n_agents} | Tools: {n_tools} | Models: {n_models} | Score: {score}/100")
    else:
        click.echo(click.style("  [scan]   ", fg="yellow") + "No cached scan found. Running scan first...")
        click.echo()
        from drako.cli.scanner import run_scan
        result = run_scan(".")
        save_scan_cache(result, ".")
        ensure_gitignore_cache(".")
        scan_data = load_scan_cache(".", max_age_seconds=9999)
        click.echo()
        click.echo(click.style("  [scan]   ", fg="green") + "Scan complete. Using results for config generation.")

    # ---- Step 3: get API key ----
    click.echo()
    if not api_key:
        env_key = os.environ.get("DRAKO_API_KEY")
        if env_key:
            api_key = env_key
            click.echo(click.style("  [auth]   ", fg="green") + "Using API key from DRAKO_API_KEY env var")
        else:
            click.echo("  Get a free API key at: " + click.style("https://app.useagentmesh.com/signup", fg="cyan", underline=True))
            api_key = click.prompt("  Enter your API key", hide_input=False)

    # ---- Step 4: validate API key ----
    click.echo(click.style("  [auth]   ", fg="green") + "Validating API key...")
    tenant_plan = "free"
    try:
        import httpx

        with httpx.Client(timeout=10.0) as http:
            resp = http.get(
                f"{endpoint.rstrip('/')}/api/v1/stats",
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code == 401:
            click.secho("  [error]  Invalid API key. Get one at https://app.useagentmesh.com/signup", fg="red")
            raise SystemExit(1)
        if resp.status_code >= 400:
            click.secho(f"  [warn]   Could not validate key (HTTP {resp.status_code}). Continuing anyway.", fg="yellow")
        else:
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            tenant_plan = data.get("plan", "free")
            click.echo(click.style("  [auth]   ", fg="green") + f"Key validated | Plan: {tenant_plan.capitalize()}")
    except (Exception,):
        click.secho("  [warn]   Could not reach backend. Continuing in offline mode.", fg="yellow")

    # Extract tenant_id from key
    parts = api_key.split("_")
    tenant_id = parts[2] if len(parts) >= 3 else "default"

    # ---- Step 5: check for existing config ----
    config_path = Path(_CONFIG_FILENAME)
    if config_path.exists():
        click.echo()
        click.echo(click.style("  [config] ", fg="yellow") + f"{_CONFIG_FILENAME} already exists.")
        choice = click.prompt(
            "           [o]verwrite  [m]erge new tools  [s]kip",
            type=click.Choice(["o", "m", "s"], case_sensitive=False),
            default="s",
        )
        if choice == "s":
            click.echo("  Aborted.")
            return
        if choice == "m":
            try:
                existing = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
                endpoint = existing.get("endpoint", endpoint)
                tenant_id = existing.get("tenant_id", tenant_id)
            except yaml.YAMLError:
                pass

    # ---- Step 6: generate .drako.yaml ----
    fw_version = scan_data.get("framework_version") if scan_data else None

    if mode == "manual":
        yaml_content = _generate_manual_yaml(
            tenant_id=tenant_id,
            endpoint=endpoint,
            framework=framework,
            framework_version=fw_version,
            scan_data=scan_data,
        )
    else:
        # autopilot, balanced, or strict all start from autopilot base
        yaml_content = _generate_autopilot_yaml(
            tenant_id=tenant_id,
            endpoint=endpoint,
            framework=framework,
            scan_data=scan_data,
        )

        # For balanced/strict, parse and apply overrides
        if mode in ("balanced", "strict"):
            config_dict = yaml.safe_load(yaml_content.split("\n#\n")[-1]) or {}
            # Re-parse the full yaml content
            lines = yaml_content.split("\n")
            comment_lines = [l for l in lines if l.startswith("#")]
            body_lines = [l for l in lines if not l.startswith("#")]
            config_dict = yaml.safe_load("\n".join(body_lines)) or {}

            if mode == "balanced":
                config_dict = _apply_balanced_overrides(config_dict)
            else:
                config_dict = _apply_strict_overrides(config_dict)

            header = "\n".join(comment_lines) + "\n"
            header = header.replace("Autopilot Configuration", f"{mode.capitalize()} Configuration")
            header = header.replace("audit mode - logging, not blocking", f"{mode} mode - enforcement active")
            yaml_body = yaml.dump(config_dict, default_flow_style=False, sort_keys=False, allow_unicode=True)
            yaml_content = header + yaml_body

    # Apply template if specified
    if template_name:
        try:
            from drako.templates import load_template, deep_merge
            template_data = load_template(template_name)
            # Parse current config
            lines = yaml_content.split("\n")
            comment_lines = [l for l in lines if l.startswith("#")]
            body_lines = [l for l in lines if not l.startswith("#")]
            config_dict = yaml.safe_load("\n".join(body_lines)) or {}
            # Merge: user config overrides template
            merged = deep_merge(template_data, config_dict)
            merged["extends"] = template_name
            header = "\n".join(comment_lines) + "\n"
            yaml_body = yaml.dump(merged, default_flow_style=False, sort_keys=False, allow_unicode=True)
            yaml_content = header + yaml_body
        except Exception as exc:
            click.secho(f"  [warn]   Could not load template '{template_name}': {exc}", fg="yellow")

    config_path.write_text(yaml_content, encoding="utf-8")

    n_agents = len(scan_data.get("agents", [])) if scan_data else 0
    n_tools = len(scan_data.get("tools", [])) if scan_data else 0
    click.echo()
    click.echo(click.style("  [ok] ", fg="green") + f"Created {_CONFIG_FILENAME} ({mode} mode, {n_agents} agents, {n_tools} tools)")

    # ---- Step 7: ensure cache dir in .gitignore ----
    ensure_gitignore_cache(".")

    # ---- Step 8: suggest .env for API key ----
    env_path = Path(".env")
    if env_path.exists():
        env_content = env_path.read_text(encoding="utf-8")
        if "DRAKO_API_KEY" not in env_content:
            click.echo(click.style("  [hint]   ", fg="yellow") + f"Add to .env: DRAKO_API_KEY={api_key}")
    else:
        if os.name == "nt":
            click.echo(click.style("  [hint]   ", fg="yellow") + f'Set env var: $env:DRAKO_API_KEY = "{api_key}"')
        else:
            click.echo(click.style("  [hint]   ", fg="yellow") + f"Set env var: export DRAKO_API_KEY={api_key}")

    # ---- Step 9: print summary and next steps ----
    click.echo()
    if mode == "autopilot":
        # Show what was auto-configured
        click.secho("  Generated with smart defaults:", fg="white", bold=True)
        click.echo()
        agents_data = scan_data.get("agents", []) if scan_data else []
        tools_data = scan_data.get("tools", []) if scan_data else []
        score_val = scan_data.get("score", "?") if scan_data else "?"
        click.echo(f"    ODD:    Each agent locked to its discovered tools")
        click.echo(f"    DLP:    Audit mode (logging PII, not blocking yet)")
        click.echo(f"    CB:     Threshold 5 failures / 60s window")
        click.echo(f"    HITL:   Active for write/execute tools (auto-allow on timeout)")
        click.echo(f"    Audit:  Enabled, tracking all actions")
        click.echo(f"    FinOps: Cost tracking enabled")
        click.echo()
        click.echo("  Everything starts in audit mode - observe before enforcing.")

    click.echo()
    click.secho("  Next steps:", fg="cyan", bold=True)
    click.echo()
    click.echo("  1. Add governance to your code (one line):")
    click.echo(click.style("     from drako import govern", fg="white"))
    click.echo(click.style("     crew = govern(crew)  # or graph = govern(graph)", fg="white"))
    click.echo()
    click.echo("  2. Run: " + click.style("drako push", fg="cyan") + "        Sync to platform")
    if mode == "autopilot":
        click.echo("  3. Run: " + click.style("drako upgrade", fg="cyan") + "     When ready for enforcement")
    click.echo("     Run: " + click.style("drako init --manual", fg="cyan") + "  Full control over every setting")
    click.echo()
