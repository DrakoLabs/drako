"""Regression tests for v4-aware scanner policies and local-first remediation snippets."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from drako import __version__
from drako.cli.formats.sarif import format_sarif
from drako.cli.main import cli
from drako.cli.scanner import run_scan


def test_v4_guarded_project_clears_odd_gov_com_sec_false_positives(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\n"
        "from drako import guard\n\n"
        "researcher = Agent(name='researcher', role='Researcher', tools=['search_docs'])\n"
        "safe = guard(researcher, allow=['search_docs'], receipts='.drako/receipts.jsonl')\n",
        encoding="utf-8",
    )
    (tmp_path / ".drako.yaml").write_text(
        'version: "4.0"\n'
        "project_id: demo\n"
        "kernel:\n"
        "  spec_pin: AGENT-HOOKS-0.1\n"
        "  default_effect: deny\n"
        "  tiers:\n"
        "    irreversible: consent\n"
        "loop_breaker:\n"
        "  enabled: true\n"
        "  trip_threshold: 10\n"
        "finops:\n"
        "  budgets:\n"
        "    daily_usd: 25.0\n"
        "audit:\n"
        "  enabled: true\n"
        "  cryptographic: true\n"
        "  receipt_store: .drako/receipts.jsonl\n"
        "a2a:\n"
        "  mode: enforce\n"
        "  require_signed_cards: true\n"
        "agents:\n"
        "  researcher:\n"
        "    source: agent.py\n",
        encoding="utf-8",
    )
    (tmp_path / "drako-policy.yaml").write_text(
        "spec_pin: AGENT-HOOKS-0.1\n"
        "default_effect: deny\n"
        "tools:\n"
        "  search_docs:\n"
        "    id: tool:search_docs\n"
        "    effect: allow\n",
        encoding="utf-8",
    )

    result = run_scan(str(tmp_path))
    ids = {f.policy_id for f in result.findings}

    for expected_clear in (
        "ODD-001", "ODD-002", "ODD-003", "ODD-004",
        "MAG-001", "MAG-002",
        "ID-002",
        "GOV-001", "GOV-002", "GOV-005",
        "COM-001", "COM-002",
        "SEC-010",
    ):
        assert expected_clear not in ids, f"Unexpected false positive {expected_clear} in {ids}"


def test_vulnerable_scan_has_no_saas_or_dead_v3_remediations(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from crewai import Agent\n\n"
        'api_key = "sk-proj-1234567890abcdef"\n'
        "def write_file(path, data):\n"
        '    with open(path, "w") as f:\n'
        "        f.write(data)\n\n"
        "a1 = Agent(name='a1', role='r1', tools=[write_file])\n"
        "a2 = Agent(name='a2', role='r2', tools=[write_file])\n",
        encoding="utf-8",
    )

    result = run_scan(str(tmp_path))
    assert result.findings, "Expected findings on unguarded agent project"

    for f in result.findings:
        combined = f"{f.message}\n{f.fix_snippet or ''}"
        for forbidden in (
            "Pro plan",
            "Drako dashboard",
            "with_compliance",
            "GovernanceMiddleware(api_key",
            "api.getdrako.com",
            "topology:",
            "chaos:",
            "did_exchange",
        ):
            assert forbidden not in combined, (
                f"Finding {f.policy_id} contains retired v3/SaaS string {forbidden!r}"
            )


def test_sarif_metadata_uses_github_uri_and_live_version(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from crewai import Agent\n"
        "a = Agent(name='a', role='r')\n",
        encoding="utf-8",
    )
    result = run_scan(str(tmp_path))
    sarif = json.loads(format_sarif(result))
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/DrakoLabs/drako"


def test_desktop_sarif_uses_live_version():
    runner = CliRunner()
    res = runner.invoke(cli, ["desktop", "scan", "--format", "sarif"])
    assert res.exit_code in (0, 1), res.output
    sarif = json.loads(res.output)
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/DrakoLabs/drako"
