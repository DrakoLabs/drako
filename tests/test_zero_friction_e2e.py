"""End-to-end zero-friction developer experience tests for Drako v4 CLI."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from drako import __version__
from drako.cli.main import cli
from drako.config import DrakoConfig


def test_zero_friction_new_user_journey(tmp_path: Path):
    """Simulate a brand-new user running init -> validate -> scan -> drift -> templates -> kernel -> bom -> skills."""
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as workdir:
        root = Path(workdir)
        (root / "requirements.txt").write_text("crewai>=0.80.0\ndrako>=4.0.0a1\n", encoding="utf-8")
        (root / "agent.py").write_text(
            "from crewai import Agent\n"
            "from crewai.tools import tool\n"
            "from drako import guard\n\n"
            "@tool\n"
            "def search_docs(query: str) -> str:\n"
            '    """Search internal documentation."""\n'
            '    return f"results for {query}"\n\n'
            "researcher = Agent(\n"
            '    name="researcher",\n'
            '    role="Documentation Researcher",\n'
            "    tools=[search_docs],\n"
            ")\n"
            'safe_researcher = guard(researcher, allow=["search_docs"], receipts=".drako/receipts.jsonl")\n',
            encoding="utf-8",
        )

        # 1. drako init --yes detects framework, agent, and tool live (no prior cache needed)
        r_init = runner.invoke(cli, ["init", "--yes"])
        assert r_init.exit_code == 0, r_init.output
        assert (root / ".drako.yaml").exists()
        assert (root / "drako-policy.yaml").exists()

        cfg = yaml.safe_load((root / ".drako.yaml").read_text(encoding="utf-8"))
        assert cfg["framework"] == "crewai"
        assert "researcher" in cfg.get("agents", {})
        assert "search_docs" in cfg.get("detected_tools", {})
        assert cfg["detected_tools"]["search_docs"]["type"] == "read"

        prof = yaml.safe_load((root / "drako-policy.yaml").read_text(encoding="utf-8"))
        assert "search_docs" in prof.get("tools", {})
        assert prof["tools"]["search_docs"]["effect"] == "allow"

        # 2. drako validate .drako.yaml passes cleanly
        r_val = runner.invoke(cli, ["validate", ".drako.yaml"])
        assert r_val.exit_code == 0, r_val.output
        assert "Result: VALID" in r_val.output

        # 3. drako scan . --format json and --format sarif
        r_json = runner.invoke(cli, ["scan", ".", "--format", "json"])
        assert r_json.exit_code == 0, r_json.output
        scan_data = json.loads(r_json.output)
        finding_ids = {f["policy_id"] for f in scan_data["findings"]}
        for unexpected in ("ODD-001", "GOV-002", "SEC-010"):
            assert unexpected not in finding_ids, f"False positive {unexpected} in {finding_ids}"
        for f in scan_data["findings"]:
            blob = f"{f.get('message', '')}\n{f.get('fix_snippet', '')}"
            assert "Pro plan" not in blob
            assert "with_compliance" not in blob

        r_sarif = runner.invoke(cli, ["scan", ".", "--format", "sarif"])
        assert r_sarif.exit_code == 0, r_sarif.output
        sarif = json.loads(r_sarif.output)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["version"] == __version__
        assert driver["informationUri"] == "https://github.com/DrakoLabs/drako"

        # 4. drako drift works immediately without .drako/.last_scan.json!
        assert not (root / ".drako" / ".last_scan.json").exists()
        r_drift = runner.invoke(cli, ["drift"])
        assert r_drift.exit_code == 0, r_drift.output
        assert "[live]" in r_drift.output
        assert "[clean]" in r_drift.output

        r_drift_json = runner.invoke(cli, ["drift", "--format", "json"])
        assert r_drift_json.exit_code == 0, r_drift_json.output
        drift_payload = json.loads(r_drift_json.output)
        assert drift_payload["clean"] is True
        assert drift_payload["source"] == "live"

        # 5. drako templates (no subcommand) lists templates cleanly
        r_tpl = runner.invoke(cli, ["templates"])
        assert r_tpl.exit_code == 0, r_tpl.output
        for name in ("base", "startup", "fintech", "healthcare", "eu-ai-act", "enterprise"):
            assert name in r_tpl.output

        # 6. drako kernel keygen + bench
        r_key = runner.invoke(cli, ["kernel", "keygen", "--out-dir", ".drako/keys", "--name", "op"])
        assert r_key.exit_code == 0, r_key.output
        assert (root / ".drako" / "keys" / "op.key").exists()

        r_bench = runner.invoke(cli, ["kernel", "bench", "--iterations", "15", "--format", "json"])
        assert r_bench.exit_code == 0, r_bench.output
        assert json.loads(r_bench.output)["all_passed"] is True

        # 7. drako bom --format cyclonedx
        r_bom = runner.invoke(cli, ["bom", ".", "--format", "cyclonedx"])
        assert r_bom.exit_code == 0, r_bom.output
        bom_doc = json.loads(r_bom.output)
        assert bom_doc["bomFormat"] == "CycloneDX"

        # 8. drako desktop skills
        r_skills = runner.invoke(cli, ["desktop", "skills", "."])
        assert r_skills.exit_code == 0, r_skills.output


@pytest.mark.parametrize(
    "template_name,expected_dlp,expected_retention,expected_hitl,expected_a2a",
    [
        ("base", "audit", 7, "audit", "audit"),
        ("startup", "audit", 30, "audit", "audit"),
        ("fintech", "enforce", 365, "enforce", "enforce"),
        ("healthcare", "enforce", 2190, "enforce", "enforce"),
        ("eu-ai-act", "enforce", 3650, "enforce", "enforce"),
        ("enterprise", "enforce", 365, "enforce", "enforce"),
    ],
)
def test_all_six_templates_apply_via_extends_and_validate(
    tmp_path: Path,
    template_name: str,
    expected_dlp: str,
    expected_retention: int,
    expected_hitl: str,
    expected_a2a: str,
):
    """Every template must apply real DrakoConfig fields via `extends:` and pass `drako validate`."""
    runner = CliRunner()
    cfg_file = tmp_path / ".drako.yaml"
    cfg_file.write_text(
        f'version: "4.0"\nproject_id: test-{template_name}\nextends: {template_name}\n',
        encoding="utf-8",
    )

    loaded = DrakoConfig.load(str(cfg_file))
    assert loaded.dlp.mode == expected_dlp
    assert loaded.audit.retention_days == expected_retention
    assert loaded.hitl.mode == expected_hitl
    assert loaded.a2a.mode == expected_a2a

    r_val = runner.invoke(cli, ["validate", str(cfg_file)])
    assert r_val.exit_code == 0, r_val.output
    assert f"Template inherited ({template_name})" in r_val.output
    assert "Result: VALID" in r_val.output


def test_init_and_validate_reject_unknown_template(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        r_init = runner.invoke(cli, ["init", "--template", "nonexistent-preset", "--yes"])
        assert r_init.exit_code != 0
        assert "Unknown template" in r_init.output
        assert not Path(".drako.yaml").exists()

        Path(".drako.yaml").write_text('version: "4.0"\nextends: nonexistent-preset\n', encoding="utf-8")
        r_val = runner.invoke(cli, ["validate", ".drako.yaml"])
        assert r_val.exit_code != 0
        assert "Unknown template" in r_val.output


def test_validate_warns_on_all_seven_retired_v3_keys(tmp_path: Path):
    runner = CliRunner()
    cfg_file = tmp_path / ".drako.yaml"
    cfg_file.write_text(
        'version: "1.0"\n'
        "api_key: k\n"
        "api_key_env: E\n"
        "endpoint: https://example.invalid\n"
        "governance: {}\n"
        "bft: {}\n"
        "chaos: {}\n"
        "topology: {}\n",
        encoding="utf-8",
    )
    res = runner.invoke(cli, ["validate", str(cfg_file)])
    assert res.exit_code == 0, res.output
    for key in ("api_key", "api_key_env", "endpoint", "governance", "bft", "chaos", "topology"):
        assert key in res.output


def test_drift_reads_scanned_at_staleness_and_explicit_missing_baseline(tmp_path: Path):
    runner = CliRunner()
    prof = tmp_path / "drako-policy.yaml"
    prof.write_text(
        "spec_pin: AGENT-HOOKS-0.1\ndefault_effect: deny\ntools:\n  search:\n    id: t1\n    effect: allow\n",
        encoding="utf-8",
    )

    # Missing explicit --baseline points user to --save-cache
    r_miss = runner.invoke(
        cli, ["drift", "--profile", str(prof), "--baseline", str(tmp_path / "missing.json")]
    )
    assert r_miss.exit_code != 0
    assert "--save-cache" in r_miss.output

    # Stale cache using scanned_at triggers advisory stale item
    stale_ts = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    cache = tmp_path / "cache.json"
    cache.write_text(
        json.dumps({"scanned_at": stale_ts, "tools": [{"name": "search", "expected_effect": "allow"}]}),
        encoding="utf-8",
    )
    r_stale = runner.invoke(
        cli, ["drift", "--profile", str(prof), "--baseline", str(cache), "--format", "json"]
    )
    assert r_stale.exit_code == 0, r_stale.output
    payload = json.loads(r_stale.output)
    assert payload["clean"] is True
    assert any(item["kind"] == "stale" for item in payload["items"])


def test_fix_skips_patch_that_would_break_python_syntax(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    from drako.cli.policies.base import Finding

    target = tmp_path / "broken_patch.py"
    original = "x = 1\n"
    target.write_text(original, encoding="utf-8")

    fake_result = SimpleNamespace(
        findings=[
            Finding(
                policy_id="TEST-001",
                category="Security",
                severity="HIGH",
                title="Synthetic broken patch",
                message="Synthetic",
                file_path="broken_patch.py",
                line_number=1,
                code_snippet="x = 1",
                fix_snippet="def invalid(:\n    pass",
            )
        ]
    )
    monkeypatch.setattr("drako.cli.scanner.run_scan", lambda *a, **kw: fake_result)

    runner = CliRunner()
    res = runner.invoke(cli, ["fix", str(tmp_path)])
    assert res.exit_code == 0, res.output
    assert "invalid Python syntax" in res.output
    assert target.read_text(encoding="utf-8") == original


def test_proxy_cli_defaults_to_loopback_host():
    from drako.cli.proxy_command import start

    host_param = next(p for p in start.params if p.name == "host")
    assert host_param.default == "127.0.0.1"
