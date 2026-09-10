"""P1-07: `drako mcp audit` (2026-09-10). Pure audit tests + CLI exit codes."""

import json

from click.testing import CliRunner

from drako.cli.main import cli
from drako.desktop.discovery import MCPServerConfig
from drako.desktop.mcp_audit import audit_servers


def _srv(name="s1", package="a-tool", source="claude.json", **over):
    base = dict(name=name, command="npx", args=[package], env={},
                transport="stdio", url=None, source_file=source, client="c")
    base.update(over)
    return MCPServerConfig(**base)


def test_ok_when_pinned_listed_clean():
    lock = {"a-tool": {"version": "1.0.0"}}
    (r,) = audit_servers([_srv()], lock=lock, allowed_packages=["a-tool"])
    assert r.verdict == "ok" and r.details == []


def test_unpinned_without_lock():
    (r,) = audit_servers([_srv()], lock={})
    assert r.verdict == "unpinned"
    assert "drako mcp pin" in r.details[0]


def test_unlisted_despite_pin():
    lock = {"a-tool": {"version": "1.0.0"}}
    (r,) = audit_servers([_srv()], lock=lock, allowed_packages=["other"])
    assert r.verdict == "unlisted"


def test_risky_on_rule_hits():
    lock = {"a-tool": {"version": "1.0.0"}}
    (r,) = audit_servers([_srv()], lock=lock,
                         rule_findings={"s1": ["MCP-002", "MCP-005"]})
    assert r.verdict == "risky"
    assert "MCP-002" in r.details[0]


def test_unpinned_beats_risky_ordering():
    (r,) = audit_servers([_srv()], lock={},
                         rule_findings={"s1": ["MCP-002"]})
    assert r.verdict == "unpinned"  # declaration first…
    assert len(r.details) == 2  # …but all details recorded


def test_cli_json_and_exit_codes(monkeypatch, tmp_path):
    lock = tmp_path / "mcp.lock"
    lock.write_text(json.dumps({"version": 1, "servers": {
        "a-tool": {"version": "1.0.0", "integrity": "sha512-x"}}}))

    class FakeAgent:
        mcp_servers = [_srv()]

    class FakeBOM:
        agents = [FakeAgent()]

    monkeypatch.setattr("drako.desktop.discovery.discover_agents",
                        lambda project_dir=".": FakeBOM())
    monkeypatch.setattr(
        "drako.desktop.mcp_rules.evaluate_mcp_rules", lambda bom: [])

    result = CliRunner().invoke(cli, [
        "mcp", "audit", "--lock", str(lock), "--format", "json",
    ])
    assert result.exit_code == 0, result.output
    (entry,) = json.loads(result.output)
    assert entry["verdict"] == "ok"
    assert entry["package"] == "a-tool"


def test_cli_fails_on_unpinned(monkeypatch, tmp_path):
    class FakeAgent:
        mcp_servers = [_srv(package="ghost-tool")]

    class FakeBOM:
        agents = [FakeAgent()]

    monkeypatch.setattr("drako.desktop.discovery.discover_agents",
                        lambda project_dir=".": FakeBOM())
    monkeypatch.setattr(
        "drako.desktop.mcp_rules.evaluate_mcp_rules", lambda bom: [])

    result = CliRunner().invoke(cli, [
        "mcp", "audit", "--lock", str(tmp_path / "absent.lock"),
    ])
    assert result.exit_code == 1
    assert "unpinned" in result.output
