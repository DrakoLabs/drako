"""Sprint 2 #1 (SDK side): `drako mcp pin` (2026-09-04). npm mocked."""

import json

from click.testing import CliRunner

from drako.cli.main import cli


def _fake_run_factory(version="1.2.3", integrity="sha512-mockedhash"):
    def fake_run(cmd, **kwargs):
        field = cmd[3]
        value = version if field == "version" else integrity

        class Proc:
            returncode = 0
            stdout = json.dumps(value)
            stderr = ""

        fake_run.seen.append(cmd)
        return Proc()

    fake_run.seen = []
    return fake_run


def test_pin_writes_lock(monkeypatch, tmp_path):
    import drako.cli.pin_command as pin_mod

    monkeypatch.setattr(pin_mod.subprocess, "run", _fake_run_factory())
    lock = tmp_path / "mcp.lock"
    result = CliRunner().invoke(cli, [
        "mcp", "pin", "my-tool", "--lock", str(lock), "--by", "op",
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(lock.read_text())
    entry = data["servers"]["my-tool"]
    assert entry["version"] == "1.2.3"
    assert entry["integrity"] == "sha512-mockedhash"
    assert entry["pinned_by"] == "op"
    assert "pinned my-tool@1.2.3" in result.output


def test_pin_explicit_version_confirmed(monkeypatch, tmp_path):
    import drako.cli.pin_command as pin_mod

    fake = _fake_run_factory(version="9.9.9")
    monkeypatch.setattr(pin_mod.subprocess, "run", fake)
    lock = tmp_path / "mcp.lock"
    result = CliRunner().invoke(cli, [
        "mcp", "pin", "my-tool@9.9.9", "--lock", str(lock),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(lock.read_text())
    assert data["servers"]["my-tool"]["version"] == "9.9.9"


def test_pin_rejects_unusable_integrity(monkeypatch, tmp_path):
    import drako.cli.pin_command as pin_mod

    monkeypatch.setattr(
        pin_mod.subprocess, "run", _fake_run_factory(integrity="md5-weak")
    )
    lock = tmp_path / "mcp.lock"
    result = CliRunner().invoke(cli, [
        "mcp", "pin", "my-tool", "--lock", str(lock),
    ])
    assert result.exit_code != 0
    assert not lock.exists()


def test_pin_merges_into_existing_lock(monkeypatch, tmp_path):
    import drako.cli.pin_command as pin_mod

    lock = tmp_path / "mcp.lock"
    lock.write_text(json.dumps({
        "version": 1, "servers": {
            "old-tool": {"version": "0.1.0", "integrity": "sha512-old"}
        },
    }))
    monkeypatch.setattr(pin_mod.subprocess, "run", _fake_run_factory())
    result = CliRunner().invoke(cli, [
        "mcp", "pin", "my-tool", "--lock", str(lock),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(lock.read_text())
    assert data["servers"]["old-tool"]["version"] == "0.1.0"  # preserved
    assert data["servers"]["my-tool"]["version"] == "1.2.3"
