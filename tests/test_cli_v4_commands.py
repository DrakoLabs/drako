"""CLI tests for Drako v4 canonical commands: kernel, a2a, drift, mcp agbom, upgrade --v4, why, verify."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from drako.cli.main import cli
from drako.kernel import ACS_SPEC_PIN
from drako.kernel.authority import Label, TrustLevel
from drako.kernel.envelope import Guardian
from drako.kernel.host import Host, HostConfig
from drako.kernel.receipts import generate_keypair


def test_kernel_keygen_sign_consent_and_bench(tmp_path: Path):
    runner = CliRunner()
    key_dir = tmp_path / "keys"
    res = runner.invoke(cli, ["kernel", "keygen", "--out-dir", str(key_dir), "--name", "op"])
    assert res.exit_code == 0, res.output
    assert (key_dir / "op.key").exists() and (key_dir / "op.pub").exists()

    res_ct = runner.invoke(
        cli,
        [
            "kernel", "sign-consent",
            "--action-hash", "deadbeef",
            "--key", str(key_dir / "op.key"),
            "--issuer", "human:alice",
        ],
    )
    assert res_ct.exit_code == 0, res_ct.output
    tok = json.loads(res_ct.output)
    assert tok["issuer"] == "human:alice"
    assert tok["action_hash"] == "deadbeef"
    assert tok["signature"]

    res_bench = runner.invoke(cli, ["kernel", "bench", "--iterations", "20", "--format", "json"])
    assert res_bench.exit_code == 0, res_bench.output
    report = json.loads(res_bench.output)
    assert report["all_passed"] is True
    assert report["metrics"]["chain_valid"] is True


def test_a2a_sign_verify_inspect_cli(tmp_path: Path):
    runner = CliRunner()
    priv, pub = generate_keypair()
    priv_p = tmp_path / "op.key"
    pub_p = tmp_path / "op.pub"
    card_p = tmp_path / "agent-card.json"
    priv_p.write_text(priv, encoding="utf-8")
    pub_p.write_text(pub, encoding="utf-8")
    card_p.write_text(json.dumps({"name": "Bot", "url": "https://bot.example.com", "skills": []}), encoding="utf-8")

    r_sign = runner.invoke(cli, ["a2a", "sign", str(card_p), "--key", str(priv_p), "--kid", "did:ex:1#k1"])
    assert r_sign.exit_code == 0, r_sign.output

    r_ver = runner.invoke(cli, ["a2a", "verify", str(card_p), "--pubkey", str(pub_p), "--format", "json"])
    assert r_ver.exit_code == 0, r_ver.output
    assert json.loads(r_ver.output)["valid"] is True

    r_insp = runner.invoke(cli, ["a2a", "inspect", str(card_p)])
    assert r_insp.exit_code == 0, r_insp.output
    assert json.loads(r_insp.output)["signatures_count"] == 1


def test_drift_and_mcp_agbom_and_upgrade_v4(tmp_path: Path):
    runner = CliRunner()

    # 1. drako upgrade --v4 idempotency
    cfg_p = tmp_path / ".drako.yaml"
    cfg_p.write_text(
        "version: '1.0'\ntenant_id: acme\napi_key_env: DRAKO_API_KEY\nendpoint: https://api.getdrako.com\n",
        encoding="utf-8",
    )
    r_up = runner.invoke(cli, ["upgrade", "--v4", "--config", str(cfg_p), "-y"])
    assert r_up.exit_code == 0, r_up.output
    migrated = cfg_p.read_text(encoding="utf-8")
    assert "api_key_env" not in migrated
    assert "AGENT-HOOKS-0.1" in migrated
    # Second run is a no-op (idempotent)
    r_up2 = runner.invoke(cli, ["upgrade", "--v4", "--config", str(cfg_p), "-y"])
    assert r_up2.exit_code == 0 and "up to date" in r_up2.output

    # 2. drako mcp agbom (CycloneDX 1.7)
    lock_p = tmp_path / "mcp.lock"
    lock_p.write_text(
        json.dumps({
            "version": 1,
            "servers": {"@mcp/fs": {"version": "1.0.0", "integrity": "sha512-AQID"}},
        }),
        encoding="utf-8",
    )
    r_ag = runner.invoke(cli, ["mcp", "agbom", "--lock", str(lock_p), "--format", "cyclonedx"])
    assert r_ag.exit_code == 0, r_ag.output
    cdx = json.loads(r_ag.output)
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.7"

    # 3. drako drift clean vs drifted
    prof_p = tmp_path / "drako-policy.yaml"
    prof_p.write_text(
        "spec_pin: AGENT-HOOKS-0.1\ndefault_effect: deny\ntools:\n  search:\n    id: t1\n    effect: allow\n",
        encoding="utf-8",
    )
    base_p = tmp_path / "last_scan.json"
    base_p.write_text(json.dumps({"tools": [{"name": "search", "expected_effect": "allow"}]}), encoding="utf-8")
    r_clean = runner.invoke(cli, ["drift", "--profile", str(prof_p), "--baseline", str(base_p), "--format", "json"])
    assert r_clean.exit_code == 0, r_clean.output
    assert json.loads(r_clean.output)["clean"] is True

    # Add extra tool to profile -> widened drift fails non-zero
    prof_p.write_text(
        "spec_pin: AGENT-HOOKS-0.1\ndefault_effect: deny\ntools:\n  search:\n    id: t1\n    effect: allow\n  shell:\n    id: t2\n    effect: allow\n",
        encoding="utf-8",
    )
    r_drift = runner.invoke(cli, ["drift", "--profile", str(prof_p), "--baseline", str(base_p), "--format", "json"])
    assert r_drift.exit_code == 1
    assert json.loads(r_drift.output)["blocking_count"] == 1


def test_why_and_verify_end_to_end(tmp_path: Path):
    runner = CliRunner()
    priv, pub = generate_keypair()
    pub_p = tmp_path / "host.pub"
    store_p = tmp_path / "receipts.jsonl"
    pub_p.write_text(pub, encoding="utf-8")

    host = Host(
        Guardian({"spec_pin": ACS_SPEC_PIN, "default_effect": "deny", "tools": {"search": {"id": "r1", "effect": "allow"}}}),
        HostConfig(agent_id="a1", store_path=str(store_p), private_pem=priv, public_pem=pub),
    )
    _, r1 = host.govern_tool_call("search", {"q": "ok"}, [Label("user:u1", TrustLevel.USER, frozenset({"read"}))], side_effect_class="read")
    assert r1 is not None

    r_why = runner.invoke(cli, ["why", r1["receipt_id"], "--store", str(store_p), "--pubkey-file", str(pub_p), "--format", "json"])
    assert r_why.exit_code == 0, r_why.output
    g = json.loads(r_why.output)
    assert g["signature_verified"] is True

    r_ver = runner.invoke(cli, ["verify", str(store_p), "--pubkey-file", str(pub_p), "--format", "json"])
    assert r_ver.exit_code == 0, r_ver.output
    assert json.loads(r_ver.output)["valid"] is True
