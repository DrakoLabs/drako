"""`drako kernel` — Operator keygen, one-shot ConsentToken signing, and hermetic benchmarks."""

from __future__ import annotations

import contextlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click


@click.group(name="kernel")
def kernel() -> None:
    """Authority Kernel utilities: keygen, operator consent signing, and benchmarks."""


@kernel.command(name="keygen")
@click.option("--out-dir", default=".drako/keys", help="Directory to write Ed25519 keypair")
@click.option("--name", default="operator", help="Key filename prefix (default: operator)")
@click.option("--force", is_flag=True, help="Overwrite existing key files")
def keygen(out_dir: str, name: str, force: bool) -> None:
    """Generate an Ed25519 keypair (mode 0600 on private key; keep off target agent nodes)."""
    from drako.kernel.receipts import generate_keypair, pubkey_fingerprint

    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    priv_path = dest / f"{name}.key"
    pub_path = dest / f"{name}.pub"
    if (priv_path.exists() or pub_path.exists()) and not force:
        raise click.ClickException(f"Key files already exist in {dest} (pass --force to overwrite)")

    priv_pem, pub_pem = generate_keypair()
    priv_path.write_text(priv_pem, encoding="utf-8")
    pub_path.write_text(pub_pem, encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(priv_path, 0o600)

    click.echo(click.style("  [keygen] ", fg="green") + f"Private key: {priv_path} (mode 0600 — keep off target agent nodes)")
    click.echo(click.style("  [keygen] ", fg="green") + f"Public key:  {pub_path}")
    click.echo(f"           Fingerprint: {pubkey_fingerprint(pub_pem)}")


@kernel.command(name="sign-consent")
@click.option("--action-hash", required=True, help="JCS SHA-256 args_hash from the approval seam")
@click.option("--key", "key_path", required=True, type=click.Path(exists=True), help="Operator Ed25519 private key PEM")
@click.option("--issuer", required=True, help="Operator identity (e.g. human:alice)")
@click.option("--ttl-seconds", default=300, type=int, help="Consent validity window in seconds (default: 300)")
@click.option("--token-id", default=None, help="Optional explicit token ID")
def sign_consent(
    action_hash: str,
    key_path: str,
    issuer: str,
    ttl_seconds: int,
    token_id: str | None,
) -> None:
    """One-shot operator signing of an anti-TOCTOU ConsentToken (AI proposes, human signs)."""
    import uuid

    from drako.kernel.authority import sign_consent_token

    priv = Path(key_path).read_text(encoding="utf-8")
    tid = token_id or f"ct_{uuid.uuid4().hex[:12]}"
    expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
    tok = sign_consent_token(
        token_id=tid,
        issuer=issuer,
        action_hash=action_hash,
        expires_at=expires,
        operator_private_pem=priv,
    )
    click.echo(json.dumps(tok.to_dict(), indent=2))


@kernel.command(name="bench")
@click.option("--iterations", default=200, type=int, help="Iterations per micro-benchmark (default: 200)")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def bench(iterations: int, output_format: str) -> None:
    """Run hermetic, reproducible Authority Kernel + MPBench verification benchmarks."""
    from drako.kernel import ACS_SPEC_PIN
    from drako.kernel.authority import Label, TrustLevel, sign_consent_token
    from drako.kernel.envelope import Guardian, args_hash
    from drako.kernel.host import Host, HostConfig
    from drako.kernel.memory_gate import authorize_memory_write
    from drako.kernel.receipts import generate_keypair, verify_chain

    op_priv, op_pub = generate_keypair()
    host_priv, host_pub = generate_keypair()
    profile = {
        "spec_pin": ACS_SPEC_PIN,
        "default_effect": "deny",
        "tools": {
            "search": {"id": "rule:search", "effect": "allow"},
            "delete_db": {"id": "rule:delete-db", "effect": "deny", "approval_liftable": True},
        },
    }
    host = Host(
        Guardian(profile),
        HostConfig(
            agent_id="bench-agent",
            private_pem=host_priv,
            public_pem=host_pub,
            operator_public_pem=op_pub,
            enable_loop_breaker=False,
        ),
    )

    # 1. Policy eval + Ed25519 receipt throughput
    t0 = time.perf_counter()
    receipts = []
    user_lbl = Label("user:bench", TrustLevel.USER, frozenset({"read", "write", "irreversible"}))
    for i in range(iterations):
        d, r = host.govern_tool_call("search", {"q": f"item-{i}"}, [user_lbl], side_effect_class="read")
        assert d.verdict == "permit" and r is not None
        receipts.append(r)
    eval_ms = (time.perf_counter() - t0) * 1000.0

    # 2. Chain verification throughput
    t1 = time.perf_counter()
    ok, _ = verify_chain(receipts, host_pub)
    verify_ms = (time.perf_counter() - t1) * 1000.0

    # 3. Deterministic security scenario checks (ASI01/02/06/08)
    scenarios: list[dict[str, Any]] = []
    # S1: Untrusted tool output cannot execute write
    d_launder, _ = host.govern_tool_call(
        "search", {"q": "x"}, [Label("tool:ext", TrustLevel.UNTRUSTED, frozenset({"read"}))], side_effect_class="write"
    )
    scenarios.append({"id": "ASI01-untrusted-write-deny", "passed": d_launder.verdict == "deny"})

    # S2: Irreversible without consent denied, lifted with operator-signed ConsentToken
    args_del = {"db": "prod"}
    d_no_ct, _ = host.govern_tool_call("delete_db", args_del, [user_lbl], side_effect_class="irreversible")
    ct = sign_consent_token(
        token_id="bench-ct",
        issuer="human:bench",
        action_hash=args_hash(args_del),
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        operator_private_pem=op_priv,
    )
    d_with_ct, _ = host.govern_tool_call(
        "delete_db", args_del, [user_lbl], side_effect_class="irreversible", consent_token=ct
    )
    scenarios.append({"id": "ASI02-signed-consent-anti-toctou", "passed": d_no_ct.verdict == "deny" and d_with_ct.verdict == "permit"})

    # S3: MPBench sourceless/immortal memory write denied
    m_bad = authorize_memory_write([Label("tool:web", TrustLevel.TOOL, frozenset({"read"}))], "mem-1")
    m_good = authorize_memory_write(
        [Label("memory:ok", TrustLevel.AGENT, frozenset({"memory_write"}), ttl_seconds=60)], "mem-1"
    )
    scenarios.append({"id": "ASI06-memory-gate-origin-ttl", "passed": m_bad.verdict == "deny" and m_good.verdict == "permit"})

    report = {
        "spec_pin": ACS_SPEC_PIN,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "iterations": iterations,
        "metrics": {
            "govern_plus_ed25519_total_ms": round(eval_ms, 2),
            "govern_plus_ed25519_per_call_ms": round(eval_ms / max(iterations, 1), 3),
            "chain_verify_total_ms": round(verify_ms, 2),
            "chain_valid": ok,
        },
        "scenarios": scenarios,
        "all_passed": ok and all(s["passed"] for s in scenarios),
    }

    if output_format == "json":
        click.echo(json.dumps(report, indent=2))
    else:
        click.echo()
        click.secho("  Drako Authority Kernel Benchmark (Hermetic)", fg="cyan", bold=True)
        click.echo(f"  Python {report['environment']['python']} | {report['environment']['platform']}")
        click.echo(f"  Govern + Ed25519 receipt: {report['metrics']['govern_plus_ed25519_per_call_ms']} ms/call ({iterations} calls)")
        click.echo(f"  Chain verify ({iterations}):      {report['metrics']['chain_verify_total_ms']} ms (valid={ok})")
        for s in scenarios:
            tag = click.style("PASS", fg="green") if s["passed"] else click.style("FAIL", fg="red")
            click.echo(f"  [{tag}] {s['id']}")
        click.echo()

    if not report["all_passed"]:
        raise SystemExit(1)
