"""`drako a2a` — Sign, verify, and inspect A2A v1.0 Agent Cards (RFC 7515 JWS + RFC 8785 JCS)."""

from __future__ import annotations

import json
from pathlib import Path

import click


@click.group(name="a2a")
def a2a() -> None:
    """Sign and verify A2A v1.0 Agent Cards (RFC 7515 Detached JWS + JCS)."""


@a2a.command(name="sign")
@click.argument("card_path", type=click.Path(exists=True))
@click.option("--key", "key_path", required=True, type=click.Path(exists=True), help="Operator Ed25519 private key PEM")
@click.option("--kid", required=True, help="Key identifier (e.g. did:example:org#sig1)")
@click.option("--ttl-days", default=90, type=int, help="Signature validity in days (default: 90)")
@click.option("--output", "-o", default=None, help="Output file path (default: overwrite CARD_PATH)")
def sign_cmd(card_path: str, key_path: str, kid: str, ttl_days: int, output: str | None) -> None:
    """Operator-side signing of an A2A v1.0 agent-card.json."""
    from drako.a2a.cards import card_fingerprint, sign_agent_card

    card = json.loads(Path(card_path).read_text(encoding="utf-8"))
    priv = Path(key_path).read_text(encoding="utf-8")
    signed = sign_agent_card(card, priv, kid=kid, ttl_days=ttl_days)
    dest = Path(output or card_path)
    dest.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
    click.echo(click.style("  [signed] ", fg="green") + f"{dest} (kid={kid}, fp={card_fingerprint(signed)})")


@a2a.command(name="verify")
@click.argument("card_path", required=False, default=None, type=click.Path(exists=True))
@click.option("--url", default=None, help="Remote /.well-known/agent-card.json URL (SSRF-guarded)")
@click.option("--pubkey", "pubkey_path", required=True, type=click.Path(exists=True), help="Trusted Ed25519 public key PEM")
@click.option("--kid", "expected_kid", default=None, help="Require a specific kid in protected JWS header")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def verify_cmd(
    card_path: str | None,
    url: str | None,
    pubkey_path: str,
    expected_kid: str | None,
    output_format: str,
) -> None:
    """Verify an A2A v1.0 Agent Card's RFC 7515 JWS signature offline or via SSRF-guarded fetch."""
    from drako.a2a.cards import card_fingerprint, fetch_and_verify_agent_card, verify_agent_card

    if not card_path and not url:
        raise click.UsageError("Provide either CARD_PATH or --url")
    pub = Path(pubkey_path).read_text(encoding="utf-8")
    if url:
        card, ok = fetch_and_verify_agent_card(url, pub, expected_kid=expected_kid)
    else:
        card = json.loads(Path(card_path).read_text(encoding="utf-8"))  # type: ignore[arg-type]
        ok = verify_agent_card(card, pub, expected_kid=expected_kid)

    fp = card_fingerprint(card) if isinstance(card, dict) else ""
    if output_format == "json":
        click.echo(json.dumps({"valid": ok, "fingerprint": fp, "name": card.get("name", "") if isinstance(card, dict) else ""}))
    else:
        click.echo(
            click.style("  [verify] ", fg="green" if ok else "red")
            + (f"A2A JWS signature VALID ({fp})" if ok else f"A2A JWS signature INVALID ({fp})")
        )
    if not ok:
        raise SystemExit(1)


@a2a.command(name="inspect")
@click.argument("card_path", type=click.Path(exists=True))
def inspect_cmd(card_path: str) -> None:
    """Inspect an A2A v1.0 Agent Card's canonical fingerprint and signature headers."""
    from drako.a2a.cards import _b64url_decode, card_fingerprint

    card = json.loads(Path(card_path).read_text(encoding="utf-8"))
    sigs = card.get("signatures") or []
    headers = []
    for s in sigs:
        if isinstance(s, dict) and isinstance(s.get("protected"), str):
            try:
                headers.append(json.loads(_b64url_decode(s["protected"]).decode("utf-8")))
            except Exception:
                headers.append({"error": "unparseable protected header"})
    click.echo(
        json.dumps(
            {
                "name": card.get("name"),
                "url": card.get("url"),
                "fingerprint": card_fingerprint(card),
                "signatures_count": len(sigs),
                "protected_headers": headers,
            },
            indent=2,
        )
    )
