"""`drako verify` — Offline cryptographic verification of receipt chains."""

from __future__ import annotations

import json
from pathlib import Path

import click


@click.command()
@click.argument("receipt_path", required=False, default=None, type=click.Path(exists=True))
@click.option("--receipt", "receipt_opt", default=None, help="Path to a receipt JSON or JSONL chain file")
@click.option("--pubkey-file", default=None, help="Ed25519 public key PEM for signature verification")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def verify(
    receipt_path: str | None,
    receipt_opt: str | None,
    pubkey_file: str | None,
    output_format: str,
) -> None:
    """Verify the integrity and Ed25519 signatures of local Drako receipts (100% offline)."""
    target = receipt_opt or receipt_path or ".drako/receipts.jsonl"
    path = Path(target)
    if not path.exists():
        click.secho(f"  [error]  Receipt file not found: {target}", fg="red", err=True)
        raise SystemExit(1)

    raw_text = path.read_text(encoding="utf-8").strip()
    if not raw_text:
        click.secho("  [error]  Empty receipt file", fg="red", err=True)
        raise SystemExit(1)

    try:
        if raw_text.startswith("[") or raw_text.startswith("{"):
            parsed = json.loads(raw_text)
            receipts = parsed if isinstance(parsed, list) else [parsed]
        else:
            receipts = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
    except ValueError as exc:
        click.secho(f"  [error]  Cannot parse receipt JSON/JSONL: {exc}", fg="red", err=True)
        raise SystemExit(1) from exc

    if not receipts:
        click.secho("  [error]  No receipts found in file", fg="red", err=True)
        raise SystemExit(1)

    if pubkey_file is None:
        prev = None
        for i, r in enumerate(receipts):
            if r.get("prev_hash") != prev:
                msg = f"chain broken at index {i}"
                if output_format == "json":
                    click.echo(json.dumps({"valid": False, "signatures_verified": False, "broken_index": i, "reason": msg}))
                else:
                    click.secho(f"  [error]  {msg}", fg="red")
                raise SystemExit(1)
            prev = r.get("payload_hash")
        if output_format == "json":
            click.echo(json.dumps({"valid": True, "signatures_verified": False, "count": len(receipts)}))
        else:
            click.echo(click.style("  [warn]   ", fg="yellow") + "no --pubkey-file: checked chain links only, signatures UNVERIFIED")
            click.echo(click.style("  [verify] ", fg="green") + f"chain links contiguous ({len(receipts)} receipt(s)) — signatures UNVERIFIED")
        return

    from drako.kernel.receipts import verify_chain, verify_receipt

    pub = Path(pubkey_file).read_text(encoding="utf-8")
    if len(receipts) == 1:
        ok = verify_receipt(receipts[0], pub)
        if output_format == "json":
            click.echo(json.dumps({"valid": ok, "signatures_verified": True, "count": 1}))
        else:
            click.echo(click.style("  [verify] ", fg="green" if ok else "red") + ("signature VALID" if ok else "signature INVALID"))
        if not ok:
            raise SystemExit(1)
        return

    ok, idx = verify_chain(receipts, pub)
    if output_format == "json":
        click.echo(json.dumps({"valid": ok, "signatures_verified": True, "count": len(receipts), "broken_index": idx}))
    elif ok:
        click.echo(click.style("  [verify] ", fg="green") + f"chain VALID ({len(receipts)} receipts, Ed25519 signatures valid)")
    else:
        click.echo(click.style("  [verify] ", fg="red") + f"chain BROKEN at index {idx}")
    if not ok:
        raise SystemExit(1)
