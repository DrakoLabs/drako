"""`drako why` — answer 'why was this allowed/denied?' from a signed receipt (T7)."""

from __future__ import annotations

import json
from pathlib import Path

import click

DEFAULT_STORE = ".drako/receipts.jsonl"


@click.command()
@click.argument("receipt_id")
@click.option("--store", "store_path", default=DEFAULT_STORE, help="Receipt store path (JSONL)")
@click.option("--pubkey-file", default=None, help="Ed25519 public key PEM to verify signature")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def why(
    receipt_id: str,
    store_path: str,
    pubkey_file: str | None,
    output_format: str,
) -> None:
    """Show the provenance subgraph behind a receipt decision (100% offline).

    Example:
      drako why rcpt_9f5b54c7 --store .drako/receipts.jsonl --pubkey-file operator.pub
    """
    from drako.kernel.receipts import ReceiptStore, provenance_subgraph, verify_receipt

    store = ReceiptStore(store_path)
    receipt = store.get(receipt_id)
    if receipt is None:
        if output_format == "json":
            click.echo(json.dumps({"error": "receipt_not_found", "receipt_id": receipt_id, "store": store_path}))
        else:
            click.echo(click.style("  [error]  ", fg="red") + f"receipt not found: {receipt_id}")
            click.echo(f"           store: {store_path}")
        raise SystemExit(1)

    sig_valid: bool | None = None
    if pubkey_file:
        pub = Path(pubkey_file).read_text(encoding="utf-8")
        sig_valid = verify_receipt(receipt, pub)

    if output_format == "json":
        graph = provenance_subgraph(receipt)
        graph["signature_verified"] = sig_valid
        click.echo(json.dumps(graph, indent=2))
        if sig_valid is False:
            raise SystemExit(1)
        return

    click.echo()
    click.secho("  Drako — Why was this decided?", fg="cyan", bold=True)
    click.echo()
    color = "green" if receipt.get("decision") == "permit" else "red"
    click.echo(
        click.style(f"  [{receipt.get('decision', '?').upper()}] ", fg=color)
        + f"{receipt.get('tool_name')} by {receipt.get('agent_id')}"
    )
    click.echo(f"           policy: {receipt.get('policy_id')}")
    click.echo(f"           reason: {receipt.get('reason')}")
    click.echo(f"           time:   {receipt.get('timestamp')}")
    click.echo(f"           grade:  {receipt.get('grade', 'evidence')}")
    prov = receipt.get("provenance") or []
    if prov:
        click.echo("           provenance:")
        for p in prov:
            ttl = f" ttl={p['ttl_seconds']}s" if p.get("ttl_seconds") is not None else ""
            click.echo(f"             - {p.get('origin')} [{p.get('trust')}]{ttl}")
    if receipt.get("prev_hash"):
        click.echo(
            f"           chain:  ...{receipt['prev_hash'][-12:]} -> {receipt['payload_hash'][:12]}..."
        )

    if sig_valid is not None:
        click.echo(
            click.style("  [verify] ", fg="green" if sig_valid else "red")
            + ("Ed25519 signature VALID" if sig_valid else "Ed25519 signature INVALID")
        )
        if not sig_valid:
            raise SystemExit(1)
    else:
        click.echo("           (pass --pubkey-file to verify the Ed25519 signature)")
    click.echo()
