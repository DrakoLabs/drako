"""CLI tests: why + verify --receipt (Sprint 1, route A)."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from click.testing import CliRunner

from drako.cli.main import cli
from drako.kernel.receipts import ReceiptStore, generate_keypair, mint_receipt


def _seed_store(tmp_path):
    priv, pub = generate_keypair()
    store = ReceiptStore(str(tmp_path / "receipts.jsonl"))
    r1 = mint_receipt(decision="permit", policy_id="p", reason="ok",
                      tool_name="web_search", agent_id="a", args_hash="h",
                      provenance=[{"origin": "user:task", "trust": "USER"}],
                      private_pem=priv, public_pem=pub)
    store.append(r1)
    pubf = tmp_path / "signing.pub"
    pubf.write_text(pub)
    chainf = tmp_path / "chain.json"
    chainf.write_text(json.dumps([r1]))
    return r1, pubf, chainf


def test_why_answers_from_receipt(tmp_path):
    r1, pubf, _ = _seed_store(tmp_path)
    res = CliRunner().invoke(cli, ["why", r1["receipt_id"],
                                   "--store", str(tmp_path / "receipts.jsonl"),
                                   "--pubkey-file", str(pubf)])
    assert res.exit_code == 0, res.output
    assert "web_search" in res.output and "signature VALID" in res.output


def test_why_missing_receipt(tmp_path):
    res = CliRunner().invoke(cli, ["why", "rcpt_nope", "--store", str(tmp_path / "r.jsonl")])
    assert res.exit_code == 1 and "not found" in res.output


def test_verify_receipt_file(tmp_path):
    _, pubf, chainf = _seed_store(tmp_path)
    res = CliRunner().invoke(cli, ["verify", "--receipt", str(chainf),
                                   "--pubkey-file", str(pubf)])
    assert res.exit_code == 0, res.output
    assert "VALID" in res.output


def test_verify_receipt_tampered(tmp_path):
    r1, pubf, chainf = _seed_store(tmp_path)
    doc = json.loads(chainf.read_text())
    doc[0]["reason"] = "forged"
    chainf.write_text(json.dumps(doc))
    res = CliRunner().invoke(cli, ["verify", "--receipt", str(chainf),
                                   "--pubkey-file", str(pubf)])
    assert res.exit_code == 1 and "INVALID" in res.output


def test_store_concurrent_appends_no_torn_writes(tmp_path):
    """T-4: 8 threads x 25 appends â†’ 200 intact JSON lines, no interleaving.

    Scope honest: the lock guarantees atomic appends (no torn writes / false
    chain breaks). Cross-thread hash-CHAIN ordering stays the caller's
    sequential concern (Host is single-threaded by design).
    """
    from drako.kernel.receipts import ReceiptStore

    store = ReceiptStore(str(tmp_path / "c.jsonl"))

    def worker(n):
        for i in range(25):
            store.append({"id": f"{n}-{i}", "pad": "x" * 200})

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(worker, range(8)))
    lines = (tmp_path / "c.jsonl").read_text().strip().split("\n")
    assert len(lines) == 200
    ids = {json.loads(ln)["id"] for ln in lines}  # raises if torn
    assert len(ids) == 200

