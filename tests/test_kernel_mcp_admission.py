"""Sprint 2 kernel/mcp admission + AgBOM suites (2026-09-04). Pure, hermetic."""

import base64
import hashlib

from drako.mcp_guard import (
    AdmissionDecision,
    admit,
    agbom_to_cyclonedx,
    canonical_snapshot,
)

LOCK = {"a-tool": "a-tool@1.0.0", "b-tool": "b-tool@2.0.0"}


def test_pinned_package_admits_with_lock_spec():
    d = admit("a-tool", LOCK)
    assert d == AdmissionDecision(True, "'a-tool' admitted as a-tool@1.0.0",
                                  admitted_spec="a-tool@1.0.0")


def test_undeclared_package_denied():
    d = admit("evil-tool", LOCK)
    assert d.admitted is False and "mcp.lock" in d.reason
    assert d.admitted_spec is None


def test_allowlist_scopes_admission():
    assert admit("a-tool", LOCK, allowed_packages=["a-tool"]).admitted is True
    d = admit("b-tool", LOCK, allowed_packages=["a-tool"])
    assert d.admitted is False and "allowlist" in d.reason


def test_unset_allowlist_is_pin_only_posture():
    assert admit("b-tool", LOCK, allowed_packages=None).admitted is True


def test_empty_name_denied():
    assert admit("  ", LOCK).admitted is False


def test_requested_version_never_leaks_into_spec():
    """Admission answers with the LOCK's spec even when the requester
    names a version (downgrade/confusion resistance)."""
    d = admit("a-tool@9.9.9", LOCK)
    assert d.admitted is True
    assert d.admitted_spec == "a-tool@1.0.0"  # lock wins, not the request


def test_agbom_snapshot_canonical_and_bound():
    servers = [
        {"package": "b-tool", "version": "2.0.0", "integrity": "sha512-b"},
        {"package": "a-tool", "version": "1.0.0", "integrity": "sha512-a",
         "admitted_spec": "a-tool@1.0.0"},
    ]
    s1 = canonical_snapshot(servers, lock_hash="sha256:x",
                            generated_at="2026-09-04T00:00:00+00:00")
    s2 = canonical_snapshot(list(reversed(servers)), lock_hash="sha256:x",
                            generated_at="2026-09-04T00:00:00+00:00")
    assert s1 == s2  # order-independent
    assert [s["package"] for s in s1["servers"]] == ["a-tool", "b-tool"]
    assert s1["snapshot_hash"].startswith("sha256:")
    changed = canonical_snapshot(
        [{"package": "a-tool", "version": "1.0.1",
          "integrity": "sha512-a2"}],
        lock_hash="sha256:x", generated_at="2026-09-04T00:00:00+00:00")
    assert changed["snapshot_hash"] != s1["snapshot_hash"]  # drift-evident


def test_agbom_mints_verifiable_receipt():
    """Snapshot â†’ signed kernel receipt â†’ verifies (caller owns keys)."""
    from drako.kernel.envelope import args_hash
    from drako.kernel.receipts import (
        generate_keypair,
        mint_receipt,
        verify_receipt,
    )

    snap = canonical_snapshot(
        [{"package": "a-tool", "version": "1.0.0",
          "integrity": "sha512-a"}],
        generated_at="2026-09-04T00:00:00+00:00",
    )
    priv, pub = generate_keypair()
    r = mint_receipt(
        decision="permit", policy_id="kernel:mcp-agbom",
        reason="admitted server set snapshot",
        tool_name="agbom.snapshot", agent_id="test",
        args_hash=args_hash({"snapshot_hash": snap["snapshot_hash"]}),
        provenance=[{"origin": "operator:lock", "trust": "USER",
                     "ttl_seconds": None}],
        private_pem=priv, public_pem=pub,
    )
    assert verify_receipt(r, pub) is True
    r["reason"] = "tampered"
    assert verify_receipt(r, pub) is False


def test_cyclonedx_emit_shape():
    """P1-02: AgBOM â†’ CycloneDX 1.6 with hex hashes + drako properties."""
    raw = hashlib.sha256(b"tarball-bytes").digest()
    integrity = "sha512-" + base64.b64encode(raw).decode()
    snap = canonical_snapshot(
        [{"package": "a-tool", "version": "1.0.0", "integrity": integrity,
          "admitted_spec": "a-tool@1.0.0"}],
        lock_hash="sha256:abc",
        generated_at="2026-09-04T00:00:00+00:00",
    )
    bom = agbom_to_cyclonedx(snap)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.7"
    assert "citations" in bom
    assert agbom_to_cyclonedx(snap, spec_version="1.6")["specVersion"] == "1.6"
    (comp,) = bom["components"]
    assert comp["bom-ref"] == "a-tool@1.0.0"
    assert comp["hashes"] == [{"alg": "SHA-512", "content": raw.hex()}]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["drako:integrity"] == integrity
    assert props["drako:admitted_spec"] == "a-tool@1.0.0"
    meta = {p["name"]: p["value"]
            for p in bom["metadata"]["properties"]}
    assert meta["drako:snapshot_hash"] == snap["snapshot_hash"]
    assert "transport-only" in meta["drako:attestation"]


def test_cyclonedx_malformed_integrity_omits_hash():
    snap = canonical_snapshot(
        [{"package": "a-tool", "version": "1.0.0",
          "integrity": "not-a-hash"}],
        generated_at="2026-09-04T00:00:00+00:00",
    )
    (comp,) = agbom_to_cyclonedx(snap)["components"]
    assert comp["hashes"] == []  # identity kept, hash omitted
    assert comp["name"] == "a-tool"


def test_cyclonedx_empty_set():
    bom = agbom_to_cyclonedx(canonical_snapshot(
        [], generated_at="2026-09-04T00:00:00+00:00"))
    assert bom["components"] == []
    assert bom["bomFormat"] == "CycloneDX"

