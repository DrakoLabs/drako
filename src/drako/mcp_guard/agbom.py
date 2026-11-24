"""Dynamic signed AgBOM: admitted MCP server set + CycloneDX 1.7 (ECMA-424) export.

Static BOMs rot: operators add servers, versions drift, pins change.
The AgBOM snapshot binds (package, version, integrity, admitted_spec, principal)
for every admitted server PLUS the lock's own hash into ONE canonical payload
minted as a kernel receipt.

CycloneDX 1.7 (ECMA-424) transports the admitted set into SBOM/SIEM toolchains
with `citations` provenance and `drako:principal` blast-radius metadata;
cryptographic trust stays in the Ed25519 kernel receipt over the canonical
snapshot (`drako verify`).
"""

from __future__ import annotations

import base64 as _b64
import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any


def canonical_snapshot(
    admitted: Sequence[Mapping[str, Any]],
    lock_hash_value: str = "",
    generated_at: str = "",
    *,
    lock_hash: str | None = None,
) -> dict[str, Any]:
    """Build the canonical AgBOM payload (pure, testable)."""
    effective_lock_hash = lock_hash if lock_hash is not None else lock_hash_value
    servers = []
    for s in sorted(admitted, key=lambda e: str(e["package"])):
        entry: dict[str, Any] = {
            "package": str(s["package"]),
            "version": str(s["version"]),
            "integrity": str(s["integrity"]),
        }
        if s.get("admitted_spec"):
            entry["admitted_spec"] = str(s["admitted_spec"])
        if s.get("principal"):
            entry["principal"] = str(s["principal"])
        if s.get("transport"):
            entry["transport"] = str(s["transport"])
        servers.append(entry)
    body: dict[str, Any] = {
        "agbom_version": 1,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "servers": servers,
        "lock_hash": effective_lock_hash,
    }
    body["snapshot_hash"] = "sha256:" + hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return body


def lock_hash(lock_text: str) -> str:
    """SHA-256 hash of the mcp.lock bytes the snapshot was built from."""
    return "sha256:" + hashlib.sha256(lock_text.encode("utf-8")).hexdigest()


def agbom_to_cyclonedx(
    snapshot: Mapping[str, Any],
    *,
    spec_version: str = "1.7",
) -> dict[str, Any]:
    """Emit a CycloneDX 1.7 (ECMA-424) or 1.6 SBOM for an AgBOM snapshot.

    Transport format only — cryptographic attestation lives in the Ed25519
    kernel receipt over `snapshot_hash` (`drako verify`).
    """
    if spec_version not in ("1.6", "1.7"):
        raise ValueError(f"unsupported CycloneDX spec_version: {spec_version!r}")

    servers = snapshot.get("servers", []) or []
    components: list[dict[str, Any]] = []
    citations: list[dict[str, Any]] = []

    for s in servers:
        pkg = str(s.get("package", ""))
        ver = str(s.get("version", ""))
        bom_ref = f"{pkg}@{ver}"
        integrity = str(s.get("integrity", ""))
        hashes: list[dict[str, str]] = []
        if integrity.startswith("sha512-"):
            try:
                digest_hex = _b64.b64decode(integrity[len("sha512-"):]).hex()
                hashes.append({"alg": "SHA-512", "content": digest_hex})
            except Exception:
                pass
        props = [
            {"name": "drako:integrity", "value": integrity},
            {"name": "drako:lock_hash", "value": str(snapshot.get("lock_hash", ""))},
        ]
        if s.get("admitted_spec"):
            props.append({"name": "drako:admitted_spec", "value": str(s["admitted_spec"])})
        if s.get("principal"):
            props.append({"name": "drako:principal", "value": str(s["principal"])})
        if s.get("transport"):
            props.append({"name": "drako:transport", "value": str(s["transport"])})

        components.append({
            "type": "application",
            "bom-ref": bom_ref,
            "name": pkg,
            "version": ver,
            "hashes": hashes,
            "properties": props,
        })
        citations.append({
            "pointers": [f"/components/{bom_ref}"],
            "timestamp": str(snapshot.get("generated_at", "")),
            "attributedTo": "drako-agbom",
            "process": "mcp.lock admission",
            "note": f"lock_hash={snapshot.get('lock_hash', '')}",
        })

    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "metadata": {
            "timestamp": str(snapshot.get("generated_at", "")),
            "tools": [{"vendor": "DrakoLabs", "name": "drako-agbom", "version": "4.0.0"}],
            "properties": [
                {"name": "drako:snapshot_hash", "value": str(snapshot.get("snapshot_hash", ""))},
                {
                    "name": "drako:attestation",
                    "value": "transport-only: verify the Ed25519 kernel receipt signature, not this document",
                },
            ],
        },
        "components": sorted(components, key=lambda c: str(c["bom-ref"])),
    }
    if spec_version == "1.7":
        doc["citations"] = citations
    return doc
