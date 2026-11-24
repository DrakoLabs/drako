"""Build a `ComplianceContext` from scan output, BOM, runtime config, answers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from drako import __version__ as DRAKO_VERSION
from drako.cli.scan_cache import load_scan_cache
from drako.comply.storage import load as load_answers


@dataclass
class ComplianceContext:
    # Identity
    system_name: str = ""
    system_version: str = ""
    provider_entity: str = ""
    deployment_environment: str = ""
    deployment_regions: list[str] = field(default_factory=list)

    # Purpose
    system_purpose: str = ""
    intended_users: str = ""
    domain: str = ""
    high_risk_rationale: str = ""
    deployment_timeline: str = ""

    # Data
    training_data_sources: list[str] = field(default_factory=list)
    data_provenance: str = ""
    data_retention_policy: str = ""
    pii_categories: list[str] = field(default_factory=list)
    data_subject_rights: str = ""

    # Oversight
    oversight_responsible_name: str = ""
    oversight_responsible_role: str = ""
    escalation_path: str = ""
    incident_response_procedure: str = ""
    update_cadence: str = ""

    # Limitations
    known_limitations: list[str] = field(default_factory=list)
    known_failure_modes: list[str] = field(default_factory=list)
    residual_risks: list[str] = field(default_factory=list)
    out_of_scope_use_cases: list[str] = field(default_factory=list)
    user_notification_mechanism: str = ""

    # Compliance context
    other_regulations: list[str] = field(default_factory=list)
    existing_certifications: list[str] = field(default_factory=list)
    third_party_audits: str = ""
    legal_counsel_involvement: str = ""
    signature_authority: str = ""

    # From BOM / scan
    agents: list[dict] = field(default_factory=list)
    tools: list[dict] = field(default_factory=list)
    models: list[dict] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    risk_findings: list[dict] = field(default_factory=list)
    governance_score: int = 0
    determinism_score: int = 100

    # Runtime config & Digital Omnibus EU AI Act (Art. 50 + Art. 12 receipts)
    audit_trail_enabled: bool = False
    hitl_configured: bool = False
    hitl_triggers: list[str] = field(default_factory=list)
    article50_transparency_active: bool = True  # active since 2026-08-02; Art. 50(2) grace ends 2026-12-02
    article50_disclosure_mechanism: str = ""
    receipt_evidence: dict[str, Any] = field(default_factory=dict)
    eu_ai_act_timeline: dict[str, str] = field(
        default_factory=lambda: {
            "article_50_transparency": "2026-08-02",
            "article_50_2_watermarking_grace_end": "2026-12-02",
            "annex_iii_high_risk": "2027-12-02",
            "annex_i_embedded_high_risk": "2028-08-02",
        }
    )

    # Meta
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    drako_version: str = DRAKO_VERSION
    scan_timestamp: str = ""


def _str(answers: dict[str, Any], key: str) -> str:
    value = answers.get(key, "")
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value or "")


def _list(answers: dict[str, Any], key: str) -> list[str]:
    value = answers.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [piece.strip() for piece in value.split(",") if piece.strip()]
    return [str(value)]


def _read_runtime_config(directory: Path) -> tuple[bool, bool, list[str], str]:
    """Best-effort: read local v4 .drako.yaml audit + HITL + receipt_store path."""
    cfg_file = directory / ".drako.yaml"
    if not cfg_file.exists():
        return False, False, [], ".drako/receipts.jsonl"
    try:
        from drako.config import DrakoConfig

        config = DrakoConfig.load(str(cfg_file))
    except Exception:
        return False, False, [], ".drako/receipts.jsonl"

    audit = bool(getattr(config.audit, "enabled", False))
    receipt_store = getattr(config.kernel, "receipt_store", None) or getattr(
        config.audit, "receipt_store", ".drako/receipts.jsonl"
    )
    hitl_obj = getattr(config, "hitl", None)
    if hitl_obj is None or getattr(hitl_obj, "mode", "off") == "off":
        return audit, False, [], str(receipt_store)
    triggers: list[str] = []
    raw_triggers = getattr(hitl_obj, "triggers", None)
    if raw_triggers is not None:
        triggers.extend(getattr(raw_triggers, "tools", []) or [])
        triggers.extend(getattr(raw_triggers, "tool_types", []) or [])
    return audit, True, [str(t) for t in triggers], str(receipt_store)


def _read_receipt_evidence(directory: Path, receipt_store: str) -> dict[str, Any]:
    """Summarize local Ed25519 receipt chain for EU AI Act Art. 12 / Art. 14 evidence."""
    store_path = Path(receipt_store)
    if not store_path.is_absolute():
        store_path = directory / store_path
    if not store_path.exists():
        return {"present": False, "count": 0, "chain_contiguous": False}
    try:
        from drako.kernel.receipts import ReceiptStore

        receipts = ReceiptStore(str(store_path)).load_all()
    except Exception:
        return {"present": False, "count": 0, "chain_contiguous": False}

    prev = None
    contiguous = True
    permits = 0
    denies = 0
    signers: set[str] = set()
    for r in receipts:
        if r.get("prev_hash") != prev:
            contiguous = False
        prev = r.get("payload_hash")
        if r.get("decision") == "permit":
            permits += 1
        elif r.get("decision") == "deny":
            denies += 1
        if r.get("signer"):
            signers.add(str(r["signer"]))
    return {
        "present": bool(receipts),
        "store_path": str(store_path),
        "count": len(receipts),
        "permits": permits,
        "denies": denies,
        "chain_contiguous": contiguous and bool(receipts),
        "signers": sorted(signers),
    }


def build_context(directory: str | Path = ".") -> ComplianceContext:
    """Compose the compliance context from every available source."""
    directory = Path(directory)
    answers = load_answers(directory)
    scan = load_scan_cache(str(directory), max_age_seconds=10 ** 9) or {}
    audit, hitl, triggers, receipt_store = _read_runtime_config(directory)
    receipt_ev = _read_receipt_evidence(directory, receipt_store)

    return ComplianceContext(
        # Identity
        system_name=_str(answers, "system_name") or scan.get("project_name", ""),
        system_version=_str(answers, "system_version"),
        provider_entity=_str(answers, "provider_entity"),
        deployment_environment=_str(answers, "deployment_environment"),
        deployment_regions=_list(answers, "deployment_regions"),
        # Purpose
        system_purpose=_str(answers, "system_purpose"),
        intended_users=_str(answers, "intended_users"),
        domain=_str(answers, "domain"),
        high_risk_rationale=_str(answers, "high_risk_rationale"),
        deployment_timeline=_str(answers, "deployment_timeline"),
        # Data
        training_data_sources=_list(answers, "training_data_sources"),
        data_provenance=_str(answers, "data_provenance"),
        data_retention_policy=_str(answers, "data_retention_policy"),
        pii_categories=_list(answers, "pii_categories"),
        data_subject_rights=_str(answers, "data_subject_rights"),
        # Oversight
        oversight_responsible_name=_str(answers, "oversight_responsible_name"),
        oversight_responsible_role=_str(answers, "oversight_responsible_role"),
        escalation_path=_str(answers, "escalation_path"),
        incident_response_procedure=_str(answers, "incident_response_procedure"),
        update_cadence=_str(answers, "update_cadence"),
        # Limitations
        known_limitations=_list(answers, "known_limitations"),
        known_failure_modes=_list(answers, "known_failure_modes"),
        residual_risks=_list(answers, "residual_risks"),
        out_of_scope_use_cases=_list(answers, "out_of_scope_use_cases"),
        user_notification_mechanism=_str(answers, "user_notification_mechanism"),
        # Compliance context
        other_regulations=_list(answers, "other_regulations"),
        existing_certifications=_list(answers, "existing_certifications"),
        third_party_audits=_str(answers, "third_party_audits"),
        legal_counsel_involvement=_str(answers, "legal_counsel_involvement"),
        signature_authority=_str(answers, "signature_authority"),
        # BOM / scan
        agents=list(scan.get("agents") or []),
        tools=list(scan.get("tools") or []),
        models=list(scan.get("models") or []),
        frameworks=[scan["framework"]] if scan.get("framework") else [],
        risk_findings=[],  # last_scan.json keeps only summary; full findings not persisted yet
        governance_score=int(scan.get("score", 0)),
        determinism_score=int(scan.get("determinism_score", 100)),
        # Runtime & Digital Omnibus EU AI Act evidence
        audit_trail_enabled=audit or receipt_ev.get("present", False),
        hitl_configured=hitl,
        hitl_triggers=triggers,
        article50_disclosure_mechanism=_str(answers, "user_notification_mechanism"),
        receipt_evidence=receipt_ev,
        # Meta
        scan_timestamp=str(scan.get("scanned_at", "")),
    )
