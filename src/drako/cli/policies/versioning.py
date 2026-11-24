"""Context Versioning policy rules (CV-001, CV-002) — v4 local-first."""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


class CV001(BasePolicy):
    """CV-001: No pinned policy versioning configured."""

    policy_id = "CV-001"
    category = "Context Versioning"
    severity = "HIGH"
    title = "No policy versioning configured"
    impact = "Without pinned policy versioning, you cannot trace which governance profile was active during a past incident or audit."
    attack_scenario = "Regulator asks which safety policies were active when an incident occurred. Without pinned spec/policy versions, you cannot prove it."
    references = ["https://artificialintelligenceact.eu/article/12/"]
    remediation_effort = "moderate"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path or "drako-policy" in path:
                config_content += "\n" + content

        if not config_content.strip():
            return [self._finding(
                message=(
                    "No .drako.yaml or ACS policy profile found. Policy changes are not pinned "
                    "and receipts cannot reference an immutable spec version (EU AI Act Art. 12)."
                ),
                fix_snippet=(
                    "# Initialize local-first v4 config and pinned ACS profile:\n"
                    "drako init\n"
                    "drako validate .drako.yaml"
                ),
            )]

        has_pin = (
            "spec_pin:" in config_content
            or "policy_version:" in config_content
            or "kernel:" in config_content
        )
        if not has_pin:
            return [self._finding(
                message=(
                    "Config exists but lacks pinned policy versioning (missing spec_pin / kernel block). "
                    "Run `drako upgrade --v4` to pin AGENT-HOOKS-0.1."
                ),
                fix_snippet=(
                    "# Add to .drako.yaml (or run `drako upgrade --v4`):\n"
                    "kernel:\n"
                    "  spec_pin: AGENT-HOOKS-0.1\n"
                    "  default_effect: deny"
                ),
            )]

        return []


class CV002(BasePolicy):
    """CV-002: Audit logging without cryptographic receipt / policy binding."""

    policy_id = "CV-002"
    category = "Context Versioning"
    severity = "MEDIUM"
    title = "Audit logs without cryptographic policy binding"
    impact = "Plain audit logs without cryptographic policy/receipt references cannot survive post-incident forensics or EU AI Act Art. 12 audits."
    attack_scenario = "Audit log shows an action ran, but lacks signed receipt hash-chain or policy_id binding. Investigation stalls."
    references = ["https://artificialintelligenceact.eu/article/12/"]
    remediation_effort = "trivial"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        if not config_content:
            return []

        has_audit = "audit:" in config_content
        has_binding = (
            "receipt_store:" in config_content
            or "spec_pin:" in config_content
            or "cryptographic: true" in config_content
        )

        if has_audit and not has_binding:
            return [self._finding(
                message=(
                    "Audit logging is configured without cryptographic receipt binding "
                    "(missing receipt_store / spec_pin / cryptographic: true)."
                ),
                fix_snippet=(
                    "# Enable cryptographic receipt chaining in .drako.yaml:\n"
                    "audit:\n"
                    "  enabled: true\n"
                    "  cryptographic: true\n"
                    "  receipt_store: .drako/receipts.jsonl"
                ),
            )]

        return []


VERSIONING_POLICIES: list[BasePolicy] = [
    CV001(),
    CV002(),
]
