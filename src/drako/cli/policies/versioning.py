"""Context Versioning policy rules (CV-001, CV-002)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


class CV001(BasePolicy):
    """CV-001: No policy versioning configured."""
    policy_id = "CV-001"
    category = "Context Versioning"
    severity = "HIGH"
    title = "No policy versioning configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # Check for .drako.yaml with platform connection
        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        if not config_content:
            # No config file at all — always flag
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    "No .drako.yaml found. Without platform connection, policy changes "
                    "are not versioned and audit logs cannot reference the active policy version. "
                    "This violates EU AI Act Art. 12 traceability requirements."
                ),
                fix_snippet=(
                    "# Initialize and connect to Drako platform:\n"
                    "drako init\n"
                    "drako push\n\n"
                    "# Every push now creates an immutable, hash-chained snapshot.\n"
                    "# View history: drako history\n"
                    "# Compare:     drako diff v1 v2"
                ),
            )]

        # Has config but no endpoint / api_key_env → offline only, no versioning
        has_endpoint = "endpoint:" in config_content or "api_key_env:" in config_content
        if not has_endpoint:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    "Config exists but has no platform connection (missing endpoint/api_key_env). "
                    "Policy versions are not tracked. Run `drako push` to enable versioning."
                ),
                fix_snippet=(
                    "# Add to .drako.yaml:\n"
                    "api_key_env: DRAKO_API_KEY\n"
                    "endpoint: https://api.useagentmesh.com\n\n"
                    "# Then push:\n"
                    "drako push"
                ),
            )]

        return []


class CV002(BasePolicy):
    """CV-002: Audit logs without policy version reference."""
    policy_id = "CV-002"
    category = "Context Versioning"
    severity = "MEDIUM"
    title = "Audit logs without policy version reference"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # This is an online-only check. For offline scan, we check if audit
        # logging is configured but there's no platform connection.
        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        if not config_content:
            return []  # CV-001 already flags missing config

        has_audit = "audit:" in config_content
        has_connection = "api_key_env:" in config_content or "endpoint:" in config_content

        if has_audit and not has_connection:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    "Audit logging is configured but without platform connection. "
                    "Audit entries will not reference the active policy version, "
                    "making post-incident investigation harder."
                ),
                fix_snippet=(
                    "# Connect to platform so audit logs include policy_snapshot_id:\n"
                    "api_key_env: DRAKO_API_KEY\n"
                    "drako push"
                ),
            )]

        return []


VERSIONING_POLICIES: list[BasePolicy] = [
    CV001(),
    CV002(),
]
