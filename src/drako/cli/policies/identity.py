"""Agent Identity Management policy rules (ID-001 through ID-003).

Detects the ABSENCE of identity management practices — agents operating
with static credentials, no identity definitions, or shared credentials.

Category: "Identity"
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


# Patterns that indicate hardcoded / static credentials
_STATIC_CREDENTIAL_RE = re.compile(
    r"""(?:api_key|token|secret|password|api_secret|auth_token|access_key)"""
    r"""\s*=\s*["'][A-Za-z0-9_\-\.]{8,}["']""",
    re.IGNORECASE,
)

# Patterns indicating identity / auth configuration
_IDENTITY_PATTERNS = [
    "identity", "credentials", "auth", "did", "agent_id",
    "identity_management", "identity_config", "credential_type",
    "authenticate", "authorization",
]

# Patterns for credential variable names
_CREDENTIAL_VAR_RE = re.compile(
    r"""(?:api_key|token|secret|password|access_key|auth_token)\s*=""",
    re.IGNORECASE,
)


def _content_has_pattern(all_content: str, patterns: list[str]) -> bool:
    """Check if any pattern exists in the combined content."""
    lower = all_content.lower()
    return any(p.lower() in lower for p in patterns)


# ---------------------------------------------------------------------------
# ID-001: Static credentials in agent code  (CRITICAL)
# ---------------------------------------------------------------------------

class ID001(BasePolicy):
    policy_id = "ID-001"
    category = "Identity"
    severity = "CRITICAL"
    title = "Static credentials in agent code"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _STATIC_CREDENTIAL_RE.search(all_content):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"Static credentials detected in agent code across "
                f"{len(bom.agents)} agent(s). Hardcoded API keys, tokens, "
                f"or secrets should be replaced with managed identities. "
                f"Use Drako Identity Management for auto-rotating "
                f"credentials (requires Pro plan)."
            ),
        )]


# ---------------------------------------------------------------------------
# ID-002: No identity definition for agent  (HIGH)
# ---------------------------------------------------------------------------

class ID002(BasePolicy):
    policy_id = "ID-002"
    category = "Identity"
    severity = "HIGH"
    title = "No identity definition for agent"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _IDENTITY_PATTERNS):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"No identity definition detected across {len(bom.agents)} "
                f"agent(s). Without identity configuration (credentials, "
                f"auth, DID), agents cannot be uniquely identified or "
                f"authenticated. Define managed identities via the "
                f"Drako dashboard (requires Pro plan)."
            ),
        )]


# ---------------------------------------------------------------------------
# ID-003: Shared credentials across agents  (HIGH)
# ---------------------------------------------------------------------------

class ID003(BasePolicy):
    policy_id = "ID-003"
    category = "Identity"
    severity = "HIGH"
    title = "Shared credentials across agents"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents or len(bom.agents) < 2:
            return []

        # Collect credential variable assignments per agent file
        agent_files = set()
        for agent in bom.agents:
            if hasattr(agent, "source_file") and agent.source_file:
                agent_files.add(agent.source_file)

        # If we can't determine per-agent files, check globally
        cred_assignments: Counter = Counter()
        for path, content in metadata.file_contents.items():
            if not path.endswith(".py"):
                continue
            matches = _CREDENTIAL_VAR_RE.findall(content)
            for m in matches:
                var_name = m.strip().rstrip("=").strip().lower()
                cred_assignments[var_name] += 1

        # If any credential variable is used more than once, flag it
        shared = [var for var, count in cred_assignments.items() if count > 1]
        if not shared:
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"Credential variables appear to be shared across multiple "
                f"files: {', '.join(shared[:5])}. Each agent should have "
                f"unique, independently managed credentials. Use Drako "
                f"Identity Management to provision per-agent identities "
                f"(requires Pro plan)."
            ),
        )]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

IDENTITY_POLICIES: list[BasePolicy] = [
    ID001(),
    ID002(),
    ID003(),
]
