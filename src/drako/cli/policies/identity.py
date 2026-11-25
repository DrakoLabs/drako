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


def _has_local_identity_config(metadata: ProjectMetadata) -> bool:
    """Return True if local .drako.yaml declares agent identities or signed A2A cards."""
    cfg = "\n".join(
        content
        for name, content in metadata.config_files.items()
        if name in (".drako.yaml", "drako.yaml")
    )
    if cfg:
        lower = cfg.lower()
        if "agents:" in lower or "require_signed_cards: true" in lower:
            return True
    for name, content in metadata.config_files.items():
        if (
            name.endswith(".json")
            and ("agent-card" in name.lower() or name.lower() == "agent.json")
            and '"signatures"' in content
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# ID-001: Static credentials in agent code  (CRITICAL)
# ---------------------------------------------------------------------------

class ID001(BasePolicy):
    policy_id = "ID-001"
    category = "Identity"
    severity = "CRITICAL"
    title = "Static credentials in agent code"
    impact = "Static credentials in agent code cannot be rotated or revoked per-agent, creating a single point of compromise."
    attack_scenario = "One agent's hardcoded API key is leaked. Since all agents share the same key, the entire fleet is compromised."
    references = ["https://cwe.mitre.org/data/definitions/798.html"]
    remediation_effort = "moderate"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _STATIC_CREDENTIAL_RE.search(all_content):
            return []

        return [self._finding(
            message=(
                f"Static credentials detected in agent code across "
                f"{len(bom.agents)} agent(s). Replace hardcoded API keys, tokens, "
                f"or secrets with environment variables or a secret manager, and "
                f"provision per-agent Ed25519 keys with `drako kernel keygen`."
            ),
            fix_snippet=(
                "import os\n\n"
                'api_key = os.environ["AGENT_API_KEY"]\n'
                "# Provision per-agent Ed25519 keys offline:\n"
                "#   drako kernel keygen --out .drako/keys"
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
    impact = "Without identity definitions, agents cannot be uniquely authenticated, making access control and audit impossible."
    attack_scenario = "Two agents use the same credentials. Audit log shows API calls but cannot distinguish which agent made them."
    references = ["https://cwe.mitre.org/data/definitions/287.html"]
    remediation_effort = "moderate"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        if _has_local_identity_config(metadata):
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _IDENTITY_PATTERNS):
            return []

        return [self._finding(
            message=(
                f"No identity definition detected across {len(bom.agents)} "
                f"agent(s). Declare per-agent identities in `.drako.yaml` "
                f"(`agents:` and `a2a.require_signed_cards: true`) and sign "
                f"A2A Agent Cards with `drako kernel keygen` and `drako a2a sign`."
            ),
            fix_snippet=(
                "# Declare agent identities in .drako.yaml and sign Agent Cards:\n"
                "#   drako kernel keygen --out .drako/keys\n"
                "#   drako a2a sign agent-card.json --key .drako/keys/private.pem\n"
                "a2a:\n"
                "  mode: enforce\n"
                "  require_signed_cards: true"
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
    impact = "Shared credentials prevent per-agent revocation — compromising one agent's key compromises all agents sharing it."
    attack_scenario = "Security incident requires revoking one agent's access. Shared credentials mean all agents must be taken offline."
    references = ["https://cwe.mitre.org/data/definitions/522.html"]
    remediation_effort = "moderate"
    finding_type = "recommendation"

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

        return [self._finding(
            message=(
                f"Credential variables appear to be shared across multiple "
                f"files: {', '.join(shared[:5])}. Assign distinct environment "
                f"variables or secret-manager entries per agent, and sign "
                f"per-agent Ed25519 identities via `drako kernel keygen` and "
                f"`drako a2a sign`."
            ),
            fix_snippet=(
                "# Use isolated per-agent credentials and Ed25519 keys:\n"
                "import os\n\n"
                'researcher_key = os.environ["RESEARCHER_API_KEY"]\n'
                'writer_key = os.environ["WRITER_API_KEY"]'
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
