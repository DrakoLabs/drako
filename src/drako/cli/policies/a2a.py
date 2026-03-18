"""A2A (Agent-to-Agent) security policy rules — Sprint 5.

A2A-001: No agent-to-agent authentication configured
A2A-002: Agent accepts unvalidated input from other agents
A2A-003: No isolation between agent communication channels
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


# ---------------------------------------------------------------------------
# A2A-001: No agent-to-agent authentication configured
# ---------------------------------------------------------------------------

_A2A_AUTH_PATTERNS = re.compile(
    r"(?:mutual_auth|mtls|did_exchange|agent_auth|channel_auth|"
    r"verify_agent_identity|a2a.*auth|agent_credential|peer_verify)",
    re.IGNORECASE,
)


class A2A001(BasePolicy):
    policy_id = "A2A-001"
    category = "Security"
    severity = "HIGH"
    title = "No agent-to-agent authentication configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # Only relevant for multi-agent projects
        if len(bom.agents) < 2:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        all_config = "\n".join(metadata.config_files.values())
        combined = all_content + "\n" + all_config

        if _A2A_AUTH_PATTERNS.search(combined):
            return []

        agent_names = ", ".join(a.name for a in bom.agents[:5])
        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"Multi-agent project with {len(bom.agents)} agents "
                f"({agent_names}) communicating without mutual authentication. "
                f"A compromised agent can impersonate others and inject malicious "
                f"instructions into the communication chain (prompt worm attack)."
            ),
            fix_snippet=(
                "# Add A2A authentication in .drako.yaml:\n"
                "a2a:\n"
                "  mode: enforce\n"
                "  auth:\n"
                "    method: did_exchange\n"
                "    auto_rotate: true\n"
                "    rotation_hours: 24\n"
                "  worm_detection:\n"
                "    enabled: true\n"
                "    scan_inter_agent_messages: true\n"
                "    max_propagation_depth: 3"
            ),
        )]


# ---------------------------------------------------------------------------
# A2A-002: Agent accepts unvalidated input from other agents
# ---------------------------------------------------------------------------

_INTER_AGENT_INPUT_PATTERNS = re.compile(
    r"(?:agent.*output.*input|delegate.*task|handoff|"
    r"send_to_agent|agent_message|crew.*delegate|"
    r"pass.*result.*agent|forward.*to.*agent)",
    re.IGNORECASE,
)

_INTER_AGENT_VALIDATION_PATTERNS = re.compile(
    r"(?:validate.*agent.*input|scan.*agent.*message|"
    r"injection.*detect|sanitize.*agent|"
    r"a2a.*gateway|drako.*a2a|worm_detect)",
    re.IGNORECASE,
)


class A2A002(BasePolicy):
    policy_id = "A2A-002"
    category = "Security"
    severity = "CRITICAL"
    title = "Agent accepts unvalidated input from other agents"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if len(bom.agents) < 2:
            return []

        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue

            if not _INTER_AGENT_INPUT_PATTERNS.search(content):
                continue

            if _INTER_AGENT_VALIDATION_PATTERNS.search(content):
                continue

            # Found inter-agent data flow without validation
            findings.append(Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f"Inter-agent data flow detected in {rel_path} without "
                    f"input validation or injection scanning. Other agents' "
                    f"output should be treated as untrusted input."
                ),
                file_path=rel_path,
                fix_snippet=(
                    "# Route inter-agent messages through the A2A gateway:\n"
                    "a2a:\n"
                    "  mode: enforce\n"
                    "  worm_detection:\n"
                    "    scan_inter_agent_messages: true\n"
                    "    max_propagation_depth: 3\n"
                    "    circular_reference_block: true"
                ),
            ))

        return findings


# ---------------------------------------------------------------------------
# A2A-003: No isolation between agent communication channels
# ---------------------------------------------------------------------------

_SHARED_STATE_PATTERNS = re.compile(
    r"(?:shared_memory|global_state|shared_context|"
    r"common_store|shared_dict|global_dict|"
    r"groupchat\.messages|shared_message_history)",
    re.IGNORECASE,
)

_ISOLATION_PATTERNS = re.compile(
    r"(?:channel_isolat|message_channel|private_channel|"
    r"scoped_context|agent_sandbox|namespace|"
    r"a2a.*channel|drako.*channel)",
    re.IGNORECASE,
)


class A2A003(BasePolicy):
    policy_id = "A2A-003"
    category = "Security"
    severity = "HIGH"
    title = "No isolation between agent communication channels"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if len(bom.agents) < 2:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        all_config = "\n".join(metadata.config_files.values())
        combined = all_content + "\n" + all_config

        if not _SHARED_STATE_PATTERNS.search(all_content):
            return []

        if _ISOLATION_PATTERNS.search(combined):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                "Agents share context or state without channel isolation. "
                "If one agent is compromised, it can read or modify other "
                "agents' state. Use isolated communication channels."
            ),
            fix_snippet=(
                "# Enable channel isolation in .drako.yaml:\n"
                "a2a:\n"
                "  mode: enforce\n"
                "  channels:\n"
                "    - from: researcher\n"
                "      to: writer\n"
                "      allowed_message_types: [task_result, data_handoff]\n"
                "    - from: researcher\n"
                "      to: reviewer\n"
                "      policy: deny  # explicit deny"
            ),
        )]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

A2A_POLICIES: list[BasePolicy] = [
    A2A001(),
    A2A002(),
    A2A003(),
]
