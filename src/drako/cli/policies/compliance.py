"""EU AI Act compliance policy rules (COM-001 through COM-006)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata

# Patterns indicating logging infrastructure
_LOGGING_PATTERNS = [
    "audit_log", "audit_trail", "with_compliance", "drako",
    "GovernanceMiddleware", "ComplianceMiddleware", "log_action",
    "structlog", "logging.getLogger",
]

# Patterns indicating human oversight
_OVERSIGHT_PATTERNS = [
    "human_in_the_loop", "hitl", "require_approval", "human_approval",
    "ask_human", "confirm_action", "manual_review", "human_oversight",
    "supervisor", "review_queue",
]

# Patterns indicating HITL checkpoint configuration
_HITL_CONFIG_PATTERNS = [
    "hitl:", "hitl_checkpoint", "approval_required", "pending_approval",
    "human_gate", "escalation_policy", "require_human_approval",
]

# Tool names suggesting high-risk side-effects
_SIDE_EFFECT_TOOL_PATTERNS = re.compile(
    r"(?:delete|write|remove|send|pay|transfer|execute|deploy|publish|drop|"
    r"post|push|submit|update|modify|create|insert)",
    re.IGNORECASE,
)


def _content_has_pattern(all_content: str, patterns: list[str]) -> bool:
    lower = all_content.lower()
    return any(p.lower() in lower for p in patterns)


# ---------------------------------------------------------------------------
# COM-001: No automatic logging (EU AI Act Art. 12)
# ---------------------------------------------------------------------------

class COM001(BasePolicy):
    policy_id = "COM-001"
    category = "Compliance"
    severity = "HIGH"
    title = "No automatic logging (EU AI Act Art. 12)"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _LOGGING_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="EU AI Act Article 12 requires automatic logging of AI system activity. No logging infrastructure detected.",
                fix_snippet='from drako import with_compliance\n\n# Drako middleware provides EU AI Act compliant\n# audit logging automatically\ncrew = with_compliance(my_crew)\n# All agent actions, decisions, and tool calls are logged',
            )]

        return []


# ---------------------------------------------------------------------------
# COM-002: No human oversight mechanism (Art. 14)
# ---------------------------------------------------------------------------

class COM002(BasePolicy):
    policy_id = "COM-002"
    category = "Compliance"
    severity = "HIGH"
    title = "No human oversight mechanism (EU AI Act Art. 14)"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _OVERSIGHT_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="EU AI Act Article 14 requires human oversight measures. No human-in-the-loop mechanism detected.",
                fix_snippet='# Add human oversight for high-risk AI operations\nfrom drako import with_compliance\n\ncrew = with_compliance(my_crew, config_path=".drako.yaml")\n# Configure HITL policies in .drako.yaml:\n# governance:\n#   require_approval:\n#     - write_file\n#     - send_email\n#     - database_write',
            )]

        return []


# ---------------------------------------------------------------------------
# COM-003: No technical documentation (Art. 11)
# ---------------------------------------------------------------------------

class COM003(BasePolicy):
    policy_id = "COM-003"
    category = "Compliance"
    severity = "MEDIUM"
    title = "No technical documentation (EU AI Act Art. 11)"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        root = metadata.root
        has_docs = False

        # Check for documentation indicators
        docs_indicators = [
            root / "docs",
            root / "doc",
            root / "documentation",
            root / "README.md",
            root / "README.rst",
            root / "ARCHITECTURE.md",
        ]

        for indicator in docs_indicators:
            if indicator.exists():
                # For directories, check they're not empty
                if indicator.is_dir():
                    try:
                        if any(indicator.iterdir()):
                            has_docs = True
                            break
                    except OSError:
                        pass
                else:
                    # For README, check if it mentions agents
                    try:
                        content = indicator.read_text(encoding="utf-8", errors="ignore").lower()
                        if any(kw in content for kw in ("agent", "ai", "llm", "model")):
                            has_docs = True
                            break
                    except OSError:
                        pass

        if not has_docs:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="EU AI Act Article 11 requires technical documentation. No docs/ directory or comprehensive README found.",
                fix_snippet="# Create technical documentation for your AI system\n# Required by EU AI Act Art. 11:\n# - System architecture and design\n# - Agent capabilities and limitations\n# - Data used for training/prompting\n# - Risk assessment results\n# - Human oversight procedures\n\n# Create docs/ directory with at minimum:\nmkdir -p docs\n# docs/architecture.md  - System design\n# docs/agents.md        - Agent inventory & capabilities\n# docs/risk-assessment.md - Risk analysis",
            )]

        return []


# ---------------------------------------------------------------------------
# COM-004: No risk management documentation (Art. 9)
# ---------------------------------------------------------------------------

class COM004(BasePolicy):
    policy_id = "COM-004"
    category = "Compliance"
    severity = "MEDIUM"
    title = "No risk management documentation (EU AI Act Art. 9)"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        root = metadata.root

        risk_indicators = [
            root / "RISK_ASSESSMENT.md",
            root / "risk_assessment.md",
            root / "docs" / "risk-assessment.md",
            root / "docs" / "risk_assessment.md",
            root / "docs" / "risks.md",
        ]

        # Also check all config/doc content for risk management mentions
        has_risk_docs = any(indicator.exists() for indicator in risk_indicators)

        if not has_risk_docs:
            all_content = "\n".join(metadata.config_files.values())
            risk_patterns = ["risk_assessment", "risk_management", "risk_level", "threat_model"]
            has_risk_docs = any(p in all_content.lower() for p in risk_patterns)

        if not has_risk_docs:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="EU AI Act Article 9 requires a risk management system. No risk assessment documentation found.",
                fix_snippet="# Create a risk assessment document\n# EU AI Act Art. 9 requires:\n# - Identification of known and foreseeable risks\n# - Risk estimation and evaluation\n# - Risk mitigation measures\n# - Residual risk evaluation\n\n# Create RISK_ASSESSMENT.md with:\n# 1. Agent risk inventory\n# 2. Tool access risks (filesystem, network, etc.)\n# 3. Data handling risks\n# 4. Mitigation strategies",
            )]

        return []


# ---------------------------------------------------------------------------
# COM-005: No Agent BOM / inventory maintained
# ---------------------------------------------------------------------------

class COM005(BasePolicy):
    policy_id = "COM-005"
    category = "Compliance"
    severity = "MEDIUM"
    title = "No Agent BOM / inventory maintained"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        root = metadata.root

        bom_indicators = [
            root / ".drako.yaml",
            root / "drako.yaml",
            root / "agent-bom.json",
            root / "agent_bom.json",
            root / "AGENT_BOM.md",
        ]

        has_bom = any(indicator.exists() for indicator in bom_indicators)

        if not has_bom:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="No Agent Bill of Materials (BOM) maintained. An inventory of AI components is essential for governance.",
                fix_snippet='# Initialize Drako to maintain an Agent BOM\npip install drako\ndrako init\n\n# This creates .drako.yaml with:\n# - Agent inventory\n# - Tool registry\n# - Model usage tracking\n# - Governance policies',
            )]

        return []


# ---------------------------------------------------------------------------
# COM-006: No HITL checkpoint for high-risk actions
# ---------------------------------------------------------------------------

class COM006(BasePolicy):
    policy_id = "COM-006"
    category = "Compliance"
    severity = "CRITICAL"
    title = "No HITL checkpoint for high-risk actions"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # Only relevant if agents have tools with side-effects
        side_effect_tools = [
            t for t in bom.tools
            if _SIDE_EFFECT_TOOL_PATTERNS.search(t.name)
        ]
        if not side_effect_tools:
            return []

        # Check for HITL configuration in YAML config files
        all_config = "\n".join(metadata.config_files.values())
        if any(p.lower() in all_config.lower() for p in _HITL_CONFIG_PATTERNS):
            return []

        # Check for HITL patterns in Python source
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        if _content_has_pattern(all_content, _OVERSIGHT_PATTERNS):
            return []

        tool_names = ", ".join(t.name for t in side_effect_tools[:5])
        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"EU AI Act Article 14 requires human oversight for high-risk AI actions. "
                f"Tools with side-effects detected ({tool_names}) but no HITL checkpoint configured. "
                f"Agents can execute destructive actions without human approval."
            ),
            fix_snippet=(
                "# Configure HITL checkpoints in .drako.yaml:\n"
                "hitl:\n"
                "  mode: enforce\n"
                "  triggers:\n"
                "    tool_types:\n"
                "      - write\n"
                "      - execute\n"
                "      - payment\n"
                "    trust_score_below: 60\n"
                "    spend_above_usd: 100.00\n"
                "  approval_timeout_minutes: 30\n"
                "  timeout_action: reject"
            ),
        )]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

COMPLIANCE_POLICIES: list[BasePolicy] = [
    COM001(),
    COM002(),
    COM003(),
    COM004(),
    COM005(),
    COM006(),
]
