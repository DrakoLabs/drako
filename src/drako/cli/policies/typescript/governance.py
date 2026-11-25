"""TypeScript governance policy rules (GOV-*).

Detects missing audit logging, human-in-the-loop controls, and
circuit breaker patterns in TypeScript AI agent projects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding
from drako.cli.policies.typescript._utils import is_ts_file

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


def _content_has_pattern(content: str, patterns: list[str]) -> bool:
    lower = content.lower()
    return any(p in lower for p in patterns)


# ---------------------------------------------------------------------------
# GOV-001: No audit logging
# ---------------------------------------------------------------------------


class GOV001TS(BasePolicy):
    policy_id = "GOV-001"
    category = "Governance"
    severity = "HIGH"
    title = "No audit logging configured"
    impact = (
        "Without audit logs, you cannot trace what actions an agent took, "
        "making incident response and compliance audits impossible."
    )
    attack_scenario = (
        "A compromised agent deletes records. With no audit trail, "
        "you cannot determine what was deleted, when, or why."
    )
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_ts = "\n".join(
            c for p, c in metadata.file_contents.items() if is_ts_file(p)
        )
        if not all_ts.strip():
            return []

        has_logging = _content_has_pattern(all_ts, [
            "audit_log", "auditlog", "audit_trail", "audittrail",
            "winston", "pino", "bunyan", "loglevel", "logger.",
            "console.log", "log.info", "log.warn", "log.error",
            "drako", "governancemiddleware",
        ])

        if not has_logging:
            return [self._finding(
                "No audit logging detected in TypeScript project. "
                "All agent actions should be logged for traceability.",
                fix_snippet=(
                    "import pino from 'pino';\n"
                    "const logger = pino({ name: 'agent-audit' });\n"
                    "logger.info({ action, agent, input, output }, 'agent-action');"
                ),
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-004: No human-in-the-loop
# ---------------------------------------------------------------------------


class GOV004TS(BasePolicy):
    policy_id = "GOV-004"
    category = "Governance"
    severity = "HIGH"
    title = "No human-in-the-loop for high-impact actions"
    impact = (
        "Without human approval for destructive or sensitive actions, "
        "agents can cause irreversible damage autonomously."
    )
    attack_scenario = (
        "A billing agent autonomously processes a large refund triggered "
        "by a prompt injection, with no human approval step."
    )
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_ts = "\n".join(
            c for p, c in metadata.file_contents.items() if is_ts_file(p)
        )
        if not all_ts.strip():
            return []

        has_side_effects = _content_has_pattern(all_ts, [
            "writefile", "unlink", "rmdir", "exec(", "execsync",
            "delete(", "put(", "post(", "send(",
            "transfer", "refund", "payment",
        ])
        has_approval = _content_has_pattern(all_ts, [
            "confirm", "approval", "approve", "human_in_the_loop",
            "humanintheloop", "requireapproval", "require_approval",
            "askuser", "ask_user", "hitl",
        ])

        if has_side_effects and not has_approval:
            return [self._finding(
                "Tools with side effects detected but no human approval pattern found. "
                "Add confirmation for destructive or sensitive operations.",
                fix_snippet=(
                    "async function executeWithApproval(action: string) {\n"
                    "  const approved = await askHumanApproval(action);\n"
                    "  if (!approved) throw new Error('Action not approved');\n"
                    "}"
                ),
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-005: No circuit breaker
# ---------------------------------------------------------------------------


class GOV005TS(BasePolicy):
    policy_id = "GOV-005"
    category = "Governance"
    severity = "MEDIUM"
    title = "No circuit breaker or retry logic for LLM calls"
    impact = (
        "Without circuit breakers, LLM API failures cascade into "
        "application crashes or infinite retry loops burning tokens."
    )
    attack_scenario = (
        "OpenAI API returns 429 rate-limit errors. Without a circuit breaker, "
        "the agent retries in a tight loop, exhausting rate limits faster."
    )
    references = [
        "https://learn.microsoft.com/en-us/azure/architecture/patterns/circuit-breaker",
    ]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_ts = "\n".join(
            c for p, c in metadata.file_contents.items() if is_ts_file(p)
        )
        if not all_ts.strip():
            return []

        has_llm_calls = _content_has_pattern(all_ts, [
            "openai(", "anthropic(", "generatetext(",
            "streamtext(", "chat.completions", "messages.create",
        ])
        has_resilience = _content_has_pattern(all_ts, [
            "circuitbreaker", "circuit_breaker", "retry",
            "backoff", "exponentialbackoff", "cockatiel",
            "p-retry", "async-retry", "got.retry",
            "maxretries", "max_retries",
        ])

        if has_llm_calls and not has_resilience:
            return [self._finding(
                "LLM API calls detected without circuit breaker or retry logic.",
                fix_snippet=(
                    "import pRetry from 'p-retry';\n"
                    "const result = await pRetry(() => openai.chat.completions.create({...}), {\n"
                    "  retries: 3,\n"
                    "  onFailedAttempt: (err) => logger.warn(`Retry ${err.attemptNumber}`);\n"
                    "});"
                ),
            )]

        return []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TS_GOVERNANCE_POLICIES: list[BasePolicy] = [
    GOV001TS(),
    GOV004TS(),
    GOV005TS(),
]
