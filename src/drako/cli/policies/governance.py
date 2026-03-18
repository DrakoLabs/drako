"""Governance policy rules (GOV-001 through GOV-011)."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata

# Patterns indicating audit logging is configured
_AUDIT_PATTERNS = [
    "audit_log", "audit_trail", "with_compliance", "drako",
    "GovernanceMiddleware", "ComplianceMiddleware", "log_action",
    "AuditLog", "audit_logger",
]

# Patterns indicating policy enforcement
_POLICY_PATTERNS = [
    "evaluate_policy", "policy_check", "check_policy", "governance",
    "PolicyEngine", "policy_enforcement", "GovernanceMiddleware",
]

# Patterns indicating rate limiting
_RATE_LIMIT_PATTERNS = [
    "rate_limit", "ratelimit", "throttle", "RateLimiter",
    "rate_limiter", "calls_per_minute", "max_calls",
]

# Patterns indicating human-in-the-loop
_HITL_PATTERNS = [
    "human_in_the_loop", "hitl", "require_approval", "human_approval",
    "ask_human", "confirm_action", "manual_review", "approval_required",
]

# Patterns indicating circuit breaker
_CIRCUIT_BREAKER_PATTERNS = [
    "circuit_breaker", "CircuitBreaker", "pybreaker", "circuitbreaker",
    "breaker", "circuit_open",
]


def _content_has_pattern(all_content: str, patterns: list[str]) -> bool:
    """Check if any pattern exists in the combined content."""
    lower = all_content.lower()
    return any(p.lower() in lower for p in patterns)


# ---------------------------------------------------------------------------
# GOV-001: No audit logging configured
# ---------------------------------------------------------------------------

class GOV001(BasePolicy):
    policy_id = "GOV-001"
    category = "Governance"
    severity = "HIGH"
    title = "No audit logging configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _AUDIT_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="No audit logging detected in the project. All agent actions should be logged for traceability.",
                fix_snippet='from drako import GovernanceMiddleware\n\nmiddleware = GovernanceMiddleware(api_key="your-key")\ncrew = Crew(agents=[...], middleware=middleware)\n# All agent actions are now automatically logged',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-002: No policy enforcement middleware
# ---------------------------------------------------------------------------

class GOV002(BasePolicy):
    policy_id = "GOV-002"
    category = "Governance"
    severity = "MEDIUM"
    title = "No policy enforcement middleware"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _POLICY_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="No policy enforcement middleware detected. Agents can perform any action without governance checks.",
                fix_snippet='from drako import with_compliance\n\n# Wrap your crew/graph with governance middleware\ncrew = with_compliance(my_crew, config_path=".drako.yaml")\n# Policies are now evaluated before every agent action',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-003: No rate limiting on tool calls
# ---------------------------------------------------------------------------

class GOV003(BasePolicy):
    policy_id = "GOV-003"
    category = "Governance"
    severity = "MEDIUM"
    title = "No rate limiting on tool calls"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.tools:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _RATE_LIMIT_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f"No rate limiting detected on {len(bom.tools)} tool(s). Agents could make unlimited API/tool calls.",
                fix_snippet='# Add rate limiting to tool calls\nfrom functools import wraps\nimport time\n\ndef rate_limit(max_calls: int = 10, period: int = 60):\n    calls = []\n    def decorator(func):\n        @wraps(func)\n        def wrapper(*args, **kwargs):\n            now = time.time()\n            calls[:] = [t for t in calls if now - t < period]\n            if len(calls) >= max_calls:\n                raise RuntimeError("Rate limit exceeded")\n            calls.append(now)\n            return func(*args, **kwargs)\n        return wrapper\n    return decorator',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-004: No human-in-the-loop for destructive actions
# ---------------------------------------------------------------------------

class GOV004(BasePolicy):
    policy_id = "GOV-004"
    category = "Governance"
    severity = "HIGH"
    title = "No human-in-the-loop for destructive actions"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # Check if there are tools with filesystem write or code execution
        destructive_tools = [
            t for t in bom.tools
            if t.has_filesystem_access or t.has_code_execution
        ]

        if not destructive_tools:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _HITL_PATTERNS):
            tool_names = ", ".join(t.name for t in destructive_tools[:5])
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f"No human approval required for destructive tools: {tool_names}",
                fix_snippet='# Add human-in-the-loop for high-risk operations\n@middleware.require_approval(tools=["write_file", "delete_file"])\ndef run_agent():\n    # Agent will pause and ask for human approval\n    # before executing write_file or delete_file\n    crew.kickoff()',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-005: No circuit breaker configured
# ---------------------------------------------------------------------------

class GOV005(BasePolicy):
    policy_id = "GOV-005"
    category = "Governance"
    severity = "MEDIUM"
    title = "No circuit breaker configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _CIRCUIT_BREAKER_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="No circuit breaker pattern detected. Failed tool/LLM calls could cascade without automatic recovery.",
                fix_snippet='import pybreaker\n\n# Circuit breaker trips after 5 failures, resets after 30s\nllm_breaker = pybreaker.CircuitBreaker(\n    fail_max=5,\n    reset_timeout=30,\n)\n\n@llm_breaker\ndef call_llm(prompt: str) -> str:\n    return client.chat(prompt)',
            )]

        return []


# ---------------------------------------------------------------------------
# GOV-006: Agent can modify its own system prompt
# ---------------------------------------------------------------------------

class GOV006(BasePolicy):
    policy_id = "GOV-006"
    category = "Governance"
    severity = "CRITICAL"
    title = "Agent can modify its own system prompt"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue

            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            for node in ast.walk(tree):
                # Look for self.system_prompt = ... or self.prompt = ...
                # OUTSIDE of __init__
                if isinstance(node, ast.FunctionDef) and node.name != "__init__":
                    for child in ast.walk(node):
                        if isinstance(child, ast.Assign):
                            for target in child.targets:
                                if (isinstance(target, ast.Attribute)
                                        and isinstance(target.value, ast.Name)
                                        and target.value.id == "self"
                                        and target.attr in ("system_prompt", "prompt", "instructions", "system_message")):
                                    line_content = lines[child.lineno - 1].strip() if child.lineno <= len(lines) else ""
                                    findings.append(Finding(
                                        policy_id=self.policy_id,
                                        category=self.category,
                                        severity=self.severity,
                                        title=self.title,
                                        message=f'Agent modifies its own "{target.attr}" in method "{node.name}"',
                                        file_path=rel_path,
                                        line_number=child.lineno,
                                        code_snippet=line_content[:80],
                                        fix_snippet='# Make system prompts immutable — set once in __init__\nclass MyAgent:\n    def __init__(self, prompt: str):\n        self._frozen_prompt = prompt\n\n    @property\n    def system_prompt(self) -> str:\n        return self._frozen_prompt  # Read-only',
                                    ))

        return findings


# ---------------------------------------------------------------------------
# GOV-007: No per-tool failure handling
# ---------------------------------------------------------------------------

# Patterns indicating external I/O calls
_EXTERNAL_CALL_PATTERNS = re.compile(
    r"(?:requests\.|httpx\.|urllib\.|aiohttp\.|open\(|"
    r"subprocess\.|os\.system|db\.|cursor\.|execute\(|"
    r"fetch\(|download\(|upload\()",
    re.IGNORECASE,
)


class GOV007(BasePolicy):
    policy_id = "GOV-007"
    category = "Governance"
    severity = "MEDIUM"
    title = "No per-tool failure handling"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            content = metadata.file_contents.get(tool.file_path, "")
            if not content:
                continue

            # Find the tool function body
            func_match = re.search(
                rf"def\s+{re.escape(tool.name)}\s*\(.*?\).*?(?=\ndef\s|\Z)",
                content, re.DOTALL,
            )
            if not func_match:
                continue

            func_body = func_match.group()

            # Does the tool make external calls?
            if not _EXTERNAL_CALL_PATTERNS.search(func_body):
                continue

            # Does the tool have error handling?
            has_try_except = "try:" in func_body and "except" in func_body

            if not has_try_except:
                findings.append(Finding(
                    policy_id=self.policy_id,
                    category=self.category,
                    severity=self.severity,
                    title=self.title,
                    message=f'Tool "{tool.name}" makes external calls without error handling',
                    file_path=tool.file_path,
                    line_number=tool.line_number,
                    code_snippet=f"# Tool: {tool.name} has no try/except around external calls",
                    fix_snippet=(
                        "@tool\n"
                        "def my_tool(query: str) -> str:\n"
                        "    try:\n"
                        "        result = external_api.call(query)\n"
                        "        return result\n"
                        "    except (ConnectionError, TimeoutError) as e:\n"
                        '        return f"Tool temporarily unavailable: {e}"'
                    ),
                ))

        return findings


# ---------------------------------------------------------------------------
# GOV-008: No fallback defined for critical tools
# ---------------------------------------------------------------------------

_CRITICAL_TOOL_PATTERNS = re.compile(
    r"(?:write|delete|remove|send|pay|transfer|execute|deploy|publish|post|push|submit)",
    re.IGNORECASE,
)

_FALLBACK_PATTERNS = re.compile(
    r"(?:fallback|retry|retries|backoff|tenacity|@retry|"
    r"alternative|backup|redundant|failover|graceful_degrad)",
    re.IGNORECASE,
)


class GOV008(BasePolicy):
    policy_id = "GOV-008"
    category = "Governance"
    severity = "HIGH"
    title = "No fallback for critical tool"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            # Check if tool name suggests critical/side-effect operations
            if not _CRITICAL_TOOL_PATTERNS.search(tool.name):
                continue

            content = metadata.file_contents.get(tool.file_path, "")
            if not content:
                continue

            func_match = re.search(
                rf"def\s+{re.escape(tool.name)}\s*\(.*?\).*?(?=\ndef\s|\Z)",
                content, re.DOTALL,
            )
            if not func_match:
                continue

            func_body = func_match.group()

            if _FALLBACK_PATTERNS.search(func_body):
                continue

            findings.append(Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f'Critical tool "{tool.name}" has no fallback or retry logic',
                file_path=tool.file_path,
                line_number=tool.line_number,
                code_snippet=f"# Tool: {tool.name} performs side-effects without fallback",
                fix_snippet=(
                    "from tenacity import retry, stop_after_attempt, wait_exponential\n\n"
                    "@retry(stop=stop_after_attempt(3), wait=wait_exponential())\n"
                    "def my_critical_tool(data: str) -> str:\n"
                    "    result = api.send(data)\n"
                    "    return result\n\n"
                    "# Or define a fallback:\n"
                    "def fallback_tool(data: str) -> str:\n"
                    '    return "Operation queued for manual processing"'
                ),
            ))

        return findings


# ---------------------------------------------------------------------------
# GOV-009: Agent can execute destructive actions autonomously
# ---------------------------------------------------------------------------

_HITL_REGEX = re.compile(
    r"(?:human_in_the_loop|hitl|require_approval|human_approval|"
    r"ask_human|confirm_action|manual_review|human_oversight|"
    r"supervisor|approval_required|pending_approval|human_gate)",
    re.IGNORECASE,
)


class GOV009(BasePolicy):
    policy_id = "GOV-009"
    category = "Governance"
    severity = "CRITICAL"
    title = "Agent can execute destructive actions autonomously"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            if not _CRITICAL_TOOL_PATTERNS.search(tool.name):
                continue

            content = metadata.file_contents.get(tool.file_path, "")
            if not content:
                continue

            # Extract the function body
            func_match = re.search(
                rf"def\s+{re.escape(tool.name)}\s*\(.*?\).*?(?=\ndef\s|\Z)",
                content, re.DOTALL,
            )
            func_body = func_match.group() if func_match else content

            if _HITL_REGEX.search(func_body):
                continue

            findings.append(Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f'Tool "{tool.name}" can execute destructive actions (delete/write/execute/pay) '
                    f"without any human approval gate. This violates EU AI Act Art. 14."
                ),
                file_path=tool.file_path,
                line_number=tool.line_number,
                code_snippet=f"# Tool: {tool.name} has no HITL checkpoint",
                fix_snippet=(
                    "# Add HITL checkpoint in .drako.yaml:\n"
                    "hitl:\n"
                    "  mode: enforce\n"
                    "  triggers:\n"
                    "    tools:\n"
                    f"      - {tool.name}\n"
                    "    tool_types:\n"
                    "      - write\n"
                    "      - execute\n"
                    "      - payment"
                ),
            ))

        return findings


# ---------------------------------------------------------------------------
# GOV-010: No escalation path defined
# ---------------------------------------------------------------------------

_ESCALATION_PATTERNS = re.compile(
    r"(?:escalat|supervisor|admin_review|human_review|on_reject|"
    r"on_failure.*human|fallback_human|approval_flow|notification.*webhook|"
    r"notify_admin|alert_supervisor|escalation_policy)",
    re.IGNORECASE,
)


class GOV010(BasePolicy):
    policy_id = "GOV-010"
    category = "Governance"
    severity = "HIGH"
    title = "No escalation path defined"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        all_config = "\n".join(metadata.config_files.values())
        combined = all_content + "\n" + all_config

        if _ESCALATION_PATTERNS.search(combined):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                "No escalation path defined for agent failures or policy violations. "
                "When an agent encounters an error or a governance check blocks an action, "
                "there is no mechanism to notify a supervisor or route to a human."
            ),
            fix_snippet=(
                "# Define escalation in .drako.yaml:\n"
                "hitl:\n"
                "  mode: enforce\n"
                "  notification:\n"
                '    webhook_url: "https://hooks.slack.com/services/xxx"\n'
                '    email: "supervisor@company.com"\n'
                "  approval_timeout_minutes: 30\n"
                "  timeout_action: reject"
            ),
        )]


# ---------------------------------------------------------------------------
# GOV-011: Action replay vulnerability
# ---------------------------------------------------------------------------

_REPLAY_PROTECTION_PATTERNS = re.compile(
    r"(?:nonce|idempotency_key|idempotent|replay_protect|sequence_number|"
    r"intent_hash|request_id.*dedup|deduplicat|unique_request|"
    r"already_processed|prevent_replay)",
    re.IGNORECASE,
)


class GOV011(BasePolicy):
    policy_id = "GOV-011"
    category = "Governance"
    severity = "HIGH"
    title = "Action replay vulnerability"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            if not _CRITICAL_TOOL_PATTERNS.search(tool.name):
                continue

            content = metadata.file_contents.get(tool.file_path, "")
            if not content:
                continue

            func_match = re.search(
                rf"def\s+{re.escape(tool.name)}\s*\(.*?\).*?(?=\ndef\s|\Z)",
                content, re.DOTALL,
            )
            func_body = func_match.group() if func_match else content

            if _REPLAY_PROTECTION_PATTERNS.search(func_body):
                continue

            findings.append(Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f'Tool "{tool.name}" can be called repeatedly without idempotency check. '
                    f"A retry or replay could duplicate writes, payments, or destructive actions."
                ),
                file_path=tool.file_path,
                line_number=tool.line_number,
                code_snippet=f"# Tool: {tool.name} has no replay protection",
                fix_snippet=(
                    "# Add intent fingerprinting in .drako.yaml:\n"
                    "intent_verification:\n"
                    "  mode: enforce\n"
                    "  anti_replay: true\n"
                    "  intent_ttl_seconds: 300\n"
                    "  required_for:\n"
                    "    tools:\n"
                    f"      - {tool.name}\n\n"
                    "# Or add idempotency in code:\n"
                    "def my_tool(data: str, request_id: str) -> str:\n"
                    "    if already_processed(request_id):\n"
                    '        return "Already executed"\n'
                    "    result = execute(data)\n"
                    "    mark_processed(request_id)\n"
                    "    return result"
                ),
            ))

        return findings


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

GOVERNANCE_POLICIES: list[BasePolicy] = [
    GOV001(),
    GOV002(),
    GOV003(),
    GOV004(),
    GOV005(),
    GOV006(),
    GOV007(),
    GOV008(),
    GOV009(),
    GOV010(),
    GOV011(),
]
