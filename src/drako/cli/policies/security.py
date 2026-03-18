"""Security policy rules (SEC-001 through SEC-007)."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Common API key prefixes / patterns
_API_KEY_PATTERNS = [
    re.compile(r"""(?:"|')sk-[a-zA-Z0-9]{20,}(?:"|')"""),                     # OpenAI
    re.compile(r"""(?:"|')sk-proj-[a-zA-Z0-9_-]{20,}(?:"|')"""),              # OpenAI project
    re.compile(r"""(?:"|')sk-ant-[a-zA-Z0-9_-]{20,}(?:"|')"""),               # Anthropic
    re.compile(r"""(?:"|')AKIA[A-Z0-9]{16,}(?:"|')"""),                        # AWS
    re.compile(r"""(?:"|')ghp_[a-zA-Z0-9]{36}(?:"|')"""),                      # GitHub
    re.compile(r"""(?:"|')gho_[a-zA-Z0-9]{36}(?:"|')"""),                      # GitHub OAuth
    re.compile(r"""(?:"|')AIza[a-zA-Z0-9_-]{35}(?:"|')"""),                    # Google
    re.compile(r"""(?:"|')xox[bprs]-[a-zA-Z0-9-]{10,}(?:"|')"""),             # Slack
    re.compile(r"""(?:"|')(?:bearer|token|api[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]""", re.IGNORECASE),
]

# Variable names that suggest API keys
_SECRET_VAR_NAMES = re.compile(
    r"(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|private[_-]?key|secret)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# SEC-001: API keys hardcoded in source code
# ---------------------------------------------------------------------------

class SEC001(BasePolicy):
    policy_id = "SEC-001"
    category = "Security"
    severity = "CRITICAL"
    title = "API key hardcoded in source code"

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
                # Check string assignments to suspicious variable names
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        var_name = None
                        if isinstance(target, ast.Name):
                            var_name = target.id
                        elif isinstance(target, ast.Attribute):
                            var_name = target.attr

                        if var_name and _SECRET_VAR_NAMES.search(var_name):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                val = node.value.value
                                if len(val) >= 8 and not val.startswith(("os.environ", "os.getenv", "{")):
                                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                                    findings.append(Finding(
                                        policy_id=self.policy_id,
                                        category=self.category,
                                        severity=self.severity,
                                        title=self.title,
                                        message=f'Hardcoded secret in variable "{var_name}"',
                                        file_path=rel_path,
                                        line_number=node.lineno,
                                        code_snippet=line_content,
                                        fix_snippet=f'import os\n{var_name} = os.environ["{var_name.upper()}"]',
                                    ))

            # Also check for raw API key patterns in the source
            for i, line in enumerate(lines, 1):
                if line.strip().startswith("#"):
                    continue
                for pattern in _API_KEY_PATTERNS:
                    if pattern.search(line):
                        # Avoid double-counting with AST findings
                        if not any(f.file_path == rel_path and f.line_number == i for f in findings):
                            findings.append(Finding(
                                policy_id=self.policy_id,
                                category=self.category,
                                severity=self.severity,
                                title=self.title,
                                message="API key pattern detected in source code",
                                file_path=rel_path,
                                line_number=i,
                                code_snippet=line.strip()[:80],
                                fix_snippet='import os\napi_key = os.environ["API_KEY"]',
                            ))
                        break

        return findings


# ---------------------------------------------------------------------------
# SEC-002: Secrets in prompts or configuration
# ---------------------------------------------------------------------------

class SEC002(BasePolicy):
    policy_id = "SEC-002"
    category = "Security"
    severity = "CRITICAL"
    title = "Secrets in prompts or configuration"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for prompt in bom.prompts:
            preview = prompt.content_preview.lower()
            if any(kw in preview for kw in ("api_key", "secret", "password", "token", "sk-", "akia")):
                findings.append(Finding(
                    policy_id=self.policy_id,
                    category=self.category,
                    severity=self.severity,
                    title=self.title,
                    message="Potential secret or API key reference found in prompt text",
                    file_path=prompt.file_path,
                    line_number=prompt.line_number,
                    code_snippet=prompt.content_preview[:60],
                    fix_snippet="Never include secrets in prompts. Use environment variables\nand inject values at runtime, not in prompt templates.",
                ))

        return findings


# ---------------------------------------------------------------------------
# SEC-003: Unrestricted filesystem access in tools
# ---------------------------------------------------------------------------

class SEC003(BasePolicy):
    policy_id = "SEC-003"
    category = "Security"
    severity = "HIGH"
    title = "Unrestricted filesystem access in tool"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            if tool.has_filesystem_access:
                # Check if there's any path validation in the function
                content = metadata.file_contents.get(tool.file_path, "")
                has_validation = _has_path_validation(content, tool.name)

                if not has_validation:
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f'Tool "{tool.name}" has filesystem access without path validation',
                        file_path=tool.file_path,
                        line_number=tool.line_number,
                        code_snippet=f"# Tool: {tool.name} uses open()/Path without path restriction",
                        fix_snippet='from pathlib import Path\n\nALLOWED_DIR = Path("/data/output")\n\ndef validate_path(path: str) -> Path:\n    resolved = Path(path).resolve()\n    if not str(resolved).startswith(str(ALLOWED_DIR)):\n        raise ValueError(f"Path {path} outside allowed directory")\n    return resolved',
                    ))

        return findings


def _has_path_validation(content: str, func_name: str) -> bool:
    """Check if a function has any path validation patterns."""
    patterns = [
        r"allowed_dir",
        r"validate_path",
        r"startswith\(",
        r"is_relative_to\(",
        r"resolve\(\)",
        r"ALLOWED",
        r"whitelist",
        r"allowlist",
    ]
    # Try to find the function body
    func_match = re.search(rf"def\s+{re.escape(func_name)}\s*\(.*?\).*?(?=\ndef\s|\Z)", content, re.DOTALL)
    if func_match:
        func_body = func_match.group()
        return any(re.search(p, func_body, re.IGNORECASE) for p in patterns)
    return False


# ---------------------------------------------------------------------------
# SEC-004: Unrestricted network access in tools
# ---------------------------------------------------------------------------

class SEC004(BasePolicy):
    policy_id = "SEC-004"
    category = "Security"
    severity = "HIGH"
    title = "Unrestricted network access in tool"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            if tool.has_network_access:
                content = metadata.file_contents.get(tool.file_path, "")
                has_allowlist = _has_domain_allowlist(content, tool.name)

                if not has_allowlist:
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f'Tool "{tool.name}" makes HTTP requests without domain allowlist',
                        file_path=tool.file_path,
                        line_number=tool.line_number,
                        code_snippet=f"# Tool: {tool.name} uses requests/httpx without domain restriction",
                        fix_snippet='ALLOWED_DOMAINS = ["api.example.com", "data.example.com"]\n\ndef validate_url(url: str) -> str:\n    from urllib.parse import urlparse\n    host = urlparse(url).hostname\n    if host not in ALLOWED_DOMAINS:\n        raise ValueError(f"Domain {host} not in allowlist")\n    return url',
                    ))

        return findings


def _has_domain_allowlist(content: str, func_name: str) -> bool:
    """Check if a function has domain/URL validation."""
    patterns = [
        r"allowed_domain",
        r"allowlist",
        r"whitelist",
        r"domain_check",
        r"urlparse",
        r"validate_url",
        r"ALLOWED_DOMAINS",
        r"ALLOWED_URLS",
    ]
    func_match = re.search(rf"def\s+{re.escape(func_name)}\s*\(.*?\).*?(?=\ndef\s|\Z)", content, re.DOTALL)
    if func_match:
        func_body = func_match.group()
        return any(re.search(p, func_body, re.IGNORECASE) for p in patterns)
    return False


# ---------------------------------------------------------------------------
# SEC-005: Arbitrary code execution (exec/eval/subprocess)
# ---------------------------------------------------------------------------

class SEC005(BasePolicy):
    policy_id = "SEC-005"
    category = "Security"
    severity = "CRITICAL"
    title = "Arbitrary code execution in tool"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        # Check tools first
        for tool in bom.tools:
            if tool.has_code_execution:
                findings.append(Finding(
                    policy_id=self.policy_id,
                    category=self.category,
                    severity=self.severity,
                    title=self.title,
                    message=f'Tool "{tool.name}" can execute arbitrary code (exec/eval/subprocess)',
                    file_path=tool.file_path,
                    line_number=tool.line_number,
                    code_snippet=f"# Tool: {tool.name} uses exec(), eval(), or subprocess",
                    fix_snippet='# Use a sandboxed execution environment\nfrom drako.sandbox import safe_exec\nresult = safe_exec(code, timeout=30, allowed_modules=["math"])',
                ))

        # Also scan all files for dangerous calls not in tools
        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id in ("os", "subprocess"):
                            func_name = f"{node.func.value.id}.{node.func.attr}"

                if func_name in ("exec", "eval"):
                    # Skip if already reported as a tool
                    if any(f.file_path == rel_path and f.policy_id == self.policy_id for f in findings):
                        continue
                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f"Dangerous {func_name}() call found",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content[:80],
                        fix_snippet="Avoid exec()/eval() with untrusted input.\nUse ast.literal_eval() for data parsing or a sandboxed environment.",
                    ))

                if func_name and func_name.startswith(("os.system", "os.popen", "subprocess.")):
                    if any(f.file_path == rel_path and f.policy_id == self.policy_id for f in findings):
                        continue
                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f"Shell command execution via {func_name}()",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content[:80],
                        fix_snippet="Avoid shell commands with agent-controlled input.\nUse subprocess.run() with shell=False and validate all arguments.",
                    ))

        return findings


# ---------------------------------------------------------------------------
# SEC-006: No input validation on tool parameters
# ---------------------------------------------------------------------------

class SEC006(BasePolicy):
    policy_id = "SEC-006"
    category = "Security"
    severity = "MEDIUM"
    title = "No input validation on tool parameters"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for tool in bom.tools:
            content = metadata.file_contents.get(tool.file_path, "")
            if not content:
                continue

            try:
                tree = ast.parse(content, filename=tool.file_path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == tool.name:
                    # Check if function has type annotations on parameters
                    has_annotations = False
                    for arg in node.args.args:
                        if arg.arg == "self":
                            continue
                        if arg.annotation is not None:
                            has_annotations = True
                            break

                    # Check for validation patterns in body
                    body_src = ast.dump(node)
                    has_validation = any(
                        kw in body_src for kw in
                        ("isinstance", "validate", "ValueError", "TypeError", "assert")
                    )

                    if not has_annotations and not has_validation:
                        findings.append(Finding(
                            policy_id=self.policy_id,
                            category=self.category,
                            severity=self.severity,
                            title=self.title,
                            message=f'Tool "{tool.name}" has no type annotations or input validation',
                            file_path=tool.file_path,
                            line_number=tool.line_number,
                            code_snippet=f"def {tool.name}(...)  # No type hints or validation",
                            fix_snippet=f'@tool\ndef {tool.name}(query: str, limit: int = 10) -> str:\n    """Add type hints and validate inputs."""\n    if not query or len(query) > 1000:\n        raise ValueError("Invalid query")',
                        ))

        return findings


# ---------------------------------------------------------------------------
# SEC-007: Prompt injection vulnerability
# ---------------------------------------------------------------------------

class SEC007(BasePolicy):
    policy_id = "SEC-007"
    category = "Security"
    severity = "HIGH"
    title = "Prompt injection vulnerability"

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
                # Look for f-strings or .format() in prompt-related assignments
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        name = None
                        if isinstance(target, ast.Name):
                            name = target.id
                        elif isinstance(target, ast.Attribute):
                            name = target.attr

                        if name and any(kw in name.lower() for kw in ("prompt", "system_message", "instruction")):
                            if isinstance(node.value, ast.JoinedStr):
                                # f-string in a prompt
                                line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                                findings.append(Finding(
                                    policy_id=self.policy_id,
                                    category=self.category,
                                    severity=self.severity,
                                    title=self.title,
                                    message=f'User input interpolated into prompt via f-string in "{name}"',
                                    file_path=rel_path,
                                    line_number=node.lineno,
                                    code_snippet=line_content[:80],
                                    fix_snippet="# Separate system prompt from user input\nsystem_prompt = \"You are a helpful assistant.\"\n# Pass user input as a separate message, not interpolated\nmessages = [\n    {\"role\": \"system\", \"content\": system_prompt},\n    {\"role\": \"user\", \"content\": user_input},\n]",
                                ))

                            if isinstance(node.value, ast.Call):
                                func = node.value.func
                                if isinstance(func, ast.Attribute) and func.attr == "format":
                                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                                    findings.append(Finding(
                                        policy_id=self.policy_id,
                                        category=self.category,
                                        severity=self.severity,
                                        title=self.title,
                                        message=f'User input interpolated into prompt via .format() in "{name}"',
                                        file_path=rel_path,
                                        line_number=node.lineno,
                                        code_snippet=line_content[:80],
                                        fix_snippet="# Separate system prompt from user input\nsystem_prompt = \"You are a helpful assistant.\"\n# Pass user input as a separate message, not interpolated\nmessages = [\n    {\"role\": \"system\", \"content\": system_prompt},\n    {\"role\": \"user\", \"content\": user_input},\n]",
                                    ))

        return findings


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SEC-008: Tool results used without sanitization
# ---------------------------------------------------------------------------

# Sources indicating data from external/untrusted origins
_EXTERNAL_DATA_CALLS = re.compile(
    r"(?:requests\.get|requests\.post|httpx\.|urllib\.|urlopen|"
    r"open\(|read_file|db_query|web_search|scrape|fetch|download|"
    r"execute_query|run_query|get_url|read_url)",
    re.IGNORECASE,
)

_SANITIZATION_PATTERNS = re.compile(
    r"(?:sanitize|validate|clean|escape|strip_tags|bleach|"
    r"html\.escape|markupsafe|DOMPurify|filter_input|"
    r"re\.sub|re\.match|isinstance|json\.loads)",
    re.IGNORECASE,
)


class SEC008(BasePolicy):
    policy_id = "SEC-008"
    category = "Security"
    severity = "CRITICAL"
    title = "No input sanitization on tool results"

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

            # Does the tool fetch external data?
            if not _EXTERNAL_DATA_CALLS.search(func_body):
                continue

            # Does the tool sanitize before returning?
            if _SANITIZATION_PATTERNS.search(func_body):
                continue

            findings.append(Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f'Tool "{tool.name}" returns external data without sanitization',
                file_path=tool.file_path,
                line_number=tool.line_number,
                code_snippet=f"# Tool: {tool.name} fetches external data and returns raw",
                fix_snippet=(
                    "def sanitize_tool_output(raw: str) -> str:\n"
                    '    """Strip dangerous content from tool results."""\n'
                    "    import re\n"
                    "    # Remove potential injection markers\n"
                    '    sanitized = re.sub(r"\\[INST\\]|\\[/INST\\]|<\\|.*?\\|>", "", raw)\n'
                    "    return sanitized.strip()[:5000]  # Truncate"
                ),
            ))

        return findings


# ---------------------------------------------------------------------------
# SEC-009: Agent processes untrusted external data in prompts
# ---------------------------------------------------------------------------

class SEC009(BasePolicy):
    policy_id = "SEC-009"
    category = "Security"
    severity = "HIGH"
    title = "Agent processes untrusted external data"

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
                if not isinstance(node, ast.Assign):
                    continue

                for target in node.targets:
                    name = None
                    if isinstance(target, ast.Name):
                        name = target.id
                    elif isinstance(target, ast.Attribute):
                        name = target.attr

                    if not name:
                        continue

                    # Only check prompt-like variable names
                    if not any(kw in name.lower() for kw in (
                        "prompt", "system_message", "instruction", "context", "messages"
                    )):
                        continue

                    # Check f-string interpolation with result/output/response variables
                    if isinstance(node.value, ast.JoinedStr):
                        src_line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        if any(kw in src_line.lower() for kw in (
                            "result", "output", "response", "data", "content", "tool_output",
                        )):
                            findings.append(Finding(
                                policy_id=self.policy_id,
                                category=self.category,
                                severity=self.severity,
                                title=self.title,
                                message=f'Tool output interpolated into prompt variable "{name}"',
                                file_path=rel_path,
                                line_number=node.lineno,
                                code_snippet=src_line.strip()[:80],
                                fix_snippet=(
                                    "# Separate tool output from system prompt\n"
                                    "messages = [\n"
                                    '    {"role": "system", "content": system_prompt},\n'
                                    '    {"role": "tool", "content": sanitize(tool_output)},\n'
                                    '    {"role": "user", "content": user_input},\n'
                                    "]"
                                ),
                            ))

                    # Check string concatenation with + on result-like variables
                    if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                        src_line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        if any(kw in src_line.lower() for kw in (
                            "result", "output", "response", "tool_output",
                        )):
                            findings.append(Finding(
                                policy_id=self.policy_id,
                                category=self.category,
                                severity=self.severity,
                                title=self.title,
                                message=f'Tool output concatenated into prompt variable "{name}"',
                                file_path=rel_path,
                                line_number=node.lineno,
                                code_snippet=src_line.strip()[:80],
                                fix_snippet=(
                                    "# Never concatenate raw tool output into prompts\n"
                                    "# Use structured messages instead:\n"
                                    "messages = [\n"
                                    '    {"role": "system", "content": system_prompt},\n'
                                    '    {"role": "tool", "content": sanitize(tool_output)},\n'
                                    "]"
                                ),
                            ))

        return findings


# ---------------------------------------------------------------------------
# SEC-010: No prompt injection defense configured
# ---------------------------------------------------------------------------

_INJECTION_DEFENSE_PATTERNS = [
    "guardrails", "guardrail", "drako", "GovernanceMiddleware",
    "PromptGuard", "prompt_guard", "lakera", "rebuff", "nemo_guardrails",
    "input_validation", "sanitize_prompt", "injection_detection",
    "instruction_hierarchy", "system_boundary", "with_compliance",
    "PromptInjectionDetector", "ContentFilter",
]


class SEC010(BasePolicy):
    policy_id = "SEC-010"
    category = "Security"
    severity = "HIGH"
    title = "No prompt injection defense configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        lower = all_content.lower()

        if any(p.lower() in lower for p in _INJECTION_DEFENSE_PATTERNS):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                "No prompt injection defense detected in the project. "
                "Agents processing external data are vulnerable to indirect prompt injection."
            ),
            fix_snippet=(
                "from drako import with_compliance\n\n"
                '# Add injection detection middleware\n'
                'crew = with_compliance(my_crew, config_path=".drako.yaml")\n'
                "# Or install standalone guardrails:\n"
                "# pip install drako && drako init"
            ),
        )]


# ---------------------------------------------------------------------------
# SEC-011: No intent verification on high-impact actions
# ---------------------------------------------------------------------------

_HIGH_IMPACT_TOOL_PATTERNS = re.compile(
    r"(?:transfer|payment|pay|send_money|withdraw|delete|drop|remove|modify|"
    r"execute_code|run_command|deploy|write_file|update_record)",
    re.IGNORECASE,
)

_INTENT_VERIFICATION_PATTERNS = re.compile(
    r"(?:intent_verif|intent_fingerprint|verify_intent|intent_hash|"
    r"two_gate|pre_verify|action_nonce|checksum|integrity_check|"
    r"verify_before_execute)",
    re.IGNORECASE,
)


class SEC011(BasePolicy):
    policy_id = "SEC-011"
    category = "Security"
    severity = "HIGH"
    title = "No intent verification on high-impact actions"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        high_impact_tools = [
            t for t in bom.tools
            if _HIGH_IMPACT_TOOL_PATTERNS.search(t.name)
        ]
        if not high_impact_tools:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        all_config = "\n".join(metadata.config_files.values())
        combined = all_content + "\n" + all_config

        if _INTENT_VERIFICATION_PATTERNS.search(combined):
            return []

        tool_names = ", ".join(t.name for t in high_impact_tools[:5])
        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"High-impact tools detected ({tool_names}) without intent verification. "
                f"Between the LLM's decision and execution, hallucination, prompt injection, "
                f"or parsing bugs could alter arguments. No cryptographic verification "
                f"guarantees that the executed action matches the intended one."
            ),
            fix_snippet=(
                "# Add intent fingerprinting in .drako.yaml:\n"
                "intent_verification:\n"
                "  mode: enforce\n"
                "  required_for:\n"
                "    tool_types:\n"
                "      - payment\n"
                "      - write\n"
                "      - execute\n"
                "    tools:\n"
                "      - transfer_funds\n"
                "      - delete_records\n"
                "  anti_replay: true\n"
                "  intent_ttl_seconds: 300"
            ),
        )]


SECURITY_POLICIES: list[BasePolicy] = [
    SEC001(),
    SEC002(),
    SEC003(),
    SEC004(),
    SEC005(),
    SEC006(),
    SEC007(),
    SEC008(),
    SEC009(),
    SEC010(),
    SEC011(),
]
