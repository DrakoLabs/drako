"""AutoGen framework-specific governance rules (FW-AUTOGEN-001, FW-AUTOGEN-002)."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from drako.cli.policies.frameworks.base import FrameworkPolicy

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata
    from drako.cli.policies.base import Finding


def _get_call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _file_has_docker_executor(tree: ast.AST) -> bool:
    """Check AST for DockerCommandLineCodeExecutor usage."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "DockerCommandLineCodeExecutor":
                    return True
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name == "DockerCommandLineCodeExecutor":
                return True
    return False


_VALIDATION_PATTERNS = frozenset({
    "register_reply", "reply_func", "output_validator",
    "is_termination_msg", "content_filter",
    "message_validator", "validate_output",
})


def _file_has_validation(tree: ast.AST) -> bool:
    """Check AST for output validation patterns."""
    for node in ast.walk(tree):
        # method calls: agent.register_reply(...)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _VALIDATION_PATTERNS
        ):
            return True
        # keyword arguments: is_termination_msg=...
        if isinstance(node, ast.keyword) and node.arg in _VALIDATION_PATTERNS:
            return True
    return False


# ---------------------------------------------------------------------------
# FW-AUTOGEN-001: Code execution default configuration
# ---------------------------------------------------------------------------

class FW_AUTOGEN_001(FrameworkPolicy):
    policy_id = "FW-AUTOGEN-001"
    required_framework = "autogen"
    severity = "CRITICAL"
    title = "Code execution with LocalCommandLineCodeExecutor"
    impact = (
        "LocalCommandLineCodeExecutor runs LLM-generated code with the same "
        "permissions as the parent process. Code influenced by injected "
        "instructions in tool results executes with full system access."
    )
    attack_scenario = (
        "A multi-agent chat processes user-provided data containing hidden "
        "instructions. The assistant agent generates code that follows those "
        "instructions. LocalCommandLineCodeExecutor runs it with full "
        "filesystem and network access, exfiltrating secrets."
    )
    references = [
        "https://microsoft.github.io/autogen/docs/tutorial/code-executors",
        "https://cwe.mitre.org/data/definitions/94.html",
    ]
    remediation_effort = "moderate"

    def _evaluate_framework(
        self, bom: AgentBOM, metadata: ProjectMetadata
    ) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            # Check if file uses DockerCommandLineCodeExecutor via AST
            has_docker_executor = _file_has_docker_executor(tree)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _get_call_name(node)

                # Direct LocalCommandLineCodeExecutor usage
                if call_name == "LocalCommandLineCodeExecutor" and not has_docker_executor:
                    line_content = (
                        lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else ""
                    )
                    findings.append(self._finding(
                        "AutoGen LocalCommandLineCodeExecutor used without "
                        "Docker isolation. LLM-generated code runs with full "
                        "system privileges.",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content,
                        fix_snippet=(
                            "from autogen.coding import DockerCommandLineCodeExecutor\n\n"
                            "executor = DockerCommandLineCodeExecutor(\n"
                            '    image="python:3.12-slim",\n'
                            '    work_dir="./output",\n'
                            "    timeout=60,\n"
                            ")"
                        ),
                    ))

                # Legacy code_execution_config with work_dir (pre-0.2 API)
                if call_name in (
                    "AssistantAgent", "UserProxyAgent",
                    "ConversableAgent", "GroupChatManager",
                ):
                    for kw in node.keywords:
                        if kw.arg != "code_execution_config":
                            continue
                        if not isinstance(kw.value, ast.Dict):
                            continue
                        # Check for work_dir key without docker
                        has_work_dir = False
                        has_docker = False
                        for key in kw.value.keys:
                            if isinstance(key, ast.Constant):
                                if key.value == "work_dir":
                                    has_work_dir = True
                                if key.value in ("use_docker", "docker"):
                                    has_docker = True
                        # Also check for executor key
                        for key, val in zip(kw.value.keys, kw.value.values, strict=False):
                            if isinstance(key, ast.Constant) and key.value == "executor":
                                exec_name = _get_call_name(val) if isinstance(val, ast.Call) else None
                                if exec_name == "DockerCommandLineCodeExecutor":
                                    has_docker = True

                        if has_work_dir and not has_docker and not _file_has_docker_executor(tree):
                            line_content = (
                                lines[node.lineno - 1].strip()
                                if node.lineno <= len(lines)
                                else ""
                            )
                            findings.append(self._finding(
                                "AutoGen agent with code_execution_config "
                                "using local execution without Docker.",
                                file_path=rel_path,
                                line_number=node.lineno,
                                code_snippet=line_content,
                                fix_snippet=(
                                    "agent = ConversableAgent(\n"
                                    '    name="coder",\n'
                                    "    code_execution_config={\n"
                                    '        "executor": DockerCommandLineCodeExecutor(\n'
                                    '            image="python:3.12-slim"\n'
                                    "        ),\n"
                                    "    },\n"
                                    ")"
                                ),
                            ))

        return findings


# ---------------------------------------------------------------------------
# FW-AUTOGEN-002: No output validation on agent responses
# ---------------------------------------------------------------------------

class FW_AUTOGEN_002(FrameworkPolicy):
    policy_id = "FW-AUTOGEN-002"
    required_framework = "autogen"
    severity = "HIGH"
    title = "No output validation on agent responses"
    impact = (
        "Agent responses in multi-agent AutoGen setups are passed as prompts "
        "to other agents. Without output validation, a compromised agent can "
        "inject instructions that hijack downstream agents."
    )
    attack_scenario = (
        "In a GroupChat, agent_A processes untrusted data and produces output "
        "containing hidden instructions. Agent_B receives this output as "
        "context and follows the injected instructions, bypassing its own "
        "system prompt restrictions."
    )
    references = [
        "https://microsoft.github.io/autogen/docs/tutorial/conversation-patterns",
        "https://cwe.mitre.org/data/definitions/20.html",
    ]
    remediation_effort = "significant"

    def _evaluate_framework(
        self, bom: AgentBOM, metadata: ProjectMetadata
    ) -> list[Finding]:
        findings: list[Finding] = []

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            lines = content.splitlines()

            # Check if file has validation patterns via AST
            has_validation = _file_has_validation(tree)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _get_call_name(node)

                if call_name == "GroupChat" and not has_validation:
                    # Count agents in the group chat
                    agents_kw = None
                    for kw in node.keywords:
                        if kw.arg == "agents":
                            agents_kw = kw.value
                    # Also check positional arg
                    if agents_kw is None and node.args:
                        agents_kw = node.args[0]

                    agent_count = 0
                    if isinstance(agents_kw, (ast.List, ast.Tuple)):
                        agent_count = len(agents_kw.elts)

                    if agent_count >= 2:
                        line_content = (
                            lines[node.lineno - 1].strip()
                            if node.lineno <= len(lines)
                            else ""
                        )
                        findings.append(self._finding(
                            "AutoGen GroupChat with multiple agents but no "
                            "output validation hooks (register_reply, "
                            "is_termination_msg).",
                            file_path=rel_path,
                            line_number=node.lineno,
                            code_snippet=line_content,
                            fix_snippet=(
                                "# Add output validation to agents\n"
                                "def validate_output(recipient, messages, sender, config):\n"
                                '    """Validate agent output before passing to group."""\n'
                                "    last = messages[-1].get('content', '')\n"
                                "    if contains_injection(last):\n"
                                "        return True, 'BLOCKED: suspicious output'\n"
                                "    return False, None\n\n"
                                "agent.register_reply([Agent], validate_output)"
                            ),
                        ))

        return findings


AUTOGEN_POLICIES = [FW_AUTOGEN_001(), FW_AUTOGEN_002()]
