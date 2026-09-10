"""OpenAI Agents SDK governance rules (F-1, Sprint 2).

Verified against openai-agents-python: Agent(input_guardrails=[...],
output_guardrails=[...]); @input_guardrail / @output_guardrail build
GuardrailFunctionOutput tripwires.
"""

from __future__ import annotations

import ast

from drako.cli.policies.base import Finding
from drako.cli.policies.frameworks.base import FrameworkPolicy


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _has_drako_guardrail(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in (
            "make_drako_input_guardrail", "make_drako_output_guardrail",
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# FW-OPENAI-001: Agent without input guardrails
# ---------------------------------------------------------------------------

class FW_OPENAI_001(FrameworkPolicy):
    policy_id = "FW-OPENAI-001"
    required_framework = "openai_agents"
    severity = "MEDIUM"
    title = "OpenAI Agent without input guardrails"
    impact = (
        "No input tripwire stands between user input and the agent loop. "
        "Jailbreaks and injections reach the model unchecked."
    )
    attack_scenario = (
        "Attacker sends a jailbreak as the first message. With no input "
        "guardrail, nothing trips before the agent acts on it."
    )
    references = [
        "https://openai.github.io/openai-agents-python/guardrails/",
    ]
    remediation_effort = "trivial"

    def _evaluate_framework(
        self, bom, metadata
    ) -> list[Finding]:
        findings: list[Finding] = []
        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue
            if _has_drako_guardrail(tree):
                continue
            lines = content.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if _call_name(node) != "Agent":
                    continue
                keywords = {kw.arg for kw in node.keywords}
                if "input_guardrails" in keywords:
                    continue
                line_content = (
                    lines[node.lineno - 1].strip()
                    if node.lineno <= len(lines) else ""
                )
                findings.append(self._finding(
                    "OpenAI Agent without input_guardrails — no tripwire "
                    "between user input and the agent loop.",
                    file_path=rel_path,
                    line_number=node.lineno,
                    code_snippet=line_content,
                    fix_snippet=(
                        "from drako.middleware.openai_agents import "
                        "make_drako_input_guardrail\n\n"
                        "agent = Agent(name=..., instructions=...,\n"
                        "    input_guardrails=[make_drako_input_guardrail("
                        "my_check)])"
                    ),
                ))
        return findings


OPENAI_POLICIES = [FW_OPENAI_001()]

__all__ = ["OPENAI_POLICIES", "FW_OPENAI_001"]
