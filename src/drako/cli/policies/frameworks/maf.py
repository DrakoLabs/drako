"""MAF (Microsoft Agent Framework) governance rules (F-1, Sprint 2).

Verified against agent_framework 1.0 GA: Agent(client, instructions,
tools=[...], middleware=[...]); per-run middleware via
Agent.run(messages, middleware=[...]).
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


def _uses_governance(tree: ast.AST) -> bool:
    """Drako MAF wrapper or native middleware present anywhere."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in (
            "with_maf_compliance", "drako_maf_middleware",
            "agent_middleware", "function_middleware", "chat_middleware",
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# FW-MAF-001: Agent with tools but no middleware/governance
# ---------------------------------------------------------------------------

class FW_MAF_001(FrameworkPolicy):
    policy_id = "FW-MAF-001"
    required_framework = "maf"
    severity = "HIGH"
    title = "MAF Agent with tools but no middleware"
    impact = (
        "Every tool call runs with no interception point: no policy check, "
        "no audit record. A compromised instruction set executes tools "
        "silently."
    )
    attack_scenario = (
        "Attacker prompt-injects the agent into calling an exfiltration "
        "tool. With no FunctionMiddleware in the chain, nothing observes "
        "or stops the call."
    )
    references = [
        "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/middleware/",
    ]
    remediation_effort = "moderate"

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
            if _uses_governance(tree):
                continue
            lines = content.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if _call_name(node) != "Agent":
                    continue
                keywords = {kw.arg: kw.value for kw in node.keywords}
                if "tools" not in keywords:
                    continue
                # middleware=[] is theater, not governance: an empty chain
                # intercepts nothing. Safe iff the chain is non-empty (or a
                # Drako wrapper/native decorator is used, checked above).
                mw = keywords.get("middleware")
                if isinstance(mw, ast.List) and not mw.elts:
                    has_middleware = False
                else:
                    has_middleware = "middleware" in keywords
                if has_middleware:
                    continue
                line_content = (
                    lines[node.lineno - 1].strip()
                    if node.lineno <= len(lines) else ""
                )
                findings.append(self._finding(
                    "MAF Agent declares tools with no middleware — tool "
                    "calls run unobserved and unstopped.",
                    file_path=rel_path,
                    line_number=node.lineno,
                    code_snippet=line_content,
                    fix_snippet=(
                        "from drako.middleware.maf import with_maf_compliance\n\n"
                        "agent = with_maf_compliance(agent)\n"
                        "# or native: Agent(..., tools=[...], middleware=[...])"
                    ),
                ))
        return findings


MAF_POLICIES = [FW_MAF_001()]

__all__ = ["MAF_POLICIES", "FW_MAF_001"]
