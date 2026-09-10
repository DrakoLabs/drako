"""Base policy class and Finding dataclass for the scan policy engine."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


@dataclass
class Finding:
    """A single finding from a policy evaluation."""
    policy_id: str            # e.g. "SEC-001"
    category: str             # "Security", "Governance", "Compliance", "Best Practices"
    severity: str             # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    title: str                # Short title
    message: str              # Detailed description
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None   # The problematic code
    fix_snippet: str | None = None    # How to fix it
    impact: str | None = None
    attack_scenario: str | None = None
    references: list[str] = field(default_factory=list)
    remediation_effort: str | None = None  # "trivial" | "moderate" | "significant"
    finding_type: str = "vulnerability"    # "vulnerability" | "recommendation"


class BasePolicy(ABC):
    """Abstract base class for all scan policy rules."""

    policy_id: str = ""
    category: str = ""
    severity: str = ""
    title: str = ""
    impact: str = ""
    attack_scenario: str = ""
    references: list[str] = []
    remediation_effort: str = "moderate"  # "trivial" | "moderate" | "significant"
    finding_type: str = "vulnerability"   # "vulnerability" | "recommendation"

    def _finding(self, message: str, **kwargs: object) -> Finding:
        """Create a Finding pre-filled with this policy's metadata."""
        return Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            impact=self.impact,
            attack_scenario=self.attack_scenario,
            references=list(self.references),
            remediation_effort=self.remediation_effort,
            finding_type=self.finding_type,
            message=message,
            **kwargs,
        )

    @abstractmethod
    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        """Evaluate this policy against the project. Return list of findings."""
        ...


def find_function_node(
    content: str, func_name: str
) -> Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]]:
    """Locate a FunctionDef/AsyncFunctionDef by name via AST (P1-4, 2026-09-04).

    Single canonical implementation for all policies. The old per-rule regex
    (`def NAME(...).*?(?=\\ndef)`) broke on decorators, `async def`, methods,
    and nested functions — silently analyzing the wrong slice (or nothing).
    Returns None when the name is not a defined function (callers treat as
    "no evidence", never as clean).
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return node
    return None


def function_body_text(content: str, func_name: str) -> Optional[str]:
    """Exact source of the named function body (None if not found)."""
    node = find_function_node(content, func_name)
    if node is None:
        return None
    try:
        return ast.get_source_segment(content, node)
    except Exception:
        return None
