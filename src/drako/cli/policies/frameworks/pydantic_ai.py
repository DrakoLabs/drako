"""PydanticAI framework-specific governance rules (FW-PYDANTIC-001)."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from drako.cli.policies.frameworks.base import FrameworkPolicy

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata
    from drako.cli.policies.base import Finding


_UNVALIDATED_RETURN_TYPES = frozenset({
    "Any", "dict", "str", "list", "tuple", "object", "None",
})


def _get_call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _get_return_type_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Get the return type annotation name from a function definition."""
    ret = node.returns
    if ret is None:
        return None  # no annotation
    if isinstance(ret, ast.Constant) and ret.value is None:
        return "None"
    if isinstance(ret, ast.Name):
        return ret.id
    if isinstance(ret, ast.Attribute):
        return ret.attr
    if isinstance(ret, ast.Subscript) and isinstance(ret.value, ast.Name):
        # e.g. Optional[str], dict[str, Any]
        return ret.value.id
    return None


# ---------------------------------------------------------------------------
# FW-PYDANTIC-001: Tool return type not validated
# ---------------------------------------------------------------------------

class FW_PYDANTIC_001(FrameworkPolicy):
    policy_id = "FW-PYDANTIC-001"
    required_framework = "pydantic_ai"
    severity = "MEDIUM"
    title = "Tool return type not validated"
    impact = (
        "PydanticAI promises type-safe agent outputs, but unvalidated tool "
        "return types create a safety gap where malformed or injected data "
        "can flow through the agent pipeline unchecked."
    )
    attack_scenario = (
        "A tool returns a plain dict that includes extra fields injected "
        "by an external source. Without Pydantic model validation on the "
        "return type, the injected fields are passed through to the agent "
        "and may influence its reasoning."
    )
    references = [
        "https://ai.pydantic.dev/tools/",
        "https://cwe.mitre.org/data/definitions/20.html",
    ]
    remediation_effort = "trivial"

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

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                # Check if function has @agent.tool or @<name>.tool decorator
                is_agent_tool = False
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Attribute) and dec.attr == "tool":
                        is_agent_tool = True
                        break
                    if (
                        isinstance(dec, ast.Call)
                        and isinstance(dec.func, ast.Attribute)
                        and dec.func.attr == "tool"
                    ):
                        is_agent_tool = True
                        break

                if not is_agent_tool:
                    continue

                # Check return type
                ret_name = _get_return_type_name(node)

                # No annotation or unvalidated type
                if ret_name is None or ret_name in _UNVALIDATED_RETURN_TYPES:
                    line_content = (
                        lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else ""
                    )
                    type_msg = (
                        f"returns unvalidated type '{ret_name}'"
                        if ret_name
                        else "has no return type annotation"
                    )
                    findings.append(self._finding(
                        f"PydanticAI tool function '{node.name}' {type_msg}. "
                        "Use a Pydantic model for type-safe tool outputs.",
                        file_path=rel_path,
                        line_number=node.lineno,
                        code_snippet=line_content,
                        fix_snippet=(
                            "from pydantic import BaseModel\n\n"
                            "class ToolResult(BaseModel):\n"
                            "    data: str\n"
                            "    source: str\n\n"
                            "@agent.tool\n"
                            f"async def {node.name}(...) -> ToolResult:\n"
                            "    return ToolResult(data=..., source=...)"
                        ),
                    ))

        return findings


PYDANTIC_AI_POLICIES = [FW_PYDANTIC_001()]
