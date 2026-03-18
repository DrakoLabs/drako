"""Auto-fix engine for ``drako fix``.

Generates proposed code fixes for scan findings.  **Dry-run only** --
this module never writes to files.
"""

from __future__ import annotations

import ast
import difflib
import re
import textwrap
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.policies.base import Finding
    from drako.cli.scanner import ScanResult


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AutoFix:
    """A single proposed fix."""
    finding: Finding
    file_path: str
    original_lines: list[str]
    replacement_lines: list[str]
    start_line: int                # 1-based
    end_line: int                  # 1-based, inclusive
    imports_needed: list[str] = field(default_factory=list)
    description: str = ""
    new_file: bool = False         # True if this creates a brand-new file


# ---------------------------------------------------------------------------
# AutoFixer
# ---------------------------------------------------------------------------

class AutoFixer:
    """Generate read-only fix proposals for scan findings."""

    _SUPPORTED = frozenset({"SEC-001", "SEC-006", "COM-005", "CI-001"})

    def __init__(self, result: ScanResult) -> None:
        self._result = result
        self._file_cache: dict[str, list[str]] = {}

    # -- public API --

    def can_fix(self, finding: Finding) -> bool:
        return finding.policy_id in self._SUPPORTED

    def generate_fix(self, finding: Finding) -> AutoFix | None:
        handler = {
            "SEC-001": self._fix_sec001,
            "SEC-006": self._fix_sec006,
            "COM-005": self._fix_com005,
            "CI-001": self._fix_ci001,
        }.get(finding.policy_id)
        if handler is None:
            return None
        try:
            return handler(finding)
        except Exception:
            return None

    def generate_all_fixes(self, policy_filter: str | None = None) -> list[AutoFix]:
        fixes: list[AutoFix] = []
        seen: set[tuple[str, int | None]] = set()
        for finding in self._result.findings:
            if policy_filter and finding.policy_id != policy_filter.upper():
                continue
            if not self.can_fix(finding):
                continue
            # Deduplicate by (file, line)
            key = (finding.file_path or "", finding.line_number)
            if key in seen:
                continue
            seen.add(key)
            fix = self.generate_fix(finding)
            if fix is not None:
                fixes.append(fix)
        return fixes

    # -- helpers --

    def _get_lines(self, rel_path: str) -> list[str]:
        if rel_path not in self._file_cache:
            content = self._result.metadata.file_contents.get(rel_path, "")
            self._file_cache[rel_path] = content.splitlines(keepends=True)
        return self._file_cache[rel_path]

    # -- SEC-001: hardcoded key -> os.environ --

    def _fix_sec001(self, finding: Finding) -> AutoFix | None:
        if not finding.file_path or not finding.line_number:
            return None
        lines = self._get_lines(finding.file_path)
        if not lines or finding.line_number > len(lines):
            return None

        idx = finding.line_number - 1
        original = lines[idx]

        # Extract variable name from the finding message
        var_match = re.search(r'variable "(\w+)"', finding.message)
        var_name = var_match.group(1) if var_match else None

        if not var_name:
            # Try to parse it from the original line
            line_match = re.match(r'\s*(\w+)\s*=', original)
            var_name = line_match.group(1) if line_match else "API_KEY"

        env_var = var_name.upper()
        indent = len(original) - len(original.lstrip())
        indent_str = " " * indent
        replacement = f'{indent_str}{var_name} = os.environ["{env_var}"]\n'

        return AutoFix(
            finding=finding,
            file_path=finding.file_path,
            original_lines=[original],
            replacement_lines=[replacement],
            start_line=finding.line_number,
            end_line=finding.line_number,
            imports_needed=["import os"],
            description=f'Replace hardcoded secret with os.environ["{env_var}"]',
        )

    # -- SEC-006: add type hints to tool function --

    def _fix_sec006(self, finding: Finding) -> AutoFix | None:
        if not finding.file_path or not finding.line_number:
            return None
        content = self._result.metadata.file_contents.get(finding.file_path, "")
        if not content:
            return None

        try:
            tree = ast.parse(content, filename=finding.file_path)
        except SyntaxError:
            return None

        lines = self._get_lines(finding.file_path)

        # Extract tool name from finding message
        tool_match = re.search(r'Tool "(\w+)"', finding.message)
        tool_name = tool_match.group(1) if tool_match else None
        if not tool_name:
            return None

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != tool_name:
                continue

            # Build new parameter list with type hints
            params: list[str] = []
            for arg in node.args.args:
                if arg.arg == "self":
                    params.append("self")
                    continue
                if arg.annotation is not None:
                    try:
                        ann = ast.unparse(arg.annotation)
                    except (AttributeError, ValueError):
                        ann = "str"
                    params.append(f"{arg.arg}: {ann}")
                else:
                    params.append(f"{arg.arg}: str")

            param_str = ", ".join(params)
            idx = node.lineno - 1
            if idx >= len(lines):
                return None

            original = lines[idx]
            indent = len(original) - len(original.lstrip())
            indent_str = " " * indent
            replacement = f"{indent_str}def {tool_name}({param_str}) -> str:\n"

            return AutoFix(
                finding=finding,
                file_path=finding.file_path,
                original_lines=[original],
                replacement_lines=[replacement],
                start_line=node.lineno,
                end_line=node.lineno,
                description=f"Add type annotations to {tool_name}()",
            )

        return None

    # -- COM-005: generate .drako.yaml --

    def _fix_com005(self, finding: Finding) -> AutoFix | None:
        bom = self._result.bom
        agent_list = "\n".join(f"    - {a.name}" for a in bom.agents) or "    - my_agent"
        tool_list = "\n".join(f"    - {t.name}" for t in bom.tools) or "    - my_tool"
        model_list = "\n".join(f"    - {m.name}" for m in bom.models) or "    - gpt-4"
        fw = bom.frameworks[0].name if bom.frameworks else "unknown"

        yaml_content = textwrap.dedent(f"""\
            # Drako Agent BOM — auto-generated
            # See: https://docs.useagentmesh.com/bom
            version: "1.0"
            framework: {fw}
            agents:
            {agent_list}
            tools:
            {tool_list}
            models:
            {model_list}
        """)

        return AutoFix(
            finding=finding,
            file_path=".drako.yaml",
            original_lines=[],
            replacement_lines=yaml_content.splitlines(keepends=True),
            start_line=1,
            end_line=1,
            description="Generate .drako.yaml with detected Agent BOM",
            new_file=True,
        )

    # -- CI-001: generate GitHub Actions workflow --

    def _fix_ci001(self, finding: Finding) -> AutoFix | None:
        workflow = textwrap.dedent("""\
            # Drako governance gate — auto-generated
            # Runs `drako scan` on every push and PR.
            name: Drako Governance
            on: [push, pull_request]
            jobs:
              scan:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-python@v5
                    with:
                      python-version: "3.12"
                  - run: pip install drako
                  - run: drako scan . --threshold 60
        """)

        return AutoFix(
            finding=finding,
            file_path=".github/workflows/drako.yml",
            original_lines=[],
            replacement_lines=workflow.splitlines(keepends=True),
            start_line=1,
            end_line=1,
            description="Generate GitHub Actions workflow for Drako governance gate",
            new_file=True,
        )


# ---------------------------------------------------------------------------
# Diff formatting
# ---------------------------------------------------------------------------

def format_unified_diff(fix: AutoFix) -> str:
    """Format an AutoFix as a unified diff string."""
    if fix.new_file:
        # Show as a new-file diff
        header = f"--- /dev/null\n+++ b/{fix.file_path}\n"
        body = "".join(f"+{line.rstrip()}\n" for line in fix.replacement_lines)
        return header + body

    a_lines = [line.rstrip("\n\r") for line in fix.original_lines]
    b_lines = [line.rstrip("\n\r") for line in fix.replacement_lines]

    diff = difflib.unified_diff(
        a_lines,
        b_lines,
        fromfile=f"a/{fix.file_path}",
        tofile=f"b/{fix.file_path}",
        lineterm="",
    )
    return "\n".join(diff)
