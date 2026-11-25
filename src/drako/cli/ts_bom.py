"""Agent BOM extraction for TypeScript / JavaScript projects.

Uses tree-sitter to detect agents, tools, models, prompts, and
permissions from TS/JS source code.  Reuses the same dataclasses
as ``drako.cli.bom``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from drako.ts_parser._compat import ts_available

if TYPE_CHECKING:
    from tree_sitter import Tree

    from drako.cli.bom import (
        AgentBOM,
        DetectedAgent,
        DetectedModel,
        DetectedPrompt,
        DetectedTool,
    )
    from drako.cli.discovery import ProjectMetadata
    from drako.ts_parser.parser import TSParser

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TS_EXTENSIONS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs", ".cts", ".cjs"})

_MODEL_PATTERN = re.compile(
    r"\b("
    r"gpt-4[a-z0-9-]*"
    r"|gpt-3\.5[a-z0-9-]*"
    r"|gpt-4o[a-z0-9-]*"
    r"|o1[a-z0-9-]*"
    r"|o3[a-z0-9-]*"
    r"|claude-[a-z0-9.-]+"
    r"|gemini-[a-z0-9.-]+"
    r"|llama[_-]?[0-9][a-z0-9.-]*"
    r"|mistral[a-z0-9.-]*"
    r"|command-r[a-z0-9.-]*"
    r"|deepseek[a-z0-9.-]*"
    r")\b",
    re.IGNORECASE,
)

_AGENT_CONSTRUCTOR_NAMES = frozenset({
    "Agent", "createAgent", "ChatAgent", "AssistantAgent",
    "ToolCallingAgent", "ReactAgent",
})

_TOOL_CONSTRUCTOR_NAMES = frozenset({
    "tool", "createTool", "defineTool", "DynamicTool",
    "DynamicStructuredTool",
})

_LLM_CLIENT_NAMES = frozenset({
    "OpenAI", "Anthropic", "GoogleGenerativeAI",
    "createOpenAI", "createAnthropic", "createGoogleGenerativeAI",
    "ChatOpenAI", "ChatAnthropic",
})

_PROMPT_KEYS = frozenset({
    "systemPrompt", "system_prompt", "system", "instructions",
    "systemMessage", "system_message",
})

_FS_FUNCTIONS = frozenset({
    "readFile", "readFileSync", "writeFile", "writeFileSync",
    "readdir", "readdirSync", "unlink", "unlinkSync",
    "mkdir", "mkdirSync", "rmdir", "rmdirSync",
    "rename", "renameSync", "copyFile", "copyFileSync",
    "appendFile", "appendFileSync",
})

_NET_FUNCTIONS = frozenset({"fetch", "get", "post", "put", "delete", "patch", "request"})

_EXEC_FUNCTIONS = frozenset({"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"})


def _is_ts_file(path: str) -> bool:
    return any(path.endswith(ext) for ext in _TS_EXTENSIONS)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_ts_bom(metadata: ProjectMetadata) -> AgentBOM:
    """Extract agent BOM from TypeScript/JavaScript files."""
    from drako.cli.bom import AgentBOM

    if not ts_available():
        return AgentBOM()

    from drako.ts_parser import get_parser

    parser = get_parser()

    all_agents: list[DetectedAgent] = []
    all_tools: list[DetectedTool] = []
    all_models: list[DetectedModel] = []
    all_prompts: list[DetectedPrompt] = []
    permissions: set[str] = set()

    for rel_path, content in metadata.file_contents.items():
        if not _is_ts_file(rel_path):
            continue
        try:
            tree = parser.parse(content, rel_path)
        except Exception:  # noqa: BLE001
            continue

        all_agents.extend(_extract_agents(rel_path, tree, parser))
        all_tools.extend(_extract_tools(rel_path, tree, parser))
        all_models.extend(_extract_models(rel_path, content, tree, parser))
        all_prompts.extend(_extract_prompts(rel_path, tree, parser))
        permissions.update(_detect_permissions(tree, parser))

    return AgentBOM(
        agents=all_agents,
        tools=all_tools,
        models=all_models,
        prompts=all_prompts,
        permissions=sorted(permissions),
        frameworks=list(metadata.frameworks),
        dependencies=dict(metadata.dependencies),
    )


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_agents(
    rel_path: str,
    tree: Tree,
    parser: TSParser,
) -> list[DetectedAgent]:
    from drako.cli.bom import DetectedAgent

    results: list[DetectedAgent] = []

    # new Agent(...) / createAgent(...)
    for call in parser.find_new_expressions(tree):
        if call.name in _AGENT_CONSTRUCTOR_NAMES:
            results.append(DetectedAgent(
                name=call.name,
                class_name=call.name,
                file_path=rel_path,
                line_number=call.line,
                framework="typescript",
            ))
    for call in parser.find_function_calls(tree):
        if call.name in _AGENT_CONSTRUCTOR_NAMES:
            results.append(DetectedAgent(
                name=call.name,
                class_name=call.name,
                file_path=rel_path,
                line_number=call.line,
                framework="typescript",
            ))

    # class X extends Agent
    for cls in parser.find_class_declarations(tree):
        for base in cls.bases:
            if base in _AGENT_CONSTRUCTOR_NAMES or "Agent" in base:
                results.append(DetectedAgent(
                    name=cls.name,
                    class_name=cls.name,
                    file_path=rel_path,
                    line_number=cls.line,
                    framework="typescript",
                ))
                break

    return results


def _extract_tools(
    rel_path: str,
    tree: Tree,
    parser: TSParser,
) -> list[DetectedTool]:
    from drako.cli.bom import DetectedTool

    results: list[DetectedTool] = []

    for call in parser.find_function_calls(tree):
        if call.name in _TOOL_CONSTRUCTOR_NAMES:
            results.append(DetectedTool(
                name=call.name,
                file_path=rel_path,
                line_number=call.line,
            ))

    for call in parser.find_new_expressions(tree):
        if call.name in _TOOL_CONSTRUCTOR_NAMES or "Tool" in call.name:
            results.append(DetectedTool(
                name=call.name,
                file_path=rel_path,
                line_number=call.line,
            ))

    return results


def _extract_models(
    rel_path: str,
    content: str,
    tree: Tree,
    parser: TSParser,
) -> list[DetectedModel]:
    from drako.cli.bom import DetectedModel

    results: list[DetectedModel] = []
    seen: set[str] = set()

    # new OpenAI(...) / createOpenAI(...)
    for call in parser.find_new_expressions(tree):
        if call.name in _LLM_CLIENT_NAMES and call.name not in seen:
            seen.add(call.name)
            results.append(DetectedModel(
                name=call.name,
                file_path=rel_path,
                line_number=call.line,
            ))
    for call in parser.find_function_calls(tree):
        if call.name in _LLM_CLIENT_NAMES and call.name not in seen:
            seen.add(call.name)
            results.append(DetectedModel(
                name=call.name,
                file_path=rel_path,
                line_number=call.line,
            ))

    # Model string patterns in source
    for i, line in enumerate(content.splitlines(), 1):
        for m in _MODEL_PATTERN.finditer(line):
            model_name = m.group(1)
            if model_name not in seen:
                seen.add(model_name)
                results.append(DetectedModel(
                    name=model_name,
                    file_path=rel_path,
                    line_number=i,
                ))

    return results


def _extract_prompts(
    rel_path: str,
    tree: Tree,
    parser: TSParser,
) -> list[DetectedPrompt]:
    from drako.cli.bom import DetectedPrompt

    results: list[DetectedPrompt] = []

    # Variable declarations with prompt-like names
    for var in parser.find_variable_declarations(tree):
        name_lower = var.name.lower()
        if any(key.lower() in name_lower for key in _PROMPT_KEYS):
            preview = var.init_text[:120].replace("\n", " ")
            results.append(DetectedPrompt(
                content_preview=preview,
                file_path=rel_path,
                line_number=var.line,
            ))

    # Object properties like { system: "...", systemPrompt: "..." }
    for node in parser.walk(tree.root_node):
        if node.type == "object":
            for prop in parser.find_object_properties(node):
                if prop.key in _PROMPT_KEYS:
                    preview = prop.value_text[:120].replace("\n", " ")
                    results.append(DetectedPrompt(
                        content_preview=preview,
                        file_path=rel_path,
                        line_number=prop.line,
                    ))

    return results


def _detect_permissions(tree: Tree, parser: TSParser) -> set[str]:
    perms: set[str] = set()

    for call in parser.find_function_calls(tree):
        if call.name in _FS_FUNCTIONS:
            perms.add("filesystem")
        if call.name in _NET_FUNCTIONS or "axios" in call.full_name:
            perms.add("network")
        if call.name in _EXEC_FUNCTIONS:
            perms.add("code_execution")

    for call in parser.find_new_expressions(tree):
        if call.name == "Function":
            perms.add("code_execution")

    # Check imports for modules implying permissions
    for imp in parser.find_imports(tree):
        if imp.module in ("fs", "node:fs", "fs/promises", "node:fs/promises"):
            perms.add("filesystem")
        if imp.module in ("child_process", "node:child_process"):
            perms.add("code_execution")
        if imp.module in ("http", "https", "node:http", "node:https", "node-fetch", "axios"):
            perms.add("network")
        if imp.module in ("pg", "mysql2", "mongodb", "mongoose", "knex", "prisma", "@prisma/client"):
            perms.add("database")

    return perms
