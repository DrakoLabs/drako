"""Agent BOM (Bill of Materials) generation via Python AST analysis.

Extracts agents, tools, models, prompts, MCP servers, and permissions
from project source code — all offline, no network calls.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.discovery import FrameworkInfo, ProjectMetadata

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DetectedAgent:
    name: str
    class_name: str | None = None
    file_path: str = ""
    line_number: int = 0
    framework: str = "unknown"
    tools: list[str] = field(default_factory=list)
    model: str | None = None
    system_prompt: str | None = None


@dataclass
class DetectedTool:
    name: str
    file_path: str = ""
    line_number: int = 0
    has_filesystem_access: bool = False
    has_network_access: bool = False
    has_code_execution: bool = False


@dataclass
class DetectedModel:
    name: str
    file_path: str = ""
    line_number: int = 0


@dataclass
class DetectedPrompt:
    content_preview: str
    file_path: str = ""
    line_number: int = 0


@dataclass
class AgentBOM:
    agents: list[DetectedAgent] = field(default_factory=list)
    tools: list[DetectedTool] = field(default_factory=list)
    models: list[DetectedModel] = field(default_factory=list)
    mcp_servers: list[str] = field(default_factory=list)
    prompts: list[DetectedPrompt] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    frameworks: list[FrameworkInfo] = field(default_factory=list)
    dependencies: dict[str, str | None] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Model name patterns
# ---------------------------------------------------------------------------

_MODEL_PATTERN = re.compile(
    r"\b("
    r"gpt-4[a-z0-9-]*"
    r"|gpt-3\.5[a-z0-9-]*"
    r"|gpt-4o[a-z0-9-]*"
    r"|o1[a-z0-9-]*"
    r"|o3[a-z0-9-]*"
    r"|claude-[a-z0-9.-]+"
    r"|claude-opus[a-z0-9.-]*"
    r"|claude-sonnet[a-z0-9.-]*"
    r"|claude-haiku[a-z0-9.-]*"
    r"|gemini-[a-z0-9.-]+"
    r"|gemini-pro[a-z0-9-]*"
    r"|gemini-flash[a-z0-9-]*"
    r"|llama-[a-z0-9.-]+"
    r"|llama[23][a-z0-9.-]*"
    r"|mistral[a-z0-9.-]*"
    r"|mixtral[a-z0-9.-]*"
    r"|command-r[a-z0-9+-]*"
    r"|deepseek[a-z0-9.-]*"
    r")\b",
    re.IGNORECASE,
)

# Agent base classes / constructors per framework
_AGENT_BASE_CLASSES = {
    "Agent", "CrewAgent", "AssistantAgent", "UserProxyAgent",
    "GroupChatManager", "ConversableAgent",
}

_AGENT_CONSTRUCTORS = {
    "Agent", "AssistantAgent", "UserProxyAgent", "GroupChatManager",
    "ConversableAgent", "ChatAgent",
}

# Dangerous calls for permission detection
_FILESYSTEM_CALLS = {"open", "Path", "pathlib"}
_FILESYSTEM_ATTRS = {"read_text", "write_text", "read_bytes", "write_bytes", "open", "unlink", "rmdir", "mkdir"}
_NETWORK_MODULES = {"requests", "httpx", "urllib", "aiohttp", "urllib3"}
_CODE_EXEC_CALLS = {"exec", "eval", "compile"}
_CODE_EXEC_MODULES = {"subprocess", "os"}
_CODE_EXEC_ATTRS = {"system", "popen", "run", "call", "check_output", "Popen"}


# ---------------------------------------------------------------------------
# AST extraction helpers
# ---------------------------------------------------------------------------

def _get_string_value(node: ast.expr) -> str | None:
    """Extract string value from an AST node if it's a simple string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _get_name(node: ast.expr) -> str | None:
    """Get the name from a Name or Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _get_keyword_str(call: ast.Call, keyword: str) -> str | None:
    """Extract a string keyword argument from an ast.Call."""
    for kw in call.keywords:
        if kw.arg == keyword:
            return _get_string_value(kw.value)
    return None


def _get_keyword_list(call: ast.Call, keyword: str) -> list[str]:
    """Extract a list-of-strings keyword argument from an ast.Call."""
    for kw in call.keywords:
        if kw.arg == keyword and isinstance(kw.value, (ast.List, ast.Tuple)):
            result = []
            for elt in kw.value.elts:
                s = _get_string_value(elt)
                if s:
                    result.append(s)
                elif isinstance(elt, ast.Name):
                    result.append(elt.id)
            return result
    return []


# ---------------------------------------------------------------------------
# Agent extraction
# ---------------------------------------------------------------------------

def _extract_agents_ast(file_path: str, content: str) -> list[DetectedAgent]:
    """Extract agent definitions from a Python file using AST."""
    agents: list[DetectedAgent] = []

    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return agents

    # 1. Find classes that inherit from agent base classes
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = _get_name(base)
                if base_name in _AGENT_BASE_CLASSES:
                    agents.append(DetectedAgent(
                        name=node.name,
                        class_name=node.name,
                        file_path=file_path,
                        line_number=node.lineno,
                        framework=_infer_framework_from_base(base_name),
                    ))
                    break

        # 2. Find Agent() constructor calls (variable = Agent(...))
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(node.value, ast.Call):
                call = node.value
                func_name = _get_name(call.func)
                if func_name in _AGENT_CONSTRUCTORS:
                    var_name = _get_name(target)
                    agent_name = (
                        _get_keyword_str(call, "name")
                        or _get_keyword_str(call, "role")
                        or var_name
                        or func_name
                    )
                    model = _get_keyword_str(call, "model") or _get_keyword_str(call, "llm")
                    tools = _get_keyword_list(call, "tools")
                    system_prompt = _get_keyword_str(call, "system_prompt") or _get_keyword_str(call, "instructions")

                    agents.append(DetectedAgent(
                        name=agent_name,
                        class_name=func_name,
                        file_path=file_path,
                        line_number=node.lineno,
                        framework=_infer_framework_from_base(func_name),
                        tools=tools,
                        model=model,
                        system_prompt=system_prompt[:200] if system_prompt else None,
                    ))

    return agents


def _infer_framework_from_base(base_name: str) -> str:
    """Infer framework from agent base class name."""
    if base_name in ("AssistantAgent", "UserProxyAgent", "GroupChatManager", "ConversableAgent"):
        return "autogen"
    if base_name in ("Agent", "CrewAgent"):
        return "crewai"
    return "unknown"


# ---------------------------------------------------------------------------
# Tool extraction
# ---------------------------------------------------------------------------

def _extract_tools_ast(file_path: str, content: str) -> list[DetectedTool]:
    """Extract tool definitions from a Python file using AST."""
    tools: list[DetectedTool] = []

    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return tools

    for node in ast.walk(tree):
        # @tool decorator on function
        if isinstance(node, ast.FunctionDef):
            is_tool = False
            for dec in node.decorator_list:
                dec_name = _get_name(dec)
                if dec_name == "tool":
                    is_tool = True
                    break
                # Also handle @tool(...) call
                if isinstance(dec, ast.Call):
                    dec_name = _get_name(dec.func)
                    if dec_name == "tool":
                        is_tool = True
                        break

            if is_tool:
                tool = DetectedTool(
                    name=node.name,
                    file_path=file_path,
                    line_number=node.lineno,
                )
                _analyze_function_body(node, tool)
                tools.append(tool)

        # Tool() constructor call
        if isinstance(node, ast.Call):
            func_name = _get_name(node.func)
            if func_name == "Tool":
                name = _get_keyword_str(node, "name") or "unnamed_tool"
                tools.append(DetectedTool(
                    name=name,
                    file_path=file_path,
                    line_number=node.lineno,
                ))

    return tools


def _analyze_function_body(func_node: ast.FunctionDef, tool: DetectedTool) -> None:
    """Analyze a function body for filesystem, network, and code execution access."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            func_name = _get_name(node.func)

            # Filesystem access
            if func_name in _FILESYSTEM_CALLS:
                tool.has_filesystem_access = True
            if isinstance(node.func, ast.Attribute) and node.func.attr in _FILESYSTEM_ATTRS:
                tool.has_filesystem_access = True

            # Network access
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id in _NETWORK_MODULES:
                    tool.has_network_access = True
            if func_name in _NETWORK_MODULES:
                tool.has_network_access = True

            # Code execution
            if func_name in _CODE_EXEC_CALLS:
                tool.has_code_execution = True
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in _CODE_EXEC_ATTRS:
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in _CODE_EXEC_MODULES:
                        tool.has_code_execution = True

        # Import inside function body
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = None
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split(".")[0]
            elif node.module:
                module = node.module.split(".")[0]

            if module in _NETWORK_MODULES:
                tool.has_network_access = True
            if module in _CODE_EXEC_MODULES:
                tool.has_code_execution = True


# ---------------------------------------------------------------------------
# Model extraction
# ---------------------------------------------------------------------------

def _extract_models_ast(file_path: str, content: str) -> list[DetectedModel]:
    """Extract AI model references from a Python file."""
    models: list[DetectedModel] = []
    seen: set[str] = set()

    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return models

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            m = _MODEL_PATTERN.search(node.value)
            if m:
                model_name = m.group(1)
                if model_name.lower() not in seen:
                    seen.add(model_name.lower())
                    models.append(DetectedModel(
                        name=model_name,
                        file_path=file_path,
                        line_number=node.lineno,
                    ))

    return models


# ---------------------------------------------------------------------------
# Prompt extraction
# ---------------------------------------------------------------------------

_PROMPT_KEYWORDS = {"system_prompt", "system_message", "instructions", "prompt", "system"}

def _extract_prompts_ast(file_path: str, content: str) -> list[DetectedPrompt]:
    """Extract system prompts and prompt templates from a Python file."""
    prompts: list[DetectedPrompt] = []

    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return prompts

    for node in ast.walk(tree):
        # Keyword arguments: system_prompt="...", instructions="..."
        if isinstance(node, ast.keyword) and node.arg in _PROMPT_KEYWORDS:
            val = _get_string_value(node.value)
            if val and len(val) > 20:
                prompts.append(DetectedPrompt(
                    content_preview=val[:100],
                    file_path=file_path,
                    line_number=node.value.lineno if hasattr(node.value, "lineno") else 0,
                ))

        # Variable assignments: SYSTEM_PROMPT = "..."
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = _get_name(target)
                if name and any(kw in name.lower() for kw in ("prompt", "system_message", "instruction")):
                    val = _get_string_value(node.value)
                    if val and len(val) > 20:
                        prompts.append(DetectedPrompt(
                            content_preview=val[:100],
                            file_path=file_path,
                            line_number=node.lineno,
                        ))

        # SystemMessage("...") constructor
        if isinstance(node, ast.Call):
            func_name = _get_name(node.func)
            if func_name == "SystemMessage" and node.args:
                val = _get_string_value(node.args[0])
                if val and len(val) > 10:
                    prompts.append(DetectedPrompt(
                        content_preview=val[:100],
                        file_path=file_path,
                        line_number=node.lineno,
                    ))

    return prompts


# ---------------------------------------------------------------------------
# MCP server detection
# ---------------------------------------------------------------------------

def _detect_mcp_servers(metadata: ProjectMetadata) -> list[str]:
    """Detect MCP server configurations."""
    servers: list[str] = []

    # Check mcp.json config
    if "mcp.json" in metadata.config_files:
        content = metadata.config_files["mcp.json"]
        # Extract server names from mcp.json
        for m in re.finditer(r'"(\w+)":\s*\{[^}]*"command"', content):
            servers.append(m.group(1))

    # Scan code for mcp:// URIs
    for content in metadata.file_contents.values():
        for m in re.finditer(r"mcp://([^\s'\"]+)", content):
            uri = m.group(1)
            if uri not in servers:
                servers.append(uri)

    return servers


# ---------------------------------------------------------------------------
# Permission detection
# ---------------------------------------------------------------------------

def _detect_permissions(tools: list[DetectedTool], file_contents: dict[str, str]) -> list[str]:
    """Determine what permissions the project's agents/tools require."""
    perms: set[str] = set()

    for tool in tools:
        if tool.has_filesystem_access:
            perms.add("filesystem")
        if tool.has_network_access:
            perms.add("network")
        if tool.has_code_execution:
            perms.add("code_execution")

    # Also scan all code for database access
    all_content = "\n".join(c for p, c in file_contents.items() if p.endswith(".py"))
    db_patterns = ["sqlite", "postgresql", "mysql", "sqlalchemy", "pymongo", "redis"]
    if any(p in all_content.lower() for p in db_patterns):
        perms.add("database")

    return sorted(perms)


# ---------------------------------------------------------------------------
# Main BOM generation
# ---------------------------------------------------------------------------

def generate_bom(metadata: ProjectMetadata) -> AgentBOM:
    """Generate a complete Agent Bill of Materials from project metadata."""
    all_agents: list[DetectedAgent] = []
    all_tools: list[DetectedTool] = []
    all_models: list[DetectedModel] = []
    all_prompts: list[DetectedPrompt] = []

    seen_agents: set[str] = set()
    seen_tools: set[str] = set()
    seen_models: set[str] = set()

    for rel_path, content in metadata.file_contents.items():
        if not rel_path.endswith(".py"):
            continue

        # Agents
        for agent in _extract_agents_ast(rel_path, content):
            key = f"{agent.name}:{agent.file_path}"
            if key not in seen_agents:
                seen_agents.add(key)
                all_agents.append(agent)

        # Tools
        for tool in _extract_tools_ast(rel_path, content):
            if tool.name not in seen_tools:
                seen_tools.add(tool.name)
                all_tools.append(tool)

        # Models
        for model in _extract_models_ast(rel_path, content):
            if model.name.lower() not in seen_models:
                seen_models.add(model.name.lower())
                all_models.append(model)

        # Prompts
        all_prompts.extend(_extract_prompts_ast(rel_path, content))

    # MCP servers
    mcp_servers = _detect_mcp_servers(metadata)

    # Permissions
    permissions = _detect_permissions(all_tools, metadata.file_contents)

    return AgentBOM(
        agents=all_agents,
        tools=all_tools,
        models=all_models,
        mcp_servers=mcp_servers,
        prompts=all_prompts,
        permissions=permissions,
        frameworks=metadata.frameworks,
        dependencies=metadata.dependencies,
    )
