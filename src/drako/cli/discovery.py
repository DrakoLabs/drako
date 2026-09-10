"""Framework & dependency detection for `drako scan`.

Collects project files, parses dependency manifests, and detects
which AI agent frameworks are in use — all offline, no network calls.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FrameworkInfo:
    """Detected AI agent framework."""
    name: str                # "crewai", "langgraph", "autogen", "langchain", "llamaindex", "pydantic_ai", "semantic_kernel"
    version: str | None = None   # parsed from requirements/pyproject
    confidence: float = 0.0      # 0.0-1.0


@dataclass
class ProjectMetadata:
    """Collected project information used by all scan phases."""
    root: Path = field(default_factory=lambda: Path("."))
    python_files: list[Path] = field(default_factory=list)
    ts_files: list[Path] = field(default_factory=list)
    config_files: dict[str, str] = field(default_factory=dict)    # filename -> content
    file_contents: dict[str, str] = field(default_factory=dict)   # rel_path -> content
    dependencies: dict[str, str | None] = field(default_factory=dict)  # package -> version
    frameworks: list[FrameworkInfo] = field(default_factory=list)

    @property
    def source_files(self) -> dict[str, str]:
        """Alias for file_contents — used by policy evaluators."""
        return self.file_contents


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_FILES = 200
_MAX_FILE_SIZE = 100_000  # 100 KB
_SKIP_DIRS = frozenset({
    "venv", ".venv", "env", ".env", "node_modules", "__pycache__",
    ".git", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build",
    "egg-info", ".eggs", ".ruff_cache", ".hypothesis", "htmlcov",
    "site-packages", ".nox",
})

_CONFIG_FILES = (
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "poetry.lock", "Pipfile", "Pipfile.lock",
    "crewai.yaml", ".drako.yaml", "mcp.json",
)

# Framework package name -> canonical framework name
_FRAMEWORK_PACKAGES: dict[str, str] = {
    "crewai": "crewai",
    "langgraph": "langgraph",
    "autogen": "autogen",
    "pyautogen": "autogen",
    "ag2": "autogen",
    "autogen_agentchat": "autogen",
    "autogen_core": "autogen",
    "autogen_ext": "autogen",
    "langchain": "langchain",
    "langchain-core": "langchain",
    "langchain-community": "langchain",
    "llama-index": "llamaindex",
    "llama_index": "llamaindex",
    "llamaindex": "llamaindex",
    "pydantic-ai": "pydantic_ai",
    "pydantic_ai": "pydantic_ai",
    "semantic-kernel": "semantic_kernel",
    "semantic_kernel": "semantic_kernel",
    "agent-framework": "maf",
    "openai-agents": "openai_agents",
}

# Import module name -> canonical framework name
_FRAMEWORK_IMPORTS: dict[str, str] = {
    "crewai": "crewai",
    "langgraph": "langgraph",
    "autogen": "autogen",
    "pyautogen": "autogen",
    "autogen_agentchat": "autogen",
    "autogen_core": "autogen",
    "autogen_ext": "autogen",
    "ag2": "autogen",
    "langchain": "langchain",
    "langchain_core": "langchain",
    "langchain_community": "langchain",
    "llama_index": "llamaindex",
    "pydantic_ai": "pydantic_ai",
    "semantic_kernel": "semantic_kernel",
    "agent_framework": "maf",
    "agents": "openai_agents",
}

# Dependency files worth searching in parent directories
_DEP_FILES = ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg")


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def _should_skip(parts: tuple[str, ...]) -> bool:
    """Check if a path should be skipped based on directory names."""
    return any(p.startswith(".") or p in _SKIP_DIRS for p in parts)


def collect_project_files(directory: Path) -> ProjectMetadata:
    """Walk directory and collect Python files + config files.

    Returns a populated ProjectMetadata with file contents loaded.
    """
    root = directory.resolve()
    metadata = ProjectMetadata(root=root)
    count = 0

    # Collect Python files
    for py_file in sorted(root.rglob("*.py")):
        rel_parts = py_file.relative_to(root).parts
        if _should_skip(rel_parts):
            continue
        try:
            size = py_file.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_SIZE or size == 0:
            continue

        count += 1
        if count > _MAX_FILES:
            break

        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            rel_path = str(py_file.relative_to(root)).replace("\\", "/")
            metadata.python_files.append(py_file)
            metadata.file_contents[rel_path] = content
        except OSError:
            continue

    # Collect config files
    for cfg_name in _CONFIG_FILES:
        cfg_path = root / cfg_name
        if cfg_path.exists():
            try:
                size = cfg_path.stat().st_size
                if size < _MAX_FILE_SIZE:
                    content = cfg_path.read_text(encoding="utf-8", errors="ignore")
                    metadata.config_files[cfg_name] = content
                    metadata.file_contents[cfg_name] = content
            except OSError:
                continue

    # Extract Python code from Jupyter notebooks (.ipynb)
    for nb_file in sorted(root.rglob("*.ipynb")):
        rel_parts = nb_file.relative_to(root).parts
        if _should_skip(rel_parts):
            continue
        if count > _MAX_FILES:
            break
        try:
            import json as _json
            nb_size = nb_file.stat().st_size
            if nb_size > _MAX_FILE_SIZE * 5 or nb_size == 0:  # notebooks can be larger
                continue
            nb = _json.loads(nb_file.read_text(encoding="utf-8", errors="ignore"))
            code_cells = []
            for cell in nb.get("cells", []):
                if cell.get("cell_type") != "code":
                    continue
                lines = []
                for line in "".join(cell["source"]).split("\n"):
                    stripped = line.lstrip()
                    # Skip IPython magics (%, %%, !) that cause SyntaxError
                    if stripped.startswith(("%", "!")):
                        lines.append("")  # keep line count stable
                    else:
                        lines.append(line)
                code_cells.append("\n".join(lines))
            if code_cells:
                content = "\n\n".join(code_cells)
                rel_path = str(nb_file.relative_to(root)).replace("\\", "/") + ".py"
                metadata.file_contents[rel_path] = content
                count += 1
        except (OSError, KeyError, ValueError, _json.JSONDecodeError):
            continue

    # Also collect .yaml/.json agent config files (nested one level)
    for pattern in ("*.yaml", "*.yml", "*.json"):
        for f in sorted(root.glob(pattern)):
            name = f.name
            if name.startswith(".") or name in metadata.config_files:
                continue
            try:
                size = f.stat().st_size
                if 0 < size < _MAX_FILE_SIZE:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    metadata.config_files[name] = content
            except OSError:
                continue

    # Check config/ subdirectory for CrewAI agent/task YAML configs
    config_dir = root / "config"
    if config_dir.is_dir():
        for pattern in ("*.yaml", "*.yml"):
            for f in sorted(config_dir.glob(pattern)):
                name = f.name
                if name not in metadata.config_files:
                    try:
                        content = f.read_text(encoding="utf-8", errors="ignore")
                        metadata.config_files[name] = content
                    except OSError:
                        continue

    # Walk up to 3 parent directories for dependency files if none found locally
    has_dep_file = any(name in metadata.config_files for name in _DEP_FILES)
    if not has_dep_file:
        for parent in list(root.parents)[:3]:
            for cfg_name in _DEP_FILES:
                cfg_path = parent / cfg_name
                if cfg_path.exists():
                    try:
                        size = cfg_path.stat().st_size
                        if 0 < size < _MAX_FILE_SIZE:
                            content = cfg_path.read_text(encoding="utf-8", errors="ignore")
                            metadata.config_files[cfg_name] = content
                    except OSError:
                        continue
            if any(name in metadata.config_files for name in _DEP_FILES):
                break

    # Parse dependencies
    metadata.dependencies = _extract_dependencies(metadata.config_files)

    # Collect TypeScript / JavaScript files
    from drako.cli.ts_discovery import collect_ts_files
    collect_ts_files(root, metadata)

    # Parse npm dependencies from package.json
    if "package.json" in metadata.config_files:
        from drako.cli.ts_discovery import parse_package_json
        npm_deps = parse_package_json(metadata.config_files["package.json"])
        metadata.dependencies.update(npm_deps)

    return metadata


# ---------------------------------------------------------------------------
# Dependency parsing
# ---------------------------------------------------------------------------

_REQ_LINE_RE = re.compile(
    r"^([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)"   # package name
    r"(?:\[.*?\])?"                        # optional extras
    r"(?:\s*([><=!~^]+)\s*([\d.*]+))?"     # optional version spec
)


def _parse_requirements_txt(content: str) -> dict[str, str | None]:
    """Parse requirements.txt into {package: version_spec | None}."""
    deps: dict[str, str | None] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            pkg = m.group(1).lower().replace("-", "_").replace(".", "_")
            version = m.group(3)
            deps[pkg] = version
    return deps


def _parse_pyproject_toml(content: str) -> dict[str, str | None]:
    """Parse pyproject.toml dependencies.

    Uses tomllib on Python 3.11+, falls back to regex extraction.
    """
    deps: dict[str, str | None] = {}

    if sys.version_info >= (3, 11):
        try:
            import tomllib
            data = tomllib.loads(content)
            # [project] dependencies
            for dep_str in data.get("project", {}).get("dependencies", []):
                m = _REQ_LINE_RE.match(dep_str)
                if m:
                    pkg = m.group(1).lower().replace("-", "_").replace(".", "_")
                    deps[pkg] = m.group(3)
            # [tool.poetry.dependencies]
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for pkg, spec in poetry_deps.items():
                if pkg.lower() == "python":
                    continue
                pkg_norm = pkg.lower().replace("-", "_").replace(".", "_")
                if isinstance(spec, str):
                    ver = spec.lstrip("^~>=<! ")
                    deps[pkg_norm] = ver if ver else None
                elif isinstance(spec, dict):
                    deps[pkg_norm] = spec.get("version", "").lstrip("^~>=<! ") or None
            return deps
        except Exception:
            pass

    # Regex fallback
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("[project]", "[tool.poetry.dependencies]"):
            # Skip, we look for the dependencies key
            pass
        if re.match(r"^dependencies\s*=\s*\[", stripped):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("]"):
                in_deps = False
                continue
            # Parse "package>=version" style
            cleaned = stripped.strip('", ')
            m = _REQ_LINE_RE.match(cleaned)
            if m:
                pkg = m.group(1).lower().replace("-", "_").replace(".", "_")
                deps[pkg] = m.group(3)

    return deps


def _parse_setup_py(content: str) -> dict[str, str | None]:
    """Best-effort parse of setup.py install_requires."""
    deps: dict[str, str | None] = {}
    # Find install_requires=[...] block
    match = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if match:
        block = match.group(1)
        for item in re.findall(r"['\"]([^'\"]+)['\"]", block):
            m = _REQ_LINE_RE.match(item)
            if m:
                pkg = m.group(1).lower().replace("-", "_").replace(".", "_")
                deps[pkg] = m.group(3)
    return deps


def _extract_dependencies(config_files: dict[str, str]) -> dict[str, str | None]:
    """Extract all dependencies from available config files."""
    deps: dict[str, str | None] = {}

    if "requirements.txt" in config_files:
        deps.update(_parse_requirements_txt(config_files["requirements.txt"]))

    if "pyproject.toml" in config_files:
        deps.update(_parse_pyproject_toml(config_files["pyproject.toml"]))

    if "setup.py" in config_files:
        deps.update(_parse_setup_py(config_files["setup.py"]))

    return deps


# ---------------------------------------------------------------------------
# Framework detection
# ---------------------------------------------------------------------------

def _detect_from_deps(dependencies: dict[str, str | None]) -> dict[str, FrameworkInfo]:
    """Detect frameworks from parsed dependencies."""
    found: dict[str, FrameworkInfo] = {}
    for pkg, version in dependencies.items():
        pkg_lower = pkg.lower().replace("-", "_").replace(".", "_")
        fw_name = _FRAMEWORK_PACKAGES.get(pkg_lower)
        if fw_name and fw_name not in found:
            found[fw_name] = FrameworkInfo(
                name=fw_name,
                version=version,
                confidence=0.9,
            )
        elif fw_name and fw_name in found and version and not found[fw_name].version:
            found[fw_name].version = version
    return found


def _detect_from_imports(file_contents: dict[str, str]) -> dict[str, FrameworkInfo]:
    """Detect frameworks by scanning Python AST imports."""
    found: dict[str, FrameworkInfo] = {}

    for _rel_path, content in file_contents.items():
        if not _rel_path.endswith(".py"):
            continue
        try:
            tree = ast.parse(content, filename=_rel_path)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            module: str | None = None
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in _FRAMEWORK_IMPORTS:
                        module = top
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split(".")[0]
                    if top in _FRAMEWORK_IMPORTS:
                        module = top

            if module:
                fw_name = _FRAMEWORK_IMPORTS[module]
                if fw_name not in found:
                    found[fw_name] = FrameworkInfo(
                        name=fw_name,
                        version=None,
                        confidence=0.7,
                    )

    return found


def _detect_from_config_files(config_files: dict[str, str]) -> dict[str, FrameworkInfo]:
    """Detect frameworks from config file presence."""
    found: dict[str, FrameworkInfo] = {}
    if "crewai.yaml" in config_files:
        found["crewai"] = FrameworkInfo(name="crewai", confidence=1.0)
    if "mcp.json" in config_files:
        # MCP config doesn't imply a specific framework, but is relevant info
        pass
    return found


def detect_frameworks(metadata: ProjectMetadata) -> list[FrameworkInfo]:
    """Detect all AI agent frameworks used in the project.

    Combines evidence from config files, dependencies, and imports.
    Returns list sorted by confidence (highest first).
    """
    all_found: dict[str, FrameworkInfo] = {}

    # Layer 1: Config files (highest confidence)
    for name, info in _detect_from_config_files(metadata.config_files).items():
        all_found[name] = info

    # Layer 2: Dependencies
    for name, info in _detect_from_deps(metadata.dependencies).items():
        if name in all_found:
            # Merge version info
            if info.version and not all_found[name].version:
                all_found[name].version = info.version
            all_found[name].confidence = max(all_found[name].confidence, info.confidence)
        else:
            all_found[name] = info

    # Layer 3: Python imports
    for name, info in _detect_from_imports(metadata.file_contents).items():
        if name in all_found:
            all_found[name].confidence = max(all_found[name].confidence, info.confidence)
        else:
            all_found[name] = info

    # Layer 4: TypeScript frameworks (package.json + TS imports)
    if metadata.ts_files or "package.json" in metadata.config_files:
        from drako.cli.ts_discovery import detect_ts_frameworks
        for info in detect_ts_frameworks(metadata):
            if info.name in all_found:
                all_found[info.name].confidence = max(
                    all_found[info.name].confidence, info.confidence,
                )
            else:
                all_found[info.name] = info

    frameworks = sorted(all_found.values(), key=lambda f: f.confidence, reverse=True)
    return frameworks
