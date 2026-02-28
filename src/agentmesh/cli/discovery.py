"""Framework & dependency detection for `agentmesh scan`.

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
    name: str                # "crewai", "langgraph", "autogen", "langchain", "llamaindex", "pydantic_ai"
    version: str | None = None   # parsed from requirements/pyproject
    confidence: float = 0.0      # 0.0-1.0


@dataclass
class ProjectMetadata:
    """Collected project information used by all scan phases."""
    root: Path = field(default_factory=lambda: Path("."))
    python_files: list[Path] = field(default_factory=list)
    config_files: dict[str, str] = field(default_factory=dict)    # filename -> content
    file_contents: dict[str, str] = field(default_factory=dict)   # rel_path -> content
    dependencies: dict[str, str | None] = field(default_factory=dict)  # package -> version
    frameworks: list[FrameworkInfo] = field(default_factory=list)


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
    "crewai.yaml", ".agentmesh.yaml", "mcp.json",
)

# Framework package name -> canonical framework name
_FRAMEWORK_PACKAGES: dict[str, str] = {
    "crewai": "crewai",
    "langgraph": "langgraph",
    "autogen": "autogen",
    "pyautogen": "autogen",
    "ag2": "autogen",
    "langchain": "langchain",
    "langchain-core": "langchain",
    "langchain-community": "langchain",
    "llama-index": "llamaindex",
    "llama_index": "llamaindex",
    "llamaindex": "llamaindex",
    "pydantic-ai": "pydantic_ai",
    "pydantic_ai": "pydantic_ai",
}

# Import module name -> canonical framework name
_FRAMEWORK_IMPORTS: dict[str, str] = {
    "crewai": "crewai",
    "langgraph": "langgraph",
    "autogen": "autogen",
    "pyautogen": "autogen",
    "langchain": "langchain",
    "langchain_core": "langchain",
    "langchain_community": "langchain",
    "llama_index": "llamaindex",
    "pydantic_ai": "pydantic_ai",
}


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def _should_skip(parts: tuple[str, ...]) -> bool:
    """Check if a path should be skipped based on directory names."""
    return any(p.startswith(".") or p in _SKIP_DIRS for p in parts)


def _safe_rglob(root: Path, pattern: str):
    """Walk directories safely, skipping any that raise OS errors.

    This is the fallback when ``root.rglob()`` crashes due to Windows
    MAX_PATH (260 chars) or broken OneDrive symlinks.
    """
    import os

    suffix = pattern.lstrip("*")  # "*.py" -> ".py"
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _: None):
        # Skip known junk directories in-place (prevents descent)
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fname in sorted(filenames):
            if fname.endswith(suffix):
                try:
                    yield Path(dirpath) / fname
                except (OSError, ValueError):
                    continue


def collect_project_files(directory: Path) -> ProjectMetadata:
    """Walk directory and collect Python files + config files.

    Returns a populated ProjectMetadata with file contents loaded.
    """
    root = directory.resolve()
    metadata = ProjectMetadata(root=root)
    count = 0

    # Collect Python files
    # Use a helper to safely walk — Windows can crash on paths > 260 chars
    # (e.g. Android build dirs, OneDrive broken symlinks)
    py_files: list[Path] = []
    try:
        py_files = sorted(root.rglob("*.py"))
    except (FileNotFoundError, PermissionError, OSError):
        # Fallback: manual walk that skips broken directories
        py_files = list(_safe_rglob(root, "*.py"))

    for py_file in py_files:
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

    # Parse dependencies
    metadata.dependencies = _extract_dependencies(metadata.config_files)

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

    # Layer 3: Imports
    for name, info in _detect_from_imports(metadata.file_contents).items():
        if name in all_found:
            all_found[name].confidence = max(all_found[name].confidence, info.confidence)
        else:
            all_found[name] = info

    frameworks = sorted(all_found.values(), key=lambda f: f.confidence, reverse=True)
    return frameworks
