"""Auto-detect which AI agent framework is used in a project directory."""

from __future__ import annotations

from pathlib import Path


def _file_contains(path: Path, needle: str) -> bool:
    """Check if a text file contains a substring (case-insensitive)."""
    try:
        return needle.lower() in path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def _check_dependency_files(directory: Path, package: str) -> bool:
    """Check requirements.txt and pyproject.toml for a dependency."""
    for name in ("requirements.txt", "pyproject.toml"):
        dep_file = directory / name
        if dep_file.exists() and _file_contains(dep_file, package):
            return True
    return False


def _check_imports(directory: Path, module: str, max_files: int = 50) -> bool:
    """Scan .py files for imports of a given module (shallow, fast)."""
    count = 0
    for py_file in directory.rglob("*.py"):
        # Skip hidden dirs / venvs
        parts = py_file.parts
        if any(p.startswith(".") or p in ("venv", "env", ".venv", "node_modules", "__pycache__") for p in parts):
            continue
        count += 1
        if count > max_files:
            break
        if _file_contains(py_file, f"from {module}") or _file_contains(py_file, f"import {module}"):
            return True
    return False


def detect_framework(directory: str = ".") -> str | None:
    """Detect the AI agent framework in use.

    Priority: CrewAI > LangGraph > AutoGen (CrewAI has the most specific files).

    Returns:
        Framework name (``"crewai"``, ``"langgraph"``, ``"autogen"``) or ``None``.
    """
    root = Path(directory).resolve()

    # --- CrewAI ---
    if (root / "crewai.yaml").exists() or (root / "crew.py").exists():
        return "crewai"
    if _check_dependency_files(root, "crewai"):
        return "crewai"
    if _check_imports(root, "crewai"):
        return "crewai"

    # --- LangGraph ---
    if _check_dependency_files(root, "langgraph"):
        return "langgraph"
    if _check_imports(root, "langgraph"):
        return "langgraph"

    # --- AutoGen ---
    for pkg in ("autogen", "pyautogen"):
        if _check_dependency_files(root, pkg):
            return "autogen"
    if _check_imports(root, "autogen"):
        return "autogen"

    return None
