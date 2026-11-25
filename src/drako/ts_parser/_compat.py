"""Tree-sitter availability check — zero-cost when deps are absent."""

from __future__ import annotations

_AVAILABLE: bool | None = None


def ts_available() -> bool:
    """Return ``True`` if tree-sitter and language grammars are importable."""
    global _AVAILABLE  # noqa: PLW0603
    if _AVAILABLE is None:
        try:
            import tree_sitter  # noqa: F401
            import tree_sitter_javascript  # noqa: F401
            import tree_sitter_typescript  # noqa: F401

            _AVAILABLE = True
        except ImportError:
            _AVAILABLE = False
    return _AVAILABLE
