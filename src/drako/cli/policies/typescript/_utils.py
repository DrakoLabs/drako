"""Shared utilities for TypeScript policy rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.ts_parser._compat import ts_available

if TYPE_CHECKING:
    from drako.ts_parser.parser import TSParser

_TS_EXTENSIONS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs", ".cts", ".cjs"})

_parser_singleton: TSParser | None = None
_parser_init_attempted: bool = False


def is_ts_file(rel_path: str) -> bool:
    """Return ``True`` if *rel_path* has a TypeScript/JavaScript extension."""
    return any(rel_path.endswith(ext) for ext in _TS_EXTENSIONS)


def get_parser() -> TSParser | None:
    """Lazy-init singleton :class:`TSParser`, ``None`` if deps missing."""
    global _parser_singleton, _parser_init_attempted  # noqa: PLW0603
    if _parser_init_attempted:
        return _parser_singleton
    _parser_init_attempted = True
    if not ts_available():
        return None
    from drako.ts_parser import get_parser as _get

    _parser_singleton = _get()
    return _parser_singleton
