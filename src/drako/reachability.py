"""Deprecated shim: use drako.heuristic_reachability (P1-6, 2026-09-04)."""

from __future__ import annotations

import warnings

warnings.warn(
    "drako.reachability is deprecated: it performs heuristic string-matching, "
    "not dataflow analysis. Use drako.heuristic_reachability.",
    DeprecationWarning,
    stacklevel=2,
)

from drako.heuristic_reachability import (  # noqa: E402,F401
    ReachabilityStatus,
    ToolReachability,
    analyze_reachability,
)
