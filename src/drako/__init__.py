"""Drako — The Portable Authority Kernel for AI Agents."""

from __future__ import annotations

__version__ = "4.0.0a1"

from drako.config import DrakoConfig
from drako.exceptions import (
    ConfigError,
    DrakoError,
    FrameworkNotInstalledError,
    PolicyViolationError,
)
from drako.guard import build_host, guard

__all__ = [
    "__version__",
    "DrakoConfig",
    "DrakoError",
    "ConfigError",
    "FrameworkNotInstalledError",
    "PolicyViolationError",
    "build_host",
    "govern",
    "guard",
]


def govern(obj, **kwargs):
    """Wrap a supported agent framework object with the offline Drako Authority Kernel."""
    from drako._governance import govern as _govern

    return _govern(obj, **kwargs)
