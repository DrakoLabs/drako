"""Drako — The Portable Authority Kernel for AI Agents."""

__version__ = "4.0.0"

from drako.config import DrakoConfig
from drako.exceptions import (
    ConfigError,
    DrakoError,
    FrameworkNotInstalledError,
    PolicyViolationError,
)

__all__ = [
    "__version__",
    "DrakoConfig",
    "DrakoError",
    "ConfigError",
    "FrameworkNotInstalledError",
    "PolicyViolationError",
    "govern",
]


def govern(obj, **kwargs):
    """Wrap a supported agent framework object with the offline Drako Authority Kernel."""
    from drako._governance import govern as _govern

    return _govern(obj, **kwargs)
