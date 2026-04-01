"""Drako SDK — The Trust Layer for AI Agents."""

__version__ = "2.5.1"

from drako.client import DrakoClient
from drako.config import DrakoConfig
from drako.exceptions import (
    DrakoAPIError,
    AuthenticationError,
    PolicyViolationError,
    QuotaExceededError,
)

__all__ = [
    "DrakoClient",
    "DrakoConfig",
    "DrakoAPIError",
    "AuthenticationError",
    "PolicyViolationError",
    "QuotaExceededError",
    "with_compliance",
    "with_langgraph_compliance",
    "with_autogen_compliance",
    "govern",
    "test_mode",
    "MockHITLResolver",
]


def test_mode(**kwargs):
    """Context manager for testing governed agents without blocking CI."""
    from drako.testing import test_mode as _test_mode

    return _test_mode(**kwargs)


def MockHITLResolver(**kwargs):  # noqa: N802 — matches class name for convenience
    """Pluggable HITL resolver for per-tool test rules."""
    from drako.testing import MockHITLResolver as _Cls

    return _Cls(**kwargs)


def with_compliance(crew, **kwargs):
    """Wrap a CrewAI Crew with Drako compliance middleware."""
    from drako.middleware.crewai import with_compliance as _with_compliance

    return _with_compliance(crew, **kwargs)


def with_langgraph_compliance(graph, **kwargs):
    """Wrap a LangGraph compiled graph with Drako compliance."""
    from drako.middleware.langgraph import with_langgraph_compliance as _fn

    return _fn(graph, **kwargs)


def with_autogen_compliance(group_chat, **kwargs):
    """Wrap an AutoGen GroupChat with Drako compliance."""
    from drako.middleware.autogen import with_autogen_compliance as _fn

    return _fn(group_chat, **kwargs)


def govern(obj, **kwargs):
    """Wrap any framework object with Drako governance (one line).

    Usage::

        from drako import govern
        crew = govern(crew)
    """
    from drako._governance import govern as _govern

    return _govern(obj, **kwargs)
