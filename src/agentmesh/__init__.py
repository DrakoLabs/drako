"""AgentMesh SDK — The Trust Layer for AI Agents."""

__version__ = "2.0.1"

from agentmesh.client import AgentMeshClient
from agentmesh.config import AgentMeshConfig
from agentmesh.exceptions import (
    AgentMeshAPIError,
    AuthenticationError,
    PolicyViolationError,
    QuotaExceededError,
)

__all__ = [
    "AgentMeshClient",
    "AgentMeshConfig",
    "AgentMeshAPIError",
    "AuthenticationError",
    "PolicyViolationError",
    "QuotaExceededError",
    "with_compliance",
    "with_langgraph_compliance",
    "with_autogen_compliance",
    "govern",
]


def with_compliance(crew, **kwargs):
    """Wrap a CrewAI Crew with AgentMesh compliance middleware."""
    from agentmesh.middleware.crewai import with_compliance as _with_compliance

    return _with_compliance(crew, **kwargs)


def with_langgraph_compliance(graph, **kwargs):
    """Wrap a LangGraph compiled graph with AgentMesh compliance."""
    from agentmesh.middleware.langgraph import with_langgraph_compliance as _fn

    return _fn(graph, **kwargs)


def with_autogen_compliance(group_chat, **kwargs):
    """Wrap an AutoGen GroupChat with AgentMesh compliance."""
    from agentmesh.middleware.autogen import with_autogen_compliance as _fn

    return _fn(group_chat, **kwargs)


def govern(obj, **kwargs):
    """Wrap any framework object with AgentMesh governance (one line).

    Usage::

        from agentmesh import govern
        crew = govern(crew)
    """
    from agentmesh.govern import govern as _govern

    return _govern(obj, **kwargs)
