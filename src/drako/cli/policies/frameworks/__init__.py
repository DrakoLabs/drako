"""Framework-specific governance rules (FW-* prefix).

Rules only fire when the corresponding framework is detected in the
project's BOM. Category: Framework. Scoring cap: -30.
"""

from drako.cli.policies.frameworks.crewai import CREWAI_POLICIES
from drako.cli.policies.frameworks.langgraph import LANGGRAPH_POLICIES
from drako.cli.policies.frameworks.autogen import AUTOGEN_POLICIES
from drako.cli.policies.frameworks.semantic_kernel import SK_POLICIES
from drako.cli.policies.frameworks.pydantic_ai import PYDANTIC_AI_POLICIES
from drako.cli.policies.frameworks.maf import MAF_POLICIES
from drako.cli.policies.frameworks.openai_agents import OPENAI_POLICIES

FRAMEWORK_POLICIES = (
    CREWAI_POLICIES
    + LANGGRAPH_POLICIES
    + AUTOGEN_POLICIES
    + SK_POLICIES
    + PYDANTIC_AI_POLICIES
    + MAF_POLICIES
    + OPENAI_POLICIES
)

__all__ = ["FRAMEWORK_POLICIES"]
