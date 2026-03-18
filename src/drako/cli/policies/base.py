"""Base policy class and Finding dataclass for the scan policy engine."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


@dataclass
class Finding:
    """A single finding from a policy evaluation."""
    policy_id: str            # e.g. "SEC-001"
    category: str             # "Security", "Governance", "Compliance", "Best Practices"
    severity: str             # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    title: str                # Short title
    message: str              # Detailed description
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None   # The problematic code
    fix_snippet: str | None = None    # How to fix it


class BasePolicy(ABC):
    """Abstract base class for all scan policy rules."""

    policy_id: str = ""
    category: str = ""
    severity: str = ""
    title: str = ""

    @abstractmethod
    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        """Evaluate this policy against the project. Return list of findings."""
        ...
