"""TypeScript policy rules for ``drako scan``.

Evaluates TypeScript/JavaScript AI agent projects using tree-sitter
AST analysis.  Rules cover the same categories as Python rules
(SEC, GOV, COM, DET, ODD) but detect TS-specific patterns.
"""

from __future__ import annotations

from drako.cli.policies.base import BasePolicy
from drako.cli.policies.typescript.compliance import TS_COMPLIANCE_POLICIES
from drako.cli.policies.typescript.determinism import TS_DETERMINISM_POLICIES
from drako.cli.policies.typescript.governance import TS_GOVERNANCE_POLICIES
from drako.cli.policies.typescript.operational import TS_OPERATIONAL_POLICIES
from drako.cli.policies.typescript.security import TS_SECURITY_POLICIES

TS_POLICIES: list[BasePolicy] = (
    TS_SECURITY_POLICIES
    + TS_GOVERNANCE_POLICIES
    + TS_DETERMINISM_POLICIES
    + TS_COMPLIANCE_POLICIES
    + TS_OPERATIONAL_POLICIES
)

__all__ = ["TS_POLICIES"]
