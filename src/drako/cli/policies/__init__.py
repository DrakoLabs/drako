"""Policy evaluation engine for `drako scan`.

Evaluates project against 60 built-in governance, security,
compliance, operational, magnitude, identity, versioning, hooks,
finops, resilience, a2a, multi-agent, and best-practice policy rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import Finding
from drako.cli.policies.security import SECURITY_POLICIES
from drako.cli.policies.governance import GOVERNANCE_POLICIES
from drako.cli.policies.compliance import COMPLIANCE_POLICIES
from drako.cli.policies.bestpractices import BEST_PRACTICE_POLICIES
from drako.cli.policies.operational import OPERATIONAL_POLICIES
from drako.cli.policies.magnitude import MAGNITUDE_POLICIES
from drako.cli.policies.identity import IDENTITY_POLICIES
from drako.cli.policies.versioning import VERSIONING_POLICIES
from drako.cli.policies.hooks import HOOKS_POLICIES
from drako.cli.policies.finops import FINOPS_POLICIES
from drako.cli.policies.resilience import RESILIENCE_POLICIES
from drako.cli.policies.a2a import A2A_POLICIES
from drako.cli.policies.multiagent import MULTIAGENT_POLICIES

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata

ALL_POLICIES = SECURITY_POLICIES + GOVERNANCE_POLICIES + COMPLIANCE_POLICIES + BEST_PRACTICE_POLICIES + OPERATIONAL_POLICIES + MAGNITUDE_POLICIES + IDENTITY_POLICIES + VERSIONING_POLICIES + HOOKS_POLICIES + FINOPS_POLICIES + RESILIENCE_POLICIES + A2A_POLICIES + MULTIAGENT_POLICIES


def evaluate_all_policies(bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
    """Run all policy rules and return findings."""
    findings: list[Finding] = []
    for policy in ALL_POLICIES:
        findings.extend(policy.evaluate(bom, metadata))
    return findings


__all__ = ["evaluate_all_policies", "Finding", "ALL_POLICIES"]
