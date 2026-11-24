"""Drako Authority Kernel — portable Guardian (AGENT-HOOKS-0.1 native).

Single chokepoint: nothing executes without a Proposal; every decision mints
a signed Receipt. Spec pin: AGENT-HOOKS-0.1 (working draft v0.1.0).
CTK pin: agent-hooks-sdk==0.1.0a5 (47 vectors, SPEC agent-hooks/0.1).
"""

from __future__ import annotations

ACS_SPEC_PIN = "AGENT-HOOKS-0.1"
ACS_SPEC_URL = "https://aos.owasp.org"
CTK_PIN = "agent-hooks-sdk==0.1.0a5"
CTK_VECTORS = 47

__all__ = ["ACS_SPEC_PIN", "ACS_SPEC_URL", "CTK_PIN", "CTK_VECTORS"]
