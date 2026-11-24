"""Drako v4 exceptions — local-first, zero-SaaS."""

from __future__ import annotations

from typing import Any


class DrakoError(Exception):
    """Base exception for all Drako errors."""


class PolicyViolationError(DrakoError):
    """An action was blocked by the Authority Kernel or governance policy."""

    def __init__(
        self,
        detail: str = "Action blocked by policy",
        policy_id: str | None = None,
        receipt: dict[str, Any] | None = None,
    ):
        self.detail = detail
        self.policy_id = policy_id
        self.receipt = receipt
        super().__init__(f"Policy violation ({policy_id or 'deny'}): {detail}")


class ConfigError(DrakoError):
    """Error loading or validating .drako.yaml or ACS policy profile."""


class FrameworkNotInstalledError(DrakoError):
    """An optional agent framework adapter dependency is not installed."""

    def __init__(self, framework: str):
        self.framework = framework
        super().__init__(
            f"{framework} is not installed. Install it with: pip install 'drako[{framework.lower()}]'"
        )
