"""Drako SDK exceptions."""

from __future__ import annotations


class DrakoError(Exception):
    """Base exception for all Drako errors."""


class DrakoAPIError(DrakoError):
    """Error returned by the Drako API."""

    def __init__(self, status_code: int, detail: str, request_id: str | None = None):
        self.status_code = status_code
        self.detail = detail
        self.request_id = request_id
        super().__init__(f"API error {status_code}: {detail}")


class AuthenticationError(DrakoAPIError):
    """Invalid or expired API key / token."""

    def __init__(self, detail: str = "Authentication failed", request_id: str | None = None):
        super().__init__(status_code=401, detail=detail, request_id=request_id)


class QuotaExceededError(DrakoAPIError):
    """Tenant has exceeded their usage quota."""

    def __init__(self, detail: str = "Quota exceeded", request_id: str | None = None):
        super().__init__(status_code=429, detail=detail, request_id=request_id)


class PolicyViolationError(DrakoAPIError):
    """An action was blocked by a governance policy."""

    def __init__(
        self,
        detail: str = "Action blocked by policy",
        policy_id: str | None = None,
        request_id: str | None = None,
    ):
        self.policy_id = policy_id
        super().__init__(status_code=403, detail=detail, request_id=request_id)


class ConfigError(DrakoError):
    """Error loading or validating configuration."""


class FrameworkNotInstalledError(DrakoError):
    """A required framework (CrewAI, LangGraph, etc.) is not installed."""

    def __init__(self, framework: str):
        self.framework = framework
        super().__init__(
            f"{framework} is not installed. Install it with: pip install drako[{framework.lower()}]"
        )
