"""DrakoClient — async-first HTTP client for the Drako API."""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

import httpx

from drako import __version__
from drako.config import DrakoConfig
from drako.exceptions import (
    DrakoAPIError,
    AuthenticationError,
    PolicyViolationError,
    QuotaExceededError,
)
from drako.utils.logger import log

_DEFAULT_ENDPOINT = "https://api.useagentmesh.com"
_TIMEOUT = 30.0
_MAX_RETRIES = 3
_BACKOFF_BASE = 1.0  # seconds


class DrakoClient:
    """HTTP client that communicates with the Drako backend.

    All async methods have ``_sync`` counterparts for non-async frameworks.
    """

    def __init__(
        self,
        api_key: str,
        endpoint: str = _DEFAULT_ENDPOINT,
        tenant_id: str | None = None,
    ):
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._tenant_id = tenant_id or self._extract_tenant_id(api_key)
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "X-Tenant-ID": self._tenant_id,
            "User-Agent": f"drako-python/{__version__}",
            "Content-Type": "application/json",
        }
        self._async_client: httpx.AsyncClient | None = None
        self._sync_client: httpx.Client | None = None

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config_path: str = ".drako.yaml") -> DrakoClient:
        """Instantiate from a .drako.yaml file."""
        config = DrakoConfig.load(config_path)
        api_key = config.resolve_api_key()
        return cls(api_key=api_key, endpoint=config.endpoint, tenant_id=config.tenant_id)

    @classmethod
    def from_env(cls) -> DrakoClient:
        """Instantiate from environment variables."""
        api_key = os.environ.get("DRAKO_API_KEY")
        if not api_key:
            raise AuthenticationError("DRAKO_API_KEY environment variable is not set")
        endpoint = os.environ.get("DRAKO_ENDPOINT", _DEFAULT_ENDPOINT)
        tenant_id = os.environ.get("DRAKO_TENANT_ID")
        return cls(api_key=api_key, endpoint=endpoint, tenant_id=tenant_id)

    # ------------------------------------------------------------------
    # Internal HTTP machinery
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_tenant_id(api_key: str) -> str:
        """Best-effort extraction of tenant_id from the API key prefix."""
        # Keys look like am_live_<tenant>_<secret> or am_test_<tenant>_<secret>
        parts = api_key.split("_")
        if len(parts) >= 3:
            return parts[2]
        return "default"

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                base_url=self._endpoint,
                headers=self._headers,
                timeout=_TIMEOUT,
            )
        return self._async_client

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(
                base_url=self._endpoint,
                headers=self._headers,
                timeout=_TIMEOUT,
            )
        return self._sync_client

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Make an HTTP request with retry and error handling."""
        client = self._get_async_client()
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES):
            try:
                response = await client.request(method, path, **kwargs)
                return self._handle_response(response)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    wait = _BACKOFF_BASE * (2 ** attempt)
                    log.warning("Request to %s failed (attempt %d/%d), retrying in %.1fs: %s",
                                path, attempt + 1, _MAX_RETRIES, wait, exc)
                    await asyncio.sleep(wait)

        raise DrakoAPIError(
            status_code=0,
            detail=f"Request failed after {_MAX_RETRIES} retries: {last_exc}",
        )

    def _request_sync(self, method: str, path: str, **kwargs: Any) -> dict:
        """Synchronous version of _request with retry."""
        client = self._get_sync_client()
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES):
            try:
                response = client.request(method, path, **kwargs)
                return self._handle_response(response)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    wait = _BACKOFF_BASE * (2 ** attempt)
                    log.warning("Request to %s failed (attempt %d/%d), retrying in %.1fs: %s",
                                path, attempt + 1, _MAX_RETRIES, wait, exc)
                    time.sleep(wait)

        raise DrakoAPIError(
            status_code=0,
            detail=f"Request failed after {_MAX_RETRIES} retries: {last_exc}",
        )

    @staticmethod
    def _handle_response(response: httpx.Response) -> dict:
        """Parse response and raise typed errors."""
        request_id = response.headers.get("X-Request-ID")

        if response.status_code == 401:
            raise AuthenticationError(
                detail=response.text or "Authentication failed",
                request_id=request_id,
            )
        if response.status_code == 429:
            raise QuotaExceededError(
                detail=response.text or "Quota exceeded",
                request_id=request_id,
            )
        if response.status_code == 403:
            body = response.json() if response.text else {}
            raise PolicyViolationError(
                detail=body.get("detail", "Action blocked by policy"),
                policy_id=body.get("policy_id"),
                request_id=request_id,
            )
        if response.status_code >= 400:
            raise DrakoAPIError(
                status_code=response.status_code,
                detail=response.text or "Unknown error",
                request_id=request_id,
            )

        if not response.text:
            return {}
        return response.json()

    # ------------------------------------------------------------------
    # Async API methods
    # ------------------------------------------------------------------

    async def verify_agent_identity(
        self, agent_name: str, agent_role: str, metadata: dict | None = None
    ) -> dict:
        """Register/verify an agent and return its DID + trust score."""
        payload: dict[str, Any] = {"agent_name": agent_name, "agent_role": agent_role}
        if metadata:
            payload["metadata"] = metadata
        result = await self._request("POST", "/api/v1/agents/register", json=payload)
        log.info('Agent "%s" verified (DID: %s)', agent_name, result.get("did", "unknown"))
        return result

    async def evaluate_policy(
        self, action: str, agent_did: str, context: dict | None = None
    ) -> dict:
        """Evaluate whether an action is permitted by the tenant's policies."""
        ctx = context or {}
        payload: dict[str, Any] = {
            "agent_id": agent_did,
            "task_id": ctx.get("task_id", str(uuid.uuid4())),
            "task_type": ctx.get("tool_name", action),
            "required_scope": ctx.get("scope", "default"),
        }
        if ctx.get("payload_preview"):
            payload["payload_preview"] = ctx["payload_preview"]
        return await self._request("POST", "/api/v1/trust/evaluate", json=payload)

    async def audit_log(
        self,
        action: str,
        agent_did: str,
        result: dict | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Create an audit hash chain entry."""
        payload: dict[str, Any] = {
            "agent_did": agent_did,
            "action_type": action,
            "action_description": action,
        }
        if result:
            payload["output_data"] = result
        if metadata:
            payload["metadata"] = metadata
        return await self._request("POST", "/api/v1/audit-logs", json=payload)

    async def verify_chain(self, last_n: int | None = None) -> dict:
        """Verify the integrity of the audit hash chain."""
        params: dict[str, Any] = {}
        if last_n is not None:
            params["last_n"] = last_n
        return await self._request("POST", "/api/v1/audit-logs/verify", json=params)

    async def check_quota(self) -> dict:
        """Check the tenant's current usage quota."""
        return await self._request("GET", "/api/v1/billing/subscription")

    async def validate_key(self) -> dict:
        """Validate the API key and return tenant info."""
        return await self._request("GET", "/api/v1/stats")

    # ------------------------------------------------------------------
    # Sync wrappers
    # ------------------------------------------------------------------

    def verify_agent_identity_sync(
        self, agent_name: str, agent_role: str, metadata: dict | None = None
    ) -> dict:
        """Sync wrapper for verify_agent_identity."""
        payload: dict[str, Any] = {"agent_name": agent_name, "agent_role": agent_role}
        if metadata:
            payload["metadata"] = metadata
        result = self._request_sync("POST", "/api/v1/agents/register", json=payload)
        log.info('Agent "%s" verified (DID: %s)', agent_name, result.get("did", "unknown"))
        return result

    def evaluate_policy_sync(
        self, action: str, agent_did: str, context: dict | None = None
    ) -> dict:
        """Sync wrapper for evaluate_policy."""
        ctx = context or {}
        payload: dict[str, Any] = {
            "agent_id": agent_did,
            "task_id": ctx.get("task_id", str(uuid.uuid4())),
            "task_type": ctx.get("tool_name", action),
            "required_scope": ctx.get("scope", "default"),
        }
        if ctx.get("payload_preview"):
            payload["payload_preview"] = ctx["payload_preview"]
        return self._request_sync("POST", "/api/v1/trust/evaluate", json=payload)

    def audit_log_sync(
        self,
        action: str,
        agent_did: str,
        result: dict | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Sync wrapper for audit_log."""
        payload: dict[str, Any] = {
            "agent_did": agent_did,
            "action_type": action,
            "action_description": action,
        }
        if result:
            payload["output_data"] = result
        if metadata:
            payload["metadata"] = metadata
        return self._request_sync("POST", "/api/v1/audit-logs", json=payload)

    def verify_chain_sync(self, last_n: int | None = None) -> dict:
        """Sync wrapper for verify_chain."""
        params: dict[str, Any] = {}
        if last_n is not None:
            params["last_n"] = last_n
        return self._request_sync("POST", "/api/v1/audit-logs/verify", json=params)

    # ------------------------------------------------------------------
    # Intent Fingerprinting (Two-Gate) — sync wrappers
    # ------------------------------------------------------------------

    def create_intent_sync(
        self,
        agent_name: str,
        tool_name: str,
        tool_args: dict | None = None,
        session_id: str | None = None,
        sequence_number: int = 0,
    ) -> dict:
        """Gate 1 — create an intent fingerprint before execution."""
        payload: dict[str, Any] = {
            "agent_name": agent_name,
            "tool_name": tool_name,
            "tool_args": tool_args or {},
            "session_id": session_id,
            "sequence_number": sequence_number,
        }
        return self._request_sync("POST", "/api/v1/intent/create", json=payload)

    def verify_intent_sync(
        self,
        intent_id: str,
        intent_hash: str,
        tool_name: str,
        tool_args: dict | None = None,
    ) -> dict:
        """Gate 2 — verify that tool args haven't changed since Gate 1."""
        payload: dict[str, Any] = {
            "intent_id": intent_id,
            "intent_hash": intent_hash,
            "tool_name": tool_name,
            "tool_args": tool_args or {},
        }
        return self._request_sync("POST", "/api/v1/intent/verify", json=payload)

    def check_quota_sync(self) -> dict:
        """Sync wrapper for check_quota."""
        return self._request_sync("GET", "/api/v1/billing/subscription")

    def validate_key_sync(self) -> dict:
        """Sync wrapper for validate_key."""
        return self._request_sync("GET", "/api/v1/stats")

    # ------------------------------------------------------------------
    # Agentic FinOps (Sprint 4)
    # ------------------------------------------------------------------

    def record_cost_sync(
        self,
        agent_name: str,
        tool_name: str,
        model_name: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        total_cost_usd: float = 0.0,
        cached: bool = False,
        routed: bool = False,
        original_model: str | None = None,
        task_id: str | None = None,
        session_id: str | None = None,
        latency_ms: int | None = None,
    ) -> dict:
        """Record an LLM call cost to the FinOps tracking system."""
        payload: dict[str, Any] = {
            "agent_id": agent_name,
            "tool_name": tool_name,
            "model_name": model_name,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_cost_usd": total_cost_usd,
            "cached": cached,
            "routed": routed,
        }
        if original_model:
            payload["original_model"] = original_model
        if task_id:
            payload["task_id"] = task_id
        if session_id:
            payload["session_id"] = session_id
        if latency_ms is not None:
            payload["latency_ms"] = latency_ms
        return self._request_sync("POST", "/api/v1/finops/record", json=payload)

    def finops_cache_lookup_sync(
        self,
        cache_key: str,
    ) -> dict:
        """Look up a cached LLM response by hash key."""
        return self._request_sync(
            "GET", f"/api/v1/finops/cache/{cache_key}",
        )

    def finops_cache_store_sync(
        self,
        cache_key: str,
        response: str,
        model_name: str,
        ttl_hours: int = 24,
    ) -> dict:
        """Store an LLM response in the FinOps cache."""
        return self._request_sync(
            "POST",
            "/api/v1/finops/cache",
            json={
                "cache_key": cache_key,
                "response": response,
                "model_name": model_name,
                "ttl_hours": ttl_hours,
            },
        )

    def finops_route_model_sync(
        self,
        tool_name: str,
        context: dict[str, Any] | None = None,
    ) -> dict:
        """Ask the backend which model to use for a given tool/context."""
        return self._request_sync(
            "POST",
            "/api/v1/finops/route",
            json={
                "tool_name": tool_name,
                "context": context or {},
            },
        )

    # ------------------------------------------------------------------
    # Programmable Hooks (Sprint 3)
    # ------------------------------------------------------------------

    async def execute_hooks(
        self,
        hook_point: str,
        context: dict[str, Any],
    ) -> dict:
        """Execute hooks for a given hook_point."""
        return await self._request(
            "POST",
            "/api/v1/hooks/execute",
            json={"hook_point": hook_point, "context": context},
        )

    def execute_hooks_sync(
        self,
        hook_point: str,
        context: dict[str, Any],
    ) -> dict:
        """Sync wrapper for execute_hooks."""
        return self._request_sync(
            "POST",
            "/api/v1/hooks/execute",
            json={"hook_point": hook_point, "context": context},
        )

    # ------------------------------------------------------------------
    # Collective Intelligence (Sprint 7)
    # ------------------------------------------------------------------

    def check_ioc_sync(
        self,
        tool_name: str,
        tool_args: str,
        block_severity: int = 7,
    ) -> dict | None:
        """Check tool args against the global IOC cache. Returns match or None."""
        try:
            result = self._request_sync(
                "POST",
                "/api/v1/intel/check",
                json={
                    "tool_name": tool_name,
                    "content": tool_args,
                    "block_severity": block_severity,
                },
            )
            if result and result.get("action"):
                return result
            return None
        except Exception:
            return None  # IOC check failures must never block execution

    async def check_ioc(
        self,
        tool_name: str,
        tool_args: str,
        block_severity: int = 7,
    ) -> dict | None:
        """Async: check tool args against the global IOC cache."""
        try:
            result = await self._request(
                "POST",
                "/api/v1/intel/check",
                json={
                    "tool_name": tool_name,
                    "content": tool_args,
                    "block_severity": block_severity,
                },
            )
            if result and result.get("action"):
                return result
            return None
        except Exception:
            return None

    def submit_ioc_sync(
        self,
        ioc_type: str,
        content: str,
        severity: int,
        source_feature: str,
    ) -> dict | None:
        """Auto-submit a detected threat to the collective intelligence network."""
        try:
            return self._request_sync(
                "POST",
                "/api/v1/intel/submit",
                json={
                    "ioc_type": ioc_type,
                    "content": content,
                    "severity": severity,
                    "source_feature": source_feature,
                },
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP clients."""
        if self._async_client and not self._async_client.is_closed:
            await self._async_client.aclose()
        if self._sync_client and not self._sync_client.is_closed:
            self._sync_client.close()

    async def __aenter__(self) -> DrakoClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
