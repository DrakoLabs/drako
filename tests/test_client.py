"""Tests for DrakoClient — HTTP calls, retry, error handling."""

from __future__ import annotations

import pytest
import httpx
import respx

from drako.client import DrakoClient
from drako.exceptions import (
    DrakoAPIError,
    AuthenticationError,
    PolicyViolationError,
    QuotaExceededError,
)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestClientConstruction:
    def test_init_extracts_tenant_from_key(self):
        c = DrakoClient(api_key="am_live_tenant42_secret")
        assert c._tenant_id == "tenant42"

    def test_init_uses_explicit_tenant(self):
        c = DrakoClient(api_key="am_live_t_s", tenant_id="override")
        assert c._tenant_id == "override"

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("DRAKO_API_KEY", "am_test_envtenant_key")
        c = DrakoClient.from_env()
        assert c._tenant_id == "envtenant"
        assert c._endpoint == "https://api.useagentmesh.com"

    def test_from_env_custom_endpoint(self, monkeypatch):
        monkeypatch.setenv("DRAKO_API_KEY", "am_test_t_k")
        monkeypatch.setenv("DRAKO_ENDPOINT", "http://localhost:8000")
        c = DrakoClient.from_env()
        assert c._endpoint == "http://localhost:8000"

    def test_from_env_missing_key(self):
        with pytest.raises(AuthenticationError):
            DrakoClient.from_env()

    def test_from_config(self, config_file):
        c = DrakoClient.from_config(config_file)
        assert c._tenant_id == "testtenant"

    def test_headers(self, api_key):
        c = DrakoClient(api_key=api_key)
        assert c._headers["Authorization"] == f"Bearer {api_key}"
        assert "drako-python" in c._headers["User-Agent"]


# ---------------------------------------------------------------------------
# Sync API calls (mocked)
# ---------------------------------------------------------------------------

class TestSyncCalls:
    @respx.mock
    def test_verify_agent_identity_sync(self, api_key, endpoint):
        route = respx.post(f"{endpoint}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_123",
                "trust_score": 0.85,
                "status": "ACTIVE",
            })
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        result = c.verify_agent_identity_sync(agent_name="researcher", agent_role="data_analyst")
        assert result["did"] == "did:mesh:ag_123"
        assert result["trust_score"] == 0.85
        assert route.called

    @respx.mock
    def test_evaluate_policy_sync(self, api_key, endpoint):
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(200, json={
                "decision": "ALLOWED",
                "policies_evaluated": 3,
            })
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        result = c.evaluate_policy_sync(action="read_data", agent_did="did:mesh:ag_1")
        assert result["decision"] == "ALLOWED"

    @respx.mock
    def test_audit_log_sync(self, api_key, endpoint):
        respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={
                "log_id": "aud_001",
                "entry_hash": "0xabc",
                "previous_hash": "0x000",
                "chain_position": 1,
            })
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        result = c.audit_log_sync(action="data_read", agent_did="did:mesh:ag_1")
        assert result["log_id"] == "aud_001"

    @respx.mock
    def test_verify_chain_sync(self, api_key, endpoint):
        respx.post(f"{endpoint}/api/v1/audit-logs/verify").mock(
            return_value=httpx.Response(200, json={
                "valid": True,
                "entries_checked": 100,
                "chain_head": "0xdef",
            })
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        result = c.verify_chain_sync()
        assert result["valid"] is True
        assert result["entries_checked"] == 100

    @respx.mock
    def test_check_quota_sync(self, api_key, endpoint, tenant_id):
        respx.get(f"{endpoint}/api/v1/billing/subscription").mock(
            return_value=httpx.Response(200, json={
                "used": 45,
                "limit": 100,
                "plan": "free",
            })
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint, tenant_id=tenant_id)
        result = c.check_quota_sync()
        assert result["plan"] == "free"
        assert result["used"] == 45


# ---------------------------------------------------------------------------
# Async API calls (mocked)
# ---------------------------------------------------------------------------

class TestAsyncCalls:
    @respx.mock
    @pytest.mark.asyncio
    async def test_verify_agent_identity_async(self, api_key, endpoint):
        respx.post(f"{endpoint}/api/v1/agents/register").mock(
            return_value=httpx.Response(200, json={
                "did": "did:mesh:ag_async",
                "trust_score": 0.9,
            })
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        result = await c.verify_agent_identity("async-agent", "tester")
        assert result["did"] == "did:mesh:ag_async"
        await c.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_audit_log_async(self, api_key, endpoint):
        respx.post(f"{endpoint}/api/v1/audit-logs").mock(
            return_value=httpx.Response(200, json={"log_id": "aud_async"})
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        result = await c.audit_log("test_action", "did:mesh:ag_1")
        assert result["log_id"] == "aud_async"
        await c.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_context_manager(self, api_key, endpoint):
        respx.get(f"{endpoint}/api/v1/stats").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        async with DrakoClient(api_key=api_key, endpoint=endpoint) as c:
            result = await c.validate_key()
            assert result["ok"] is True


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    @respx.mock
    def test_auth_error_401(self, api_key, endpoint):
        respx.get(f"{endpoint}/api/v1/stats").mock(
            return_value=httpx.Response(401, text="Unauthorized")
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        with pytest.raises(AuthenticationError) as exc_info:
            c.validate_key_sync()
        assert exc_info.value.status_code == 401

    @respx.mock
    def test_quota_error_429(self, api_key, endpoint, tenant_id):
        respx.get(f"{endpoint}/api/v1/billing/subscription").mock(
            return_value=httpx.Response(429, text="Rate limited")
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint, tenant_id=tenant_id)
        with pytest.raises(QuotaExceededError):
            c.check_quota_sync()

    @respx.mock
    def test_policy_error_403(self, api_key, endpoint):
        respx.post(f"{endpoint}/api/v1/trust/evaluate").mock(
            return_value=httpx.Response(403, json={
                "detail": "Blocked by policy X",
                "policy_id": "pol_001",
            })
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        with pytest.raises(PolicyViolationError) as exc_info:
            c.evaluate_policy_sync(action="delete", agent_did="did:mesh:ag_1")
        assert exc_info.value.policy_id == "pol_001"

    @respx.mock
    def test_generic_api_error(self, api_key, endpoint):
        respx.get(f"{endpoint}/api/v1/stats").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        with pytest.raises(DrakoAPIError) as exc_info:
            c.validate_key_sync()
        assert exc_info.value.status_code == 500


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------

class TestRetry:
    @respx.mock
    def test_retries_on_connection_error(self, api_key, endpoint):
        call_count = 0

        def _side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("Connection refused")
            return httpx.Response(200, json={"ok": True})

        respx.get(f"{endpoint}/api/v1/stats").mock(side_effect=_side_effect)
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        result = c.validate_key_sync()
        assert result["ok"] is True
        assert call_count == 3

    @respx.mock
    def test_fails_after_max_retries(self, api_key, endpoint):
        respx.get(f"{endpoint}/api/v1/stats").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        c = DrakoClient(api_key=api_key, endpoint=endpoint)
        with pytest.raises(DrakoAPIError, match="3 retries"):
            c.validate_key_sync()
