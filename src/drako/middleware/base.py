"""Base compliance middleware — shared logic for all frameworks."""

from __future__ import annotations

from typing import Any

from drako.client import DrakoClient
from drako.config import DrakoConfig
from drako.exceptions import PolicyViolationError
from drako.utils.logger import log


class ComplianceMiddleware:
    """Base class with common compliance logic shared across framework middlewares."""

    def __init__(
        self,
        client: DrakoClient,
        auto_audit: bool = True,
        auto_verify: bool = True,
        auto_policy: bool = True,
    ):
        self._client = client
        self._auto_audit = auto_audit
        self._auto_verify = auto_verify
        self._auto_policy = auto_policy
        self._agent_dids: dict[str, str] = {}  # agent_name -> DID

    # ---- Shared helpers ----

    def _verify_agent(self, name: str, role: str) -> str:
        """Verify an agent and cache its DID. Returns the DID."""
        if name in self._agent_dids:
            return self._agent_dids[name]

        result = self._client.verify_agent_identity_sync(agent_name=name, agent_role=role)
        did = result.get("did", result.get("agent_id", "unknown"))
        trust = result.get("trust_score", "N/A")
        self._agent_dids[name] = did
        log.info('Agent "%s" verified (DID: %s, trust: %s)', name, did, trust)
        return did

    async def _verify_agent_async(self, name: str, role: str) -> str:
        """Async version of _verify_agent."""
        if name in self._agent_dids:
            return self._agent_dids[name]

        result = await self._client.verify_agent_identity(agent_name=name, agent_role=role)
        did = result.get("did", result.get("agent_id", "unknown"))
        trust = result.get("trust_score", "N/A")
        self._agent_dids[name] = did
        log.info('Agent "%s" verified (DID: %s, trust: %s)', name, did, trust)
        return did

    def _check_policy(self, action: str, agent_did: str, context: dict | None = None) -> dict:
        """Evaluate policy and raise if denied. Also checks IOC cache."""
        # IOC cache check: block known-malicious tool args before policy eval
        ctx = context or {}
        tool_name = ctx.get("tool_name", action)
        tool_args_str = str(ctx.get("payload_preview", ctx.get("tool_args", "")))
        if tool_args_str:
            ioc_match = self._client.check_ioc_sync(tool_name, tool_args_str)
            if ioc_match and ioc_match.get("action") == "blocked":
                raise PolicyViolationError(
                    detail=f"Blocked by collective intelligence: known IOC (severity {ioc_match.get('severity')})",
                    policy_id="collective_intel_ioc",
                )

        result = self._client.evaluate_policy_sync(action=action, agent_did=agent_did, context=context)
        decision = result.get("decision", result.get("allowed", True))
        if decision in (False, "BLOCKED", "rejected"):
            raise PolicyViolationError(
                detail=result.get("reason", result.get("reasoning", "Action blocked by policy")),
                policy_id=result.get("blocking_policy", result.get("policy_id")),
            )
        return result

    async def _check_policy_async(self, action: str, agent_did: str, context: dict | None = None) -> dict:
        """Async version of _check_policy. Also checks IOC cache."""
        ctx = context or {}
        tool_name = ctx.get("tool_name", action)
        tool_args_str = str(ctx.get("payload_preview", ctx.get("tool_args", "")))
        if tool_args_str:
            ioc_match = await self._client.check_ioc(tool_name, tool_args_str)
            if ioc_match and ioc_match.get("action") == "blocked":
                raise PolicyViolationError(
                    detail=f"Blocked by collective intelligence: known IOC (severity {ioc_match.get('severity')})",
                    policy_id="collective_intel_ioc",
                )

        result = await self._client.evaluate_policy(action=action, agent_did=agent_did, context=context)
        decision = result.get("decision", result.get("allowed", True))
        if decision in (False, "BLOCKED", "rejected"):
            raise PolicyViolationError(
                detail=result.get("reason", result.get("reasoning", "Action blocked by policy")),
                policy_id=result.get("blocking_policy", result.get("policy_id")),
            )
        return result

    def _record_audit(self, action: str, agent_did: str, result: dict | None = None) -> dict:
        """Record an audit log entry."""
        return self._client.audit_log_sync(action=action, agent_did=agent_did, result=result)

    async def _record_audit_async(self, action: str, agent_did: str, result: dict | None = None) -> dict:
        """Async version of _record_audit."""
        return await self._client.audit_log(action=action, agent_did=agent_did, result=result)

    @classmethod
    def _build_client(cls, config_path: str = ".drako.yaml") -> DrakoClient:
        """Build an DrakoClient from config."""
        return DrakoClient.from_config(config_path)
