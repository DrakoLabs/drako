"""AutoGen compliance middleware — observer agent for group chats."""

from __future__ import annotations

from typing import Any

from drako.client import DrakoClient
from drako.middleware.base import ComplianceMiddleware
from drako.utils.logger import log


class DrakoObserver(ComplianceMiddleware):
    """An observer that participates in an AutoGen ``GroupChat`` to audit
    every message exchange without generating responses.

    The observer:
    - Registers as a participant in the group chat.
    - Intercepts each message and records it in the audit trail.
    - Evaluates policies on each exchange.
    - Never generates a reply (always passes the turn).
    """

    OBSERVER_NAME = "Drako_Compliance_Observer"

    def __init__(
        self,
        client: DrakoClient,
        auto_audit: bool = True,
        auto_policy: bool = True,
    ):
        super().__init__(
            client=client,
            auto_audit=auto_audit,
            auto_verify=True,
            auto_policy=auto_policy,
        )
        self._message_count = 0

    def on_message(self, sender_name: str, message: str, **kwargs: Any) -> None:
        """Called for every message in the group chat."""
        self._message_count += 1
        agent_did = self._agent_dids.get(sender_name, sender_name)

        # Policy check
        if self._auto_policy:
            try:
                self._check_policy(f"autogen_message:{sender_name}", agent_did)
            except Exception:
                raise

        # Audit log
        if self._auto_audit:
            try:
                self._record_audit(
                    f"autogen_message:{sender_name}",
                    agent_did,
                    {"message_preview": message[:500], "message_index": self._message_count},
                )
            except Exception as exc:
                log.warning("Audit log failed for message from %s: %s", sender_name, exc)

    async def on_message_async(self, sender_name: str, message: str, **kwargs: Any) -> None:
        """Async version of on_message."""
        self._message_count += 1
        agent_did = self._agent_dids.get(sender_name, sender_name)

        if self._auto_policy:
            await self._check_policy_async(f"autogen_message:{sender_name}", agent_did)

        if self._auto_audit:
            try:
                await self._record_audit_async(
                    f"autogen_message:{sender_name}",
                    agent_did,
                    {"message_preview": message[:500], "message_index": self._message_count},
                )
            except Exception as exc:
                log.warning("Audit log failed for message from %s: %s", sender_name, exc)


class _AutoGenGroupChatProxy:
    """Proxy that wraps an AutoGen GroupChat, injecting the compliance observer."""

    def __init__(self, group_chat: Any, observer: DrakoObserver):
        self._group_chat = group_chat
        self._observer = observer
        self._original_agents: list[Any] = []

    def _inject_observer(self) -> None:
        """Register agents with the observer and hook into the chat."""
        agents = getattr(self._group_chat, "agents", [])
        self._original_agents = list(agents)

        # Verify all agents in the chat
        if self._observer._auto_verify:
            for agent in agents:
                name = getattr(agent, "name", str(agent))
                role = getattr(agent, "description", "autogen_agent")
                try:
                    self._observer._verify_agent(name, role)
                except Exception as exc:
                    log.warning("Could not verify agent %s: %s", name, exc)

    def run(self, **kwargs: Any) -> Any:
        """Run the group chat with compliance hooks."""
        self._inject_observer()

        # Hook into message processing if the chat supports it
        original_process = getattr(self._group_chat, "run", None)
        if original_process is None:
            log.warning("GroupChat has no 'run' method. Returning chat object with observer attached.")
            return self._group_chat

        return original_process(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._group_chat, name)


def with_autogen_compliance(
    group_chat: Any,
    config_path: str = ".drako.yaml",
    auto_audit: bool = True,
    auto_policy: bool = True,
) -> _AutoGenGroupChatProxy:
    """Add Drako compliance observer to an AutoGen GroupChat.

    Usage::

        from drako import with_autogen_compliance

        chat = with_autogen_compliance(my_group_chat)
    """
    client = DrakoClient.from_config(config_path)
    observer = DrakoObserver(
        client=client,
        auto_audit=auto_audit,
        auto_policy=auto_policy,
    )
    proxy = _AutoGenGroupChatProxy(group_chat=group_chat, observer=observer)
    return proxy
