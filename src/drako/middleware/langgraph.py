"""LangGraph compliance middleware — checkpointer that intercepts state transitions."""

from __future__ import annotations

from typing import Any

from drako.client import DrakoClient
from drako.middleware.base import ComplianceMiddleware
from drako.utils.logger import log


class DrakoCheckpointer(ComplianceMiddleware):
    """A checkpoint wrapper that audits LangGraph state transitions.

    Wraps an optional inner checkpointer and intercepts ``put`` /
    ``aput`` calls to evaluate policy and record audit logs on every
    state transition.
    """

    def __init__(
        self,
        client: DrakoClient,
        inner: Any | None = None,
        auto_audit: bool = True,
        auto_policy: bool = True,
    ):
        super().__init__(
            client=client,
            auto_audit=auto_audit,
            auto_verify=False,  # LangGraph doesn't have named agents by default
            auto_policy=auto_policy,
        )
        self._inner = inner

    # ---- BaseCheckpointSaver-compatible interface ----

    def put(self, config: dict, checkpoint: dict, metadata: dict | None = None, new_versions: dict | None = None) -> dict:
        """Intercept a synchronous checkpoint write."""
        self._on_transition(config, checkpoint, metadata)
        if self._inner and hasattr(self._inner, "put"):
            return self._inner.put(config, checkpoint, metadata, new_versions)
        return config

    async def aput(self, config: dict, checkpoint: dict, metadata: dict | None = None, new_versions: dict | None = None) -> dict:
        """Intercept an async checkpoint write."""
        await self._on_transition_async(config, checkpoint, metadata)
        if self._inner and hasattr(self._inner, "aput"):
            return await self._inner.aput(config, checkpoint, metadata, new_versions)
        return config

    def get(self, config: dict) -> dict | None:
        if self._inner and hasattr(self._inner, "get"):
            return self._inner.get(config)
        return None

    async def aget(self, config: dict) -> dict | None:
        if self._inner and hasattr(self._inner, "aget"):
            return await self._inner.aget(config)
        return None

    def list(self, config: dict | None = None, **kwargs: Any) -> list:
        if self._inner and hasattr(self._inner, "list"):
            return self._inner.list(config, **kwargs)
        return []

    async def alist(self, config: dict | None = None, **kwargs: Any) -> list:
        if self._inner and hasattr(self._inner, "alist"):
            return await self._inner.alist(config, **kwargs)
        return []

    # ---- Transition hooks ----

    def _on_transition(self, config: dict, checkpoint: dict, metadata: dict | None) -> None:
        """Sync hook called on every state transition."""
        node_name = (metadata or {}).get("source", "unknown")
        agent_did = self._agent_dids.get(node_name, node_name)

        if self._auto_policy:
            try:
                context = {
                    "tool_name": node_name,
                    "task_id": f"lg_{checkpoint.get('ts', 'unknown')}",
                    "scope": "default",
                }
                self._check_policy(f"langgraph_transition:{node_name}", agent_did, context=context)
            except Exception:
                raise

        if self._auto_audit:
            try:
                self._record_audit(
                    f"langgraph_transition:{node_name}",
                    agent_did,
                    {"checkpoint_ts": checkpoint.get("ts"), "node": node_name},
                )
            except Exception as exc:
                log.warning("Audit log failed for transition %s: %s", node_name, exc)

    async def _on_transition_async(self, config: dict, checkpoint: dict, metadata: dict | None) -> None:
        """Async hook called on every state transition."""
        node_name = (metadata or {}).get("source", "unknown")
        agent_did = self._agent_dids.get(node_name, node_name)

        if self._auto_policy:
            context = {
                "tool_name": node_name,
                "task_id": f"lg_{checkpoint.get('ts', 'unknown')}",
                "scope": "default",
            }
            await self._check_policy_async(f"langgraph_transition:{node_name}", agent_did, context=context)

        if self._auto_audit:
            try:
                await self._record_audit_async(
                    f"langgraph_transition:{node_name}",
                    agent_did,
                    {"checkpoint_ts": checkpoint.get("ts"), "node": node_name},
                )
            except Exception as exc:
                log.warning("Audit log failed for transition %s: %s", node_name, exc)


class _LangGraphProxy:
    """Transparent proxy for a compiled LangGraph that injects the compliance checkpointer."""

    def __init__(self, graph: Any, checkpointer: DrakoCheckpointer):
        self._graph = graph
        self._checkpointer = checkpointer

    def invoke(self, input: Any, config: dict | None = None, **kwargs: Any) -> Any:
        config = config or {}
        config.setdefault("configurable", {})["checkpointer"] = self._checkpointer
        return self._graph.invoke(input, config=config, **kwargs)

    async def ainvoke(self, input: Any, config: dict | None = None, **kwargs: Any) -> Any:
        config = config or {}
        config.setdefault("configurable", {})["checkpointer"] = self._checkpointer
        return await self._graph.ainvoke(input, config=config, **kwargs)

    def stream(self, input: Any, config: dict | None = None, **kwargs: Any) -> Any:
        config = config or {}
        config.setdefault("configurable", {})["checkpointer"] = self._checkpointer
        return self._graph.stream(input, config=config, **kwargs)

    async def astream(self, input: Any, config: dict | None = None, **kwargs: Any) -> Any:
        config = config or {}
        config.setdefault("configurable", {})["checkpointer"] = self._checkpointer
        return self._graph.astream(input, config=config, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._graph, name)


def with_langgraph_compliance(
    graph: Any,
    config_path: str = ".drako.yaml",
    inner_checkpointer: Any | None = None,
    auto_audit: bool = True,
    auto_policy: bool = True,
) -> _LangGraphProxy:
    """Wrap a LangGraph compiled graph with compliance.

    Usage::

        from drako import with_langgraph_compliance

        graph = with_langgraph_compliance(my_graph.compile())
        result = graph.invoke(input)
    """
    client = DrakoClient.from_config(config_path)
    checkpointer = DrakoCheckpointer(
        client=client,
        inner=inner_checkpointer,
        auto_audit=auto_audit,
        auto_policy=auto_policy,
    )
    return _LangGraphProxy(graph=graph, checkpointer=checkpointer)
