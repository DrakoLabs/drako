"""CrewAI compliance middleware — transparent proxy with audit + policy."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from drako.client import DrakoClient
from drako.middleware.base import ComplianceMiddleware
from drako.utils.logger import log


class CrewAIComplianceMiddleware(ComplianceMiddleware):
    """Wraps a CrewAI ``Crew`` to intercept its lifecycle:

    - **Pre-kickoff**: verify identity of every agent.
    - **Pre-task**: evaluate policy for each task.
    - **Post-task**: record audit log.
    - **On-error**: notify the trust engine.

    All other attributes/methods are proxied transparently to the
    underlying crew so the user notices no behavioural difference.
    """

    def __init__(
        self,
        crew: Any,
        client: DrakoClient,
        auto_audit: bool = True,
        auto_verify: bool = True,
        auto_policy: bool = True,
        fail_closed: bool = False,
        finops_config: dict[str, Any] | None = None,
    ):
        super().__init__(
            client=client,
            auto_audit=auto_audit,
            auto_verify=auto_verify,
            auto_policy=auto_policy,
        )
        self._crew = crew
        self._fail_closed = fail_closed
        self._finops_config = finops_config or {}
        # In-memory response cache (hash → response)
        self._response_cache: dict[str, dict[str, Any]] = {}

    # ----------------------------------------------------------------
    # Synchronous kickoff
    # ----------------------------------------------------------------

    def kickoff(self, **kwargs: Any) -> Any:
        """Compliance-wrapped ``crew.kickoff()``."""
        # Step 1 — verify all agents
        if self._auto_verify:
            self._verify_all_agents()

        # Step 2 — wrap individual tool._run() for per-tool governance
        if self._auto_policy:
            self._wrap_agent_tools()

        # Step 3 — install task callbacks
        original_tasks = self._get_tasks()
        if self._auto_policy or self._auto_audit:
            self._wrap_tasks(original_tasks)

        # Step 4 — execute
        try:
            result = self._crew.kickoff(**kwargs)
        except Exception as exc:
            self._on_error(exc)
            raise

        # Step 5 — summary
        task_count = len(original_tasks) if original_tasks else 0
        log.info("Crew complete. %d tasks audited.", task_count)
        return result

    # ----------------------------------------------------------------
    # Async kickoff
    # ----------------------------------------------------------------

    async def akickoff(self, **kwargs: Any) -> Any:
        """Async compliance-wrapped ``crew.kickoff()``."""
        # Step 1 — verify all agents
        if self._auto_verify:
            await self._verify_all_agents_async()

        # Step 2 — wrap individual tool._run() for per-tool governance
        if self._auto_policy:
            self._wrap_agent_tools()

        # Step 3 — install task callbacks
        original_tasks = self._get_tasks()
        if self._auto_policy or self._auto_audit:
            self._wrap_tasks(original_tasks)

        # Step 4 — execute (CrewAI >=0.70 supports async kickoff)
        try:
            if hasattr(self._crew, "akickoff"):
                result = await self._crew.akickoff(**kwargs)
            else:
                result = self._crew.kickoff(**kwargs)
        except Exception as exc:
            self._on_error(exc)
            raise

        task_count = len(original_tasks) if original_tasks else 0
        log.info("Crew complete. %d tasks audited.", task_count)
        return result

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    def _get_agents(self) -> list[Any]:
        """Retrieve the agent list from the crew, handling various CrewAI versions."""
        if hasattr(self._crew, "agents"):
            return list(self._crew.agents)
        return []

    def _get_tasks(self) -> list[Any]:
        """Retrieve the task list from the crew."""
        if hasattr(self._crew, "tasks"):
            return list(self._crew.tasks)
        return []

    def _verify_all_agents(self) -> None:
        for agent in self._get_agents():
            name = getattr(agent, "name", None) or getattr(agent, "role", "unknown")
            role = getattr(agent, "role", "agent")
            self._verify_agent(name, role)

    async def _verify_all_agents_async(self) -> None:
        for agent in self._get_agents():
            name = getattr(agent, "name", None) or getattr(agent, "role", "unknown")
            role = getattr(agent, "role", "agent")
            await self._verify_agent_async(name, role)

    def _wrap_agent_tools(self) -> None:
        """Wrap every tool._run() on every agent to enforce per-tool governance.

        Each wrapped tool calls ``/trust/evaluate`` before executing.  If the
        backend returns ``rejected``, the tool returns a safe error string
        instead of executing.  On network errors, the tool **fails open**
        (executes normally) by default.
        """
        for agent in self._get_agents():
            agent_name = getattr(agent, "name", None) or getattr(agent, "role", "unknown")
            agent_did = self._agent_dids.get(agent_name, "unknown")
            tools = getattr(agent, "tools", None)
            if not tools:
                continue
            for i, tool in enumerate(tools):
                tool_name = getattr(tool, "name", None) or f"tool_{i}"
                original_run = getattr(tool, "_run", None)
                if original_run is None:
                    continue
                # Guard against double-wrapping (e.g. govern() called twice)
                if getattr(original_run, "_drako_wrapped", False):
                    continue
                wrapped = self._make_tool_wrapper(original_run, tool_name, agent_name, agent_did)
                tool._run = wrapped
                log.debug("Wrapped tool '%s' for agent '%s'", tool_name, agent_name)

    def _make_tool_wrapper(
        self,
        original_run: Any,
        tool_name: str,
        agent_name: str,
        agent_did: str,
    ) -> Any:
        """Return a wrapper around *original_run* that enforces governance."""
        client = self._client
        fail_closed = self._fail_closed
        finops = self._finops_config
        cache_ref = self._response_cache

        def governed_run(*args: Any, **kwargs: Any) -> Any:
            # Build a truncated payload preview for DLP scanning
            payload_parts: list[str] = []
            if args:
                payload_parts.append(str(args)[:200])
            if kwargs:
                payload_parts.append(str(kwargs)[:300])
            payload_preview = " ".join(payload_parts) if payload_parts else None

            context = {
                "tool_name": tool_name,
                "task_id": f"tool_{uuid.uuid4().hex[:8]}",
                "scope": "default",
            }
            if payload_preview:
                context["payload_preview"] = payload_preview

            # Extract tool_args dict for intent fingerprinting
            tool_args = dict(kwargs) if kwargs else {}

            # ── PRE-ACTION HOOKS ──
            try:
                hook_ctx = {
                    "hook_point": "pre_action",
                    "agent_name": agent_name,
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                }
                hook_resp = client.execute_hooks_sync(
                    hook_point="pre_action", context=hook_ctx,
                )
                if hook_resp.get("action") == "deny":
                    reason = hook_resp.get("reason", "Pre-action hook blocked")
                    log.warning("Drako pre_action hook blocked %s: %s", tool_name, reason)
                    return f"[Drako] Action blocked by hook: {reason}"
            except Exception as exc:
                log.debug("Pre-action hooks skipped for %s: %s", tool_name, exc)

            # ── GATE 1: Create intent fingerprint (before policy eval) ──
            intent_result = None
            try:
                intent_result = client.create_intent_sync(
                    agent_name=agent_name,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    session_id=context.get("task_id"),
                )
            except Exception as exc:
                # Intent creation is best-effort; skip if backend unavailable
                log.debug("Intent creation skipped for %s: %s", tool_name, exc)

            # ── Policy evaluation (existing) ──
            try:
                result = client.evaluate_policy_sync(
                    action=f"tool:{tool_name}",
                    agent_did=agent_did,
                    context=context,
                )
                decision = result.get("decision", result.get("allowed", True))

                # HITL: pending approval → pause the agent
                if decision in ("PENDING_APPROVAL", "escalated"):
                    approval_id = result.get("approval_id") or ""
                    # Try to extract approval_id from reasoning
                    if not approval_id:
                        for r in result.get("reasoning", []):
                            if "approval_id:" in str(r):
                                approval_id = str(r).split("approval_id:")[-1].strip().rstrip(")")
                                break
                    log.warning(
                        "Drako HITL checkpoint for %s — approval required (id: %s)",
                        tool_name, approval_id,
                    )
                    return (
                        f"[Drako] Action paused — awaiting human approval. "
                        f"Approval ID: {approval_id}. "
                        f"You can continue with other tasks while waiting."
                    )

                if decision in (False, "BLOCKED", "rejected"):
                    reasoning = result.get("reasoning", [])
                    reason = result.get("reason") or (
                        "; ".join(reasoning) if reasoning else "Policy violation"
                    )
                    log.warning(
                        "Drako BLOCKED %s for %s: %s",
                        tool_name, agent_name, reason,
                    )
                    return f"[Drako] Action blocked: {reason}"
            except Exception as exc:
                if fail_closed:
                    log.warning(
                        "Drako evaluate unreachable for %s, BLOCKING (fail-closed): %s",
                        tool_name, exc,
                    )
                    return f"[Drako] Action blocked: backend unreachable (fail-closed mode)"
                log.warning(
                    "Drako evaluate unreachable for %s, allowing: %s",
                    tool_name, exc,
                )

            # ── GATE 2: Verify intent fingerprint (before execution) ──
            if intent_result and intent_result.get("intent_id"):
                try:
                    verify = client.verify_intent_sync(
                        intent_id=intent_result["intent_id"],
                        intent_hash=intent_result["intent_hash"],
                        tool_name=tool_name,
                        tool_args=tool_args,
                    )
                    if not verify.get("verified", False):
                        details = verify.get("mismatch_details", "unknown")
                        log.warning(
                            "Drako INTENT MISMATCH on %s: %s",
                            tool_name, details,
                        )
                        return (
                            f"[Drako] Intent verification failed: {details}. "
                            f"Action blocked to prevent potential tampering."
                        )
                except Exception as exc:
                    log.debug("Intent verification skipped for %s: %s", tool_name, exc)

            # ── FINOPS: Cache lookup (before execution) ──
            cache_cfg = finops.get("cache", {})
            cache_hit = False
            cache_key = None
            if cache_cfg.get("enabled"):
                try:
                    raw = json.dumps({"tool": tool_name, "args": tool_args}, sort_keys=True)
                    cache_key = hashlib.sha256(raw.encode()).hexdigest()
                    entry = cache_ref.get(cache_key)
                    if entry is not None:
                        ttl_h = cache_cfg.get("ttl_hours", 24)
                        age_h = (time.time() - entry["ts"]) / 3600
                        if age_h <= ttl_h:
                            cache_hit = True
                            log.info("Drako cache HIT for %s (key=%s…)", tool_name, cache_key[:8])
                            # Record cost as cached (zero cost)
                            try:
                                client.record_cost_sync(
                                    agent_name=agent_name, tool_name=tool_name,
                                    model_name=entry.get("model", "cached"),
                                    cached=True, total_cost_usd=0.0,
                                    task_id=context.get("task_id"),
                                )
                            except Exception:
                                pass
                            return entry["response"]
                        else:
                            del cache_ref[cache_key]
                except Exception as exc:
                    log.debug("FinOps cache lookup failed for %s: %s", tool_name, exc)

            # ── FINOPS: Model routing (before execution) ──
            routed = False
            original_model = None
            selected_model = None
            routing_cfg = finops.get("routing", {})
            if routing_cfg.get("enabled"):
                try:
                    default_model = routing_cfg.get("default_model", "gpt-4o")
                    rules = routing_cfg.get("rules", [])
                    selected_model = default_model
                    for rule in rules:
                        condition = rule.get("condition", "")
                        if _evaluate_routing_condition(condition, tool_args, tool_name):
                            original_model = default_model
                            selected_model = rule.get("model", default_model)
                            routed = True
                            log.info(
                                "Drako routed %s: %s → %s (%s)",
                                tool_name, default_model, selected_model,
                                rule.get("reason", ""),
                            )
                            break
                except Exception as exc:
                    log.debug("FinOps routing failed for %s: %s", tool_name, exc)

            t0 = time.monotonic()
            result = original_run(*args, **kwargs)
            latency_ms = int((time.monotonic() - t0) * 1000)

            # ── FINOPS: Store in cache (after execution) ──
            if cache_cfg.get("enabled") and cache_key and not cache_hit:
                try:
                    cache_ref[cache_key] = {
                        "response": result,
                        "model": selected_model or "unknown",
                        "ts": time.time(),
                    }
                except Exception:
                    pass

            # ── FINOPS: Record cost (after execution) ──
            tracking_cfg = finops.get("tracking", {})
            if tracking_cfg.get("enabled"):
                try:
                    client.record_cost_sync(
                        agent_name=agent_name,
                        tool_name=tool_name,
                        model_name=selected_model or "unknown",
                        cached=False,
                        routed=routed,
                        original_model=original_model,
                        task_id=context.get("task_id"),
                        latency_ms=latency_ms,
                    )
                except Exception as exc:
                    log.debug("FinOps cost recording failed for %s: %s", tool_name, exc)

            # ── POST-ACTION HOOKS ──
            try:
                post_ctx = {
                    "hook_point": "post_action",
                    "agent_name": agent_name,
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "result": str(result)[:500] if result else None,
                }
                client.execute_hooks_sync(
                    hook_point="post_action", context=post_ctx,
                )
            except Exception as exc:
                log.debug("Post-action hooks skipped for %s: %s", tool_name, exc)

            return result

        governed_run._drako_wrapped = True  # type: ignore[attr-defined]
        return governed_run

    def _wrap_tasks(self, tasks: list[Any]) -> None:
        """Install pre/post hooks on each task via CrewAI's callback mechanism."""
        for task in tasks:
            original_callback = getattr(task, "callback", None)

            # Determine agent DID for this task
            agent = getattr(task, "agent", None)
            agent_name = getattr(agent, "name", None) or getattr(agent, "role", "unknown") if agent else "unknown"
            agent_did = self._agent_dids.get(agent_name, "unknown")
            task_desc = getattr(task, "description", str(task))[:200]

            # Pre-task policy check (only if task has the hook)
            if self._auto_policy and agent_did != "unknown":
                try:
                    context = {
                        "tool_name": task_desc,
                        "task_id": f"task_{id(task)}",
                        "scope": "default",
                    }
                    self._check_policy(task_desc, agent_did, context=context)
                except Exception:
                    raise

            # Wrap the callback for post-task audit
            if self._auto_audit:
                def _make_callback(orig_cb: Any, _did: str, _desc: str) -> Any:
                    def _audited_callback(output: Any) -> Any:
                        try:
                            result_data = {"output": str(output)[:1000]} if output else {}
                            self._record_audit(_desc, _did, result_data)
                        except Exception as exc:
                            log.warning("Audit log failed: %s", exc)
                        if orig_cb:
                            return orig_cb(output)
                        return output
                    return _audited_callback

                task.callback = _make_callback(original_callback, agent_did, task_desc)

    def _on_error(self, exc: Exception) -> None:
        """Notify the trust engine about an error and fire on_error hooks."""
        log.error("Crew execution failed: %s", exc)
        try:
            err_ctx = {
                "hook_point": "on_error",
                "error_type": type(exc).__name__,
                "error_message": str(exc)[:500],
            }
            self._client.execute_hooks_sync(
                hook_point="on_error", context=err_ctx,
            )
        except Exception as hook_exc:
            log.debug("on_error hooks skipped: %s", hook_exc)

    # ----------------------------------------------------------------
    # Transparent proxy
    # ----------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        """Proxy all unknown attributes to the underlying crew."""
        return getattr(self._crew, name)


def _evaluate_routing_condition(
    condition: str,
    tool_args: dict[str, Any],
    tool_name: str,
) -> bool:
    """Evaluate a simple routing condition against the current context.

    Supports patterns like:
    - ``task_type == 'summarization'``
    - ``tool_name == 'search'``
    """
    if not condition:
        return False
    try:
        if "==" in condition:
            key, value = condition.split("==", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            # Check tool_args first, then fall back to tool_name matching
            if key == "tool_name":
                return tool_name == value
            return tool_args.get(key) == value
    except Exception:
        pass
    return False


def with_compliance(
    crew: Any,
    config_path: str = ".drako.yaml",
    auto_audit: bool = True,
    auto_verify: bool = True,
    auto_policy: bool = True,
) -> CrewAIComplianceMiddleware:
    """Convenience function to wrap a CrewAI Crew with compliance.

    Usage::

        from drako import with_compliance

        crew = with_compliance(MyCrew())
        result = crew.kickoff()
    """
    client = DrakoClient.from_config(config_path)

    # Read governance.on_backend_unreachable from YAML if available
    fail_closed = False
    finops_config: dict[str, Any] = {}
    try:
        from drako.config import DrakoConfig
        cfg = DrakoConfig.load(config_path)
        fail_closed = cfg.governance.on_backend_unreachable == "block"
        # Extract FinOps config for middleware-level routing/caching
        finops_config = cfg.finops.model_dump()
    except Exception:
        pass

    return CrewAIComplianceMiddleware(
        crew=crew,
        client=client,
        auto_audit=auto_audit,
        auto_verify=auto_verify,
        auto_policy=auto_policy,
        fail_closed=fail_closed,
        finops_config=finops_config,
    )
