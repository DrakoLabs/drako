"""Drako CTK host: AGENT-HOOKS-0.1 conformance harness (Sprint 1, route A).

Implements the agent_hooks Harness protocol with a scripted agent loop that
mirrors the reference host semantics (emission order, enforcement via raised
InterceptionBlocked, transform write-back, approval seam inside the emitter,
fail-closed synthesis inside the emitter, identities from emitter results).

Drako value-add, non-interfering: our Guardian evaluates every pre_tool_call
in parallel AUDIT mode and logs divergences (scripted-verdict vs Guardian).
Divergence never alters the run — it is tuning signal for our policies.

Status: experimental. Conformance claim = (drako-guardian, adapter-version,
agent-hooks/<spec>, declared capabilities/profiles/identity, sdk-lang@sdk-ver)
+ CTK report. Never "certified secure" (cooperative contract, no
complete-mediation — spec SECURITY.md).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from drako.kernel import CTK_PIN, ACS_SPEC_PIN


def _require_ctk():
    try:
        import agent_hooks.ctk.harness as h
        from agent_hooks import (
            IdentityProvider,
            InterceptionBlocked,
            InterceptionEmitter,
        )
        from agent_hooks.ctk.reference import AgentContextBuilder
    except ImportError as e:
        raise ImportError(
            "agent-hooks-sdk (guardian extra) required for CTK runs. "
            f"Install: pip install 'drako[guardian]'  ({CTK_PIN}). ({e})"
        )
    return h, IdentityProvider, InterceptionBlocked, InterceptionEmitter, AgentContextBuilder


def _provider_of(declared: str | None):
    _, IdentityProvider, _, _, _ = _require_ctk()

    if declared == "ctk-fault":
        def _boom(_ctx: object) -> str:
            raise RuntimeError("ctk scripted provider fault")

        return IdentityProvider("ctk-fault", _boom)
    return declared


_IJSON_INT_MIN = -(2**53) + 1
_IJSON_INT_MAX = 2**53 - 1


def _ijson_violation(value: Any) -> bool:
    """True if value leaves the I-JSON domain (JCS §2: ECMA-262 safe
    integers, finite doubles, string keys). Host MUST fail closed."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return not (_IJSON_INT_MIN <= value <= _IJSON_INT_MAX)
    if isinstance(value, float):
        return not (value == value and value not in (float("inf"), float("-inf")))
    if isinstance(value, str) or value is None:
        return False
    if isinstance(value, dict):
        return any(not isinstance(k, str) or _ijson_violation(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_ijson_violation(v) for v in value)
    return True  # unknown types are outside the domain


class DrakoDomainGuard:
    """Host-side I-JSON domain validation (§10.1 input domain, fail closed).

    Registered FIRST so no scripted interceptor ever sees out-of-domain data.
    Returns deny(host_error:context_invalid) — the emitter records and
    enforces it like any other verdict. Pure function of the context;
    never touches tools, network, or the Guardian.
    """

    def intercept(self, context: dict[str, Any]) -> dict[str, Any]:
        try:
            bad = _ijson_violation(context)
        except Exception:
            bad = True
        if bad:
            return {"decision": "deny", "reason": "host_error:context_invalid"}
        return {"decision": "allow", "reason": "ctk:ijson-ok"}


class DrakoHarness:
    """agent_hooks Harness driving the scripted loop through OUR envelope side."""
    name = "drako-guardian"

    @property
    def capabilities(self) -> set:
        from agent_hooks.ctk.harness import Capability

        return {Capability.MODEL_CALLS, Capability.TOOL_CALLS}

    def __init__(self, guardian=None):
        self._guardian = guardian  # audit-mode only; None = no divergence log
        self._divergences: list[dict[str, Any]] = []
        self._scenario = None
        self._emitter = None
        self._builder = None
        self._tool_log: list[dict[str, Any]] = []

    # -- Harness protocol -------------------------------------------------
    def setup(self, scenario, interceptors, resolver, mode, composition,
              identity_provider="jcs-sha256", redact_for_approval=None) -> None:
        h, IdentityProvider, _, InterceptionEmitter, AgentContextBuilder = _require_ctk()
        import agent_hooks._core as _core

        self._scenario = scenario
        self._tool_log = []
        em = InterceptionEmitter(
            mode=mode,
            resolver=resolver,
            composition=composition,
            identity_provider=_provider_of(identity_provider),
        )
        if redact_for_approval:
            paths = list(redact_for_approval)

            def _redact(ctx: dict[str, Any]) -> dict[str, Any]:
                out = json.dumps(ctx)
                for path in paths:
                    try:
                        out = _core.apply_transform_ctx(out, path, '"[redacted]"')
                    except Exception:
                        continue
                return json.loads(out)

            em.set_approval_redactor(_redact)
        for i in interceptors:
            em.register(i)
        # NOTE (2026-09-04): DrakoDomainGuard is NOT registered here on purpose.
        # Registering any built-in interceptor defeats the §7 zero-interceptor
        # vectors (061/101: host with no controls must still fail closed via
        # host_error:no_interceptor). Domain validation lives in the Guardian
        # policy pipeline (envelope admission), unit-tested separately — never
        # as a harness-registered interceptor. Vectors needing int64_json /
        # bigint_json capabilities are legitimate capability-gated skips until
        # we declare those transports (same claim shape as MAF: pass + skips).
        self._emitter = em
        self._builder = AgentContextBuilder(
            agent_id="drako-ctk",
            framework="drako-guardian",
            session_id=str(uuid.uuid4()),
        )

    async def run(self):
        h, _, InterceptionBlocked, _, _ = _require_ctk()
        RunOutcome = h.RunOutcome
        assert self._scenario and self._emitter and self._builder
        s, em, b = self._scenario, self._emitter, self._builder
        outcome = RunOutcome.COMPLETED
        final = None
        try:
            await em.emit(b.agent_startup(tools_registered=sorted(s.tools)))
            await em.emit(b.input(content=s.input["content"], role=s.input["role"]))
            messages = [{"role": s.input["role"], "content": s.input["content"]}]
            for resp in s.model_script:
                ctx = b.pre_model_call(model_id="mock", messages=list(messages))
                await em.emit(ctx)
                messages = ctx["messages"]
                await em.emit(b.post_model_call(
                    model_id="mock", content=resp.content,
                    tool_calls=resp.tool_calls, finish_reason=resp.finish_reason))
                if resp.tool_calls:
                    for tc in resp.tool_calls:
                        try:
                            await self._do_tool_call(tc, messages)
                        except InterceptionBlocked as e:
                            messages.append({"role": "tool",
                                             "content": f"blocked: {e.result.verdict.reason}"})
                else:
                    final = resp.content
                    break
                messages.append({"role": "assistant", "content": resp.content or ""})
            if final is not None:
                ctx = b.output(content=final)
                await em.emit(ctx)
                final = ctx["output"]["content"]
        except InterceptionBlocked:
            outcome = RunOutcome.BLOCKED
            final = None
        await em.emit_unchecked(
            b.agent_shutdown(reason="completed" if outcome is RunOutcome.COMPLETED else "error"))
        return h.RunRecord(
            outcome=outcome,
            final_output=final,
            tool_invocations=list(self._tool_log),
            identities=[(r.input_identity, r.enforced_identity) for r in em.results],
            records=[r.to_wire() for r in em.results],
        )

    def teardown(self) -> None:
        self._scenario = self._emitter = self._builder = None

    @property
    def divergences(self) -> list[dict[str, Any]]:
        return list(self._divergences)

    # -- internals ----------------------------------------------------------
    async def _do_tool_call(self, tc: dict[str, Any], messages: list) -> None:
        s, em, b = self._scenario, self._emitter, self._builder
        ctx = b.pre_tool_call(call_id=tc["id"], name=tc["name"], args=dict(tc["args"]))
        self._audit_divergence(tc)
        await em.emit(ctx)
        args = ctx["tool_call"]["args"]  # post-transform
        spec = s.tools[tc["name"]]
        value, is_error = spec.invoke(args)
        self._tool_log.append({"name": tc["name"], "args": dict(args)})
        await em.emit(b.post_tool_call(
            call_id=tc["id"], name=tc["name"], args=dict(args),
            value=value, is_error=is_error))
        messages.append({"role": "tool", "content": value})

    def _audit_divergence(self, tc: dict[str, Any]) -> None:
        """Our Guardian's parallel verdict (record-only)."""
        if self._guardian is None:
            return
        try:
            from drako.kernel.envelope import Proposal
            from drako.kernel.authority import Label, TrustLevel

            d = self._guardian.evaluate(Proposal(
                action=tc["name"], side_effect_class="write", args=dict(tc["args"]),
                provenance_chain=(Label(origin="ctk:scripted", trust=TrustLevel.UNTRUSTED),),
            ))
            self._divergences.append({
                "tool": tc["name"], "args": dict(tc["args"]),
                "guardian_verdict": d.verdict, "policy_id": d.policy_id,
            })
        except Exception as e:  # audit must never break the run
            self._divergences.append({"tool": tc.get("name"), "audit_error": repr(e)})
