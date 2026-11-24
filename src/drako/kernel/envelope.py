"""Guardian envelope: single chokepoint. Proposal in, Decision out.

Verdicts: permit / deny / modify (+ deny+approval liftable via signed ConsentToken).
Fail-closed: ANY internal error synthesizes deny(host_error:*) — never allow.
AGENT-HOOKS-0.1 mapping: permit->allow, deny->deny, modify->transform.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from drako.kernel import authority as auth
from drako.kernel.authority import ConsentToken, Label, TrustLevel
from drako.kernel.eval import UnsafeExpressionError, evaluate_condition

logger = logging.getLogger("drako.kernel")


@dataclass(frozen=True)
class Proposal:
    action: str  # tool name
    side_effect_class: str  # read | write | external_comms | irreversible | memory_write
    args: dict[str, Any] = field(default_factory=dict)
    provenance_chain: tuple = field(default_factory=tuple)  # Label[]
    capability_set: frozenset = field(default_factory=frozenset)
    manifest_snapshot: str = ""  # hash of tool manifest at admission
    agent_id: str = ""
    session_id: str = ""
    consent_token: Optional[ConsentToken] = None  # operator-signed elevation


@dataclass
class Decision:
    verdict: str  # permit | deny | modify
    reason: str
    policy_id: str = ""
    modifications: Optional[dict[str, Any]] = None
    approval: Optional[dict[str, Any]] = None  # liftable deny seam
    trace: list[str] = field(default_factory=list)


def args_hash(args: dict[str, Any]) -> str:
    from drako.kernel.receipts import _canonical

    return hashlib.sha256(_canonical(args)).hexdigest()


class Guardian:
    """Deterministic policy enforcement. No LLM inside."""

    def __init__(
        self,
        profile: dict[str, Any],
        *,
        operator_public_pem: Optional[str] = None,
    ):
        self.profile = profile
        self.spec_pin = profile.get("spec_pin", "")
        self.tools = profile.get("tools", {})
        self.default_effect = profile.get("default_effect", "deny")
        self.tiers = profile.get("tiers", {})
        self.operator_public_pem = operator_public_pem

    def evaluate(self, proposal: Proposal) -> Decision:
        try:
            return self._evaluate_inner(proposal)
        except Exception as e:
            logger.warning("Guardian internal error -> synthesized deny: %s", e)
            return Decision(
                verdict="deny",
                reason=f"host_error:internal:{type(e).__name__}",
                policy_id="kernel:fail-closed",
                trace=["fail-closed-synthesis"],
            )

    def _has_valid_consent(self, proposal: Proposal) -> bool:
        """Verify either an operator-signed ConsentToken or legacy capability_set."""
        if proposal.consent_token is not None:
            if not self.operator_public_pem:
                return False
            return auth.verify_consent_token(
                proposal.consent_token,
                self.operator_public_pem,
                expected_action_hash=args_hash(proposal.args),
            )
        return bool(proposal.capability_set)

    def _evaluate_inner(self, proposal: Proposal) -> Decision:
        if proposal.side_effect_class not in auth.REQUIRED_TRUST:
            return Decision(
                "deny",
                f"unknown side-effect class: {proposal.side_effect_class}",
                policy_id="kernel:schema",
                trace=["schema"],
            )
        required = auth.REQUIRED_TRUST[proposal.side_effect_class]
        trace = [f"required_trust={required.name}"]

        # 1. Provenance lattice over the whole chain (weakest link governs)
        for label in proposal.provenance_chain:
            if not auth.may_influence(label, required, proposal.side_effect_class):
                if not label.scope:
                    reason = (
                        f"profile declares no scope for side-effect "
                        f"'{proposal.side_effect_class}' (origin={label.origin}) — "
                        f"declare permitted side-effect classes in .drako.yaml"
                    )
                else:
                    reason = (
                        f"provenance insufficient: origin={label.origin} "
                        f"trust={label.trust.name}"
                    )
                return Decision(
                    "deny",
                    reason,
                    policy_id="kernel:provenance",
                    trace=trace + ["provenance-deny"],
                )
        trace.append("provenance-ok")

        # 2. Tool rule (Progent-style: effect + arg conditions)
        rule = self.tools.get(proposal.action)
        if rule is None:
            if self.default_effect == "deny":
                return Decision(
                    "deny",
                    f"no rule for tool: {proposal.action}",
                    policy_id="kernel:default-deny",
                    trace=trace + ["default-deny"],
                )
            return self._consent_gate(proposal, "kernel:default-allow", trace + ["default-allow"])

        effect = rule.get("effect", "deny")
        for cond in rule.get("conditions", []):
            try:
                ok = evaluate_condition(
                    cond.get("when", "False"),
                    {"tool_args": proposal.args, **proposal.args},
                )
            except UnsafeExpressionError as e:
                if "Unknown variable" in str(e):
                    trace.append(f"condition-skipped:{cond.get('id', '?')}")
                    continue
                return Decision(
                    "deny",
                    f"unsafe rule condition: {e}",
                    policy_id=rule.get("id", "kernel:rule"),
                    trace=trace + ["rule-rejected"],
                )
            if ok:
                effect = cond.get("effect", effect)
                trace.append(f"condition-matched:{cond.get('id', '?')}")
        trace.append(f"rule-effect={effect}")

        if effect == "deny":
            if rule.get("approval_liftable"):
                if self._has_valid_consent(proposal) and proposal.consent_token is not None:
                    return Decision(
                        "permit",
                        f"lifted via verified consent token ({proposal.consent_token.issuer})",
                        policy_id=rule.get("id", "kernel:rule"),
                        trace=trace + ["consent-verified"],
                    )
                return Decision(
                    "deny",
                    rule.get("reason", "denied by policy"),
                    policy_id=rule.get("id", "kernel:rule"),
                    approval={"lift": "consent-token", "binds": args_hash(proposal.args)},
                    trace=trace + ["approval-seam"],
                )
            return Decision(
                "deny",
                rule.get("reason", "denied by policy"),
                policy_id=rule.get("id", "kernel:rule"),
                trace=trace,
            )
        if effect == "modify":
            return Decision(
                "modify",
                rule.get("reason", "modified by policy"),
                policy_id=rule.get("id", "kernel:rule"),
                modifications=rule.get("modifications", {}),
                trace=trace,
            )
        return self._consent_gate(proposal, rule.get("id", "kernel:rule"), trace)

    def _consent_gate(self, proposal: Proposal, policy_id: str, trace: list[str]) -> Decision:
        if proposal.side_effect_class == "irreversible" and not self._has_valid_consent(proposal):
            return Decision(
                "deny",
                "irreversible action requires consent token",
                policy_id=policy_id,
                approval={"lift": "consent-token", "binds": args_hash(proposal.args)},
                trace=trace + ["consent-required"],
            )
        return Decision("permit", "allowed by policy", policy_id=policy_id, trace=trace + ["permit"])

    @staticmethod
    def to_hooks_verdict(decision: Decision) -> dict[str, Any]:
        mapping = {"permit": "allow", "deny": "deny", "modify": "transform"}
        out: dict[str, Any] = {"verdict": mapping[decision.verdict], "reason": decision.reason}
        if decision.modifications is not None:
            out["modifications"] = decision.modifications
        if decision.approval is not None:
            out["approval"] = decision.approval
        return out
