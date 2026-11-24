"""Guardian Host: framework-agnostic chokepoint + receipt chaining + loop breaker.

Adapters (LangGraph, OpenAI Agents, MAF, Claude Agent SDK, Google ADK, CrewAI)
and the local enforcement proxy are thin translators into Proposal; ALL
decisions and signed receipts flow through here.

Charter #4: deny mints a receipt too. Signed receipts require keys; without
keys you get decisions only (explicit, never silent-unsigned).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from drako.kernel.authority import ConsentToken, Label, OriginAttester, TrustLevel
from drako.kernel.envelope import Decision, Guardian, Proposal, args_hash
from drako.kernel.loop_breaker import LoopBreaker, call_fingerprint
from drako.kernel.memory_gate import MEMORY_WRITE_CLASS, MemoryDecision, authorize_memory_write

logger = logging.getLogger("drako.kernel.host")


@dataclass
class HostConfig:
    agent_id: str = "default-agent"
    session_id: str = ""
    manifest_snapshot: str = ""
    store_path: Optional[str] = None
    private_pem: Optional[str] = None
    public_pem: Optional[str] = None
    operator_public_pem: Optional[str] = None  # sealed pubkey for ConsentToken verification
    enable_loop_breaker: bool = True
    loop_threshold: int = 10
    loop_window_seconds: float = 300.0


class Host:
    """Owns a Guardian + key material + hash chain + LoopBreaker across calls."""

    def __init__(self, guardian: Guardian, config: Optional[HostConfig] = None):
        self.guardian = guardian
        self.config = config or HostConfig()
        if self.config.operator_public_pem and not self.guardian.operator_public_pem:
            self.guardian.operator_public_pem = self.config.operator_public_pem
        self._last_hash: Optional[str] = None
        self._store = None
        if self.config.store_path:
            from drako.kernel.receipts import ReceiptStore

            self._store = ReceiptStore(self.config.store_path)
        self.attester = OriginAttester()
        self.loop_breaker: Optional[LoopBreaker] = (
            LoopBreaker(
                trip_threshold=self.config.loop_threshold,
                window_seconds=self.config.loop_window_seconds,
            )
            if self.config.enable_loop_breaker
            else None
        )

    @property
    def last_hash(self) -> Optional[str]:
        return self._last_hash

    def attest_label(
        self,
        *,
        origin: str,
        trust: TrustLevel,
        scope: frozenset,
        ttl_seconds: Optional[int] = None,
    ) -> Label:
        """Mint a call-site attested Label scoped to this Host."""
        return self.attester.issue(
            origin=origin,
            trust=trust,
            scope=scope,
            ttl_seconds=ttl_seconds,
        )

    def _mint_if_configured(
        self,
        *,
        decision_str: str,
        policy_id: str,
        reason: str,
        tool_name: str,
        digest: str,
        provenance: Sequence[Label],
        supersedes_receipt_id: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        if not (self.config.private_pem and self.config.public_pem):
            return None
        from drako.kernel import receipts as R

        receipt = R.mint_receipt(
            decision=decision_str,
            policy_id=policy_id,
            reason=reason,
            tool_name=tool_name,
            agent_id=self.config.agent_id,
            args_hash=digest,
            provenance=[
                {
                    "origin": l.origin,
                    "trust": l.trust.name,
                    "ttl_seconds": l.ttl_seconds,
                }
                for l in provenance
            ],
            prev_hash=self._last_hash,
            supersedes_receipt_id=supersedes_receipt_id,
            private_pem=self.config.private_pem,
            public_pem=self.config.public_pem,
        )
        self._last_hash = receipt["payload_hash"]
        if self._store is not None:
            self._store.append(receipt)
        return receipt

    def govern_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        provenance: Optional[list[Label]] = None,
        side_effect_class: str = "write",
        consent_token: Optional[ConsentToken] = None,
        supersedes_receipt_id: Optional[str] = None,
    ) -> tuple[Decision, Optional[dict[str, Any]]]:
        """Evaluate + check loop breaker + (if keys) mint a chained receipt."""
        prov = tuple(provenance or ())
        digest = args_hash(dict(args))

        # 1. Runaway repetition circuit-breaker (ASI08 / ASI10)
        if self.loop_breaker is not None:
            call_fp = call_fingerprint(tool_name, digest)
            lv = self.loop_breaker.record(
                self.config.agent_id,
                call_fp,
                session_id=self.config.session_id,
            )
            if lv.action != "ok":
                reason = (
                    f"runaway loop {lv.action}: '{tool_name}' invoked identically "
                    f"{lv.count} times in {int(self.loop_breaker.window_seconds)}s"
                )
                decision = Decision(
                    verdict="deny",
                    reason=reason,
                    policy_id="kernel:loop-breaker",
                    approval={"lift": "loop-approve", "key": lv.key, "binds": digest},
                    trace=["loop-breaker-tripped"],
                )
                receipt = self._mint_if_configured(
                    decision_str="deny",
                    policy_id=decision.policy_id,
                    reason=decision.reason,
                    tool_name=tool_name,
                    digest=digest,
                    provenance=prov,
                )
                return decision, receipt

        # 2. Guardian envelope evaluation
        proposal = Proposal(
            action=tool_name,
            side_effect_class=side_effect_class,
            args=dict(args),
            provenance_chain=prov,
            agent_id=self.config.agent_id,
            session_id=self.config.session_id,
            manifest_snapshot=self.config.manifest_snapshot,
            consent_token=consent_token,
        )
        decision = self.guardian.evaluate(proposal)
        receipt = self._mint_if_configured(
            decision_str="permit" if decision.verdict == "permit" else "deny",
            policy_id=decision.policy_id,
            reason=decision.reason,
            tool_name=tool_name,
            digest=digest,
            provenance=prov,
            supersedes_receipt_id=supersedes_receipt_id,
        )
        return decision, receipt

    def govern_memory_write(
        self,
        memory_id: str,
        labels: Sequence[Label],
    ) -> tuple[MemoryDecision, Optional[dict[str, Any]]]:
        """Authorize a memory write (ASI06) and mint a chained receipt."""
        mdec = authorize_memory_write(labels, memory_id)
        digest = args_hash({"memory_id": memory_id, "label_count": len(labels)})
        receipt = self._mint_if_configured(
            decision_str="permit" if mdec.verdict == "permit" else "deny",
            policy_id="kernel:memory-gate",
            reason=mdec.reason,
            tool_name=f"{MEMORY_WRITE_CLASS}:{memory_id}",
            digest=digest,
            provenance=labels,
        )
        return mdec, receipt
