"""Runaway loop circuit-breaker (OWASP ASI08/ASI10, ADR-0010).

Failure-based breakers never trip when an agent repeats the IDENTICAL call
hundreds of times and every call succeeds (Denial-of-Wallet camouflage).
This breaker counts REPETITION inside a rolling window: N identical
(tool, args-hash) invocations escalate to operator approval; while tripped,
identical calls deny fast without spamming approvals.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger("drako.kernel.loop_breaker")

TRIP_THRESHOLD = 10
WINDOW_SECONDS = 300.0


@dataclass
class _KeyState:
    uses: list[float] = field(default_factory=list)
    approval_open: bool = False


@dataclass(frozen=True)
class LoopVerdict:
    action: str  # "ok" | "escalate" | "deny_tripped"
    count: int
    key: str


def call_fingerprint(*parts: object) -> str:
    """Stable hash of a call's identity (tool/args/endpoint)."""
    blob = json.dumps(
        [str(p) for p in parts], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


class LoopBreaker:
    """Thread-safe, process-local repetition circuit breaker."""

    def __init__(
        self,
        *,
        trip_threshold: int = TRIP_THRESHOLD,
        window_seconds: float = WINDOW_SECONDS,
    ) -> None:
        if trip_threshold < 1:
            raise ValueError("trip_threshold must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.trip_threshold = trip_threshold
        self.window_seconds = window_seconds
        self._states: dict[str, _KeyState] = {}
        self._lock = threading.Lock()

    def record(self, agent_id: str, call_hash: str, *, session_id: str = "") -> LoopVerdict:
        """Record one invocation and return ok / escalate / deny_tripped."""
        key = f"{session_id}|{agent_id}|{call_hash}"
        now = time.monotonic()
        with self._lock:
            state = self._states.setdefault(key, _KeyState())
            state.uses = [t for t in state.uses if now - t < self.window_seconds]
            state.uses.append(now)
            count = len(state.uses)
            if count < self.trip_threshold:
                return LoopVerdict("ok", count, key)
            if not state.approval_open:
                state.approval_open = True
                logger.error(
                    "AUDIT runaway-loop TRIPPED session=%s agent=%s uses=%d/%ds — escalating",
                    session_id,
                    agent_id,
                    count,
                    int(self.window_seconds),
                )
                return LoopVerdict("escalate", count, key)
            logger.warning(
                "AUDIT runaway-loop DENY (tripped) session=%s agent=%s",
                session_id,
                agent_id,
            )
            return LoopVerdict("deny_tripped", count, key)

    def approve(self, key: str) -> None:
        """Operator approved continuing the loop: reset counter."""
        with self._lock:
            self._states.pop(key, None)
        logger.info("AUDIT runaway-loop APPROVED key=%s (counter reset)", key[:24])

    def reset(self) -> None:
        with self._lock:
            self._states.clear()


_DEFAULT_BREAKER = LoopBreaker()


def reset_for_tests() -> None:
    _DEFAULT_BREAKER.reset()


def record(session_id: str | None, agent_id: str, call_hash: str) -> LoopVerdict:
    return _DEFAULT_BREAKER.record(agent_id, call_hash, session_id=session_id or "")


def approve(key: str) -> None:
    _DEFAULT_BREAKER.approve(key)
