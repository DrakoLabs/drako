"""Zero-friction runtime entry point (`drako.guard`).

Wraps an agent or tool callable with the offline Authority Kernel in one line,
with zero files written to disk unless `receipts=` is explicitly configured.

Example:
    from drako import guard

    agent = guard(my_agent, allow=["search_*"], deny=["delete_*"])
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from drako.exceptions import ConfigError
from drako.kernel import ACS_SPEC_PIN
from drako.kernel.envelope import Guardian
from drako.kernel.host import Host, HostConfig
from drako.kernel.policies import compile_profile, guardian_from_yaml
from drako.kernel.receipts import generate_keypair


def _build_inline_profile(
    *,
    allow: Sequence[str] | None,
    deny: Sequence[str] | None,
    approval_required: Sequence[str] | None,
    default: Literal["deny", "allow"],
) -> dict[str, Any]:
    if default not in ("deny", "allow"):
        raise ConfigError(f"guard() default must be 'deny' or 'allow', got {default!r}")

    tools: dict[str, dict[str, Any]] = {}
    for pattern in allow or ():
        tools[str(pattern)] = {"id": f"guard:allow:{pattern}", "effect": "allow"}
    for pattern in approval_required or ():
        tools[str(pattern)] = {
            "id": f"guard:approval:{pattern}",
            "effect": "deny",
            "approval_liftable": True,
            "reason": f"approval required for {pattern}",
        }
    # Explicit deny overrides allow/approval on identical pattern (fail-closed)
    for pattern in deny or ():
        tools[str(pattern)] = {
            "id": f"guard:deny:{pattern}",
            "effect": "deny",
            "reason": f"denied by guard policy ({pattern})",
        }

    return compile_profile(
        {
            "spec_pin": ACS_SPEC_PIN,
            "default_effect": default,
            "tools": tools,
        }
    )


def build_host(
    *,
    allow: Sequence[str] | None = None,
    deny: Sequence[str] | None = None,
    approval_required: Sequence[str] | None = None,
    default: Literal["deny", "allow"] = "deny",
    profile: str | Path | dict[str, Any] | None = None,
    agent_id: str = "default-agent",
    receipts: str | Path | None = None,
    private_pem: str | None = None,
    public_pem: str | None = None,
    operator_public_pem: str | None = None,
    enable_loop_breaker: bool = True,
) -> Host:
    """Build a ready-to-use offline `Host` with zero disk I/O by default."""
    if profile is not None:
        if isinstance(profile, (str, Path)):
            p = Path(profile)
            if not p.exists():
                raise ConfigError(f"ACS policy profile not found: {p}")
            guardian = guardian_from_yaml(
                p.read_text(encoding="utf-8"),
                operator_public_pem=operator_public_pem,
            )
        elif isinstance(profile, dict):
            compiled = (
                profile
                if profile.get("spec_pin") == ACS_SPEC_PIN and isinstance(profile.get("tools"), dict)
                else compile_profile(profile)
            )
            guardian = Guardian(compiled, operator_public_pem=operator_public_pem)
        else:
            raise ConfigError(f"Unsupported profile type: {type(profile).__name__}")
    else:
        compiled = _build_inline_profile(
            allow=allow,
            deny=deny,
            approval_required=approval_required,
            default=default,
        )
        guardian = Guardian(compiled, operator_public_pem=operator_public_pem)

    priv, pub = private_pem, public_pem
    if receipts is not None and (priv is None or pub is None):
        priv, pub = generate_keypair()

    cfg = HostConfig(
        agent_id=agent_id,
        store_path=str(receipts) if receipts is not None else None,
        private_pem=priv,
        public_pem=pub,
        operator_public_pem=operator_public_pem,
        enable_loop_breaker=enable_loop_breaker,
    )
    return Host(guardian, cfg)


def guard(
    target: Any,
    *,
    allow: Sequence[str] | None = None,
    deny: Sequence[str] | None = None,
    approval_required: Sequence[str] | None = None,
    default: Literal["deny", "allow"] = "deny",
    profile: str | Path | dict[str, Any] | None = None,
    host: Host | None = None,
    framework: str | None = None,
    agent_id: str = "default-agent",
    receipts: str | Path | None = None,
    private_pem: str | None = None,
    public_pem: str | None = None,
    operator_public_pem: str | None = None,
    enable_loop_breaker: bool = True,
) -> Any:
    """Wrap an agent or tool callable with the offline Authority Kernel.

    Fail-closed by default (`default="deny"`), purely in-memory unless
    `receipts=` is supplied. Supports glob patterns in `allow`/`deny`.
    """
    from drako.adapters import wrap_agent

    resolved_host = host or build_host(
        allow=allow,
        deny=deny,
        approval_required=approval_required,
        default=default,
        profile=profile,
        agent_id=agent_id,
        receipts=receipts,
        private_pem=private_pem,
        public_pem=public_pem,
        operator_public_pem=operator_public_pem,
        enable_loop_breaker=enable_loop_breaker,
    )
    wrapped = wrap_agent(target, host=resolved_host, framework=framework)
    with contextlib.suppress(AttributeError, TypeError):
        wrapped.drako_host = resolved_host
    return wrapped
