"""One-line offline governance wrapper (`drako.govern`).

BEST-EFFORT IN-PROCESS BOUNDARY: `govern()` wraps tool execution hooks inside
the agent's Python process using the offline `drako.kernel.Host`. Code running
inside the same process (for example via unsandboxed RCE) could bypass hooks;
combine in-process adapters with out-of-process controls (`drako proxy`,
`drako-gate` CI checks, and signed Ed25519 receipts) for defense-in-depth.

Unlike v3, v4 `govern()` is 100% offline (zero network / zero API key) and
dispatches to unified `drako.adapters`.
"""

from __future__ import annotations

from typing import Any

from drako.exceptions import ConfigError


def govern(
    obj: Any,
    *,
    host: Any | None = None,
    profile_path: str | None = None,
    framework: str | None = None,
) -> Any:
    """Wrap a supported agent framework object with the Drako Authority Kernel."""
    from drako.adapters import wrap_agent

    if host is None and profile_path is None:
        raise ConfigError(
            "govern() requires either a configured `host` (drako.kernel.Host) or `profile_path` "
            "(an ACS YAML profile). Run `drako init` to generate drako-policy.yaml."
        )
    return wrap_agent(obj, host=host, profile_path=profile_path, framework=framework)
