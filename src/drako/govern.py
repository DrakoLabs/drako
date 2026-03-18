"""One-line governance wrapper for any supported framework.

Usage:
    from drako import govern

    crew = govern(crew)          # CrewAI
    graph = govern(graph)        # LangGraph
    chat = govern(group_chat)    # AutoGen

If no `.drako.yaml` or `DRAKO_API_KEY` is found, the object
is returned unchanged with a warning — govern() never crashes.
"""

from __future__ import annotations

import os
from pathlib import Path


def _find_config(start: str | None = None) -> str | None:
    """Walk up from *start* looking for `.drako.yaml`."""
    current = Path(start) if start else Path.cwd()
    for parent in [current, *current.parents]:
        candidate = parent / ".drako.yaml"
        if candidate.is_file():
            return str(candidate)
    return None


def govern(obj, *, config_path: str | None = None, framework: str | None = None):
    """Wrap a framework object with Drako governance middleware.

    Args:
        obj: A CrewAI Crew, LangGraph compiled graph, or AutoGen GroupChat.
        config_path: Explicit path to `.drako.yaml`. If omitted, walks
            up from cwd looking for the file.
        framework: Override auto-detection (``"crewai"``, ``"langgraph"``,
            ``"autogen"``).

    Returns:
        The wrapped object, or the original *obj* unchanged if no config
        is found or the framework is unrecognized.
    """
    try:
        return _govern_inner(obj, config_path=config_path, framework=framework)
    except Exception as exc:  # noqa: BLE001 — govern() must never crash
        try:
            from drako.utils.logger import log
            log.warning("Drako: govern() failed (%s), running ungoverned", exc)
        except Exception:
            pass
        return obj


def _govern_inner(obj, *, config_path: str | None = None, framework: str | None = None):
    """Internal implementation — may raise."""
    from drako.utils.logger import log

    # 1. Resolve config
    path = config_path or _find_config()
    has_env_key = bool(os.environ.get("DRAKO_API_KEY"))

    if not path and not has_env_key:
        log.warning("Drako: no config found, running ungoverned")
        return obj

    # 2. Detect framework from object type
    fw = framework
    if not fw:
        if hasattr(obj, "kickoff"):
            fw = "crewai"
        elif hasattr(obj, "invoke") or hasattr(obj, "stream"):
            fw = "langgraph"
        elif hasattr(obj, "groupchat"):
            fw = "autogen"

    if not fw:
        log.warning("Drako: unrecognized framework object (%s), running ungoverned", type(obj).__name__)
        return obj

    # 3. Build kwargs
    kwargs: dict = {}
    if path:
        kwargs["config_path"] = path

    # 4. Delegate to framework-specific wrapper
    if fw == "crewai":
        from drako.middleware.crewai import with_compliance
        return with_compliance(obj, **kwargs)
    elif fw == "langgraph":
        from drako.middleware.langgraph import with_langgraph_compliance
        return with_langgraph_compliance(obj, **kwargs)
    elif fw == "autogen":
        from drako.middleware.autogen import with_autogen_compliance
        return with_autogen_compliance(obj, **kwargs)
    else:
        log.warning("Drako: unsupported framework '%s', running ungoverned", fw)
        return obj
