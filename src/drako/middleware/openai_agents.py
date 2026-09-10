"""OpenAI Agents SDK compliance guardrails (F-1, Sprint 2).

Verified against openai-agents-python: Agent(input_guardrails=[...],
output_guardrails=[...]); guardrail functions receive
(RunContextWrapper, Agent, input) and return GuardrailFunctionOutput
with tripwire_triggered; @input_guardrail / @output_guardrail
decorators build them. This module never imports `agents` at top level
(optional dependency): the Drako check itself is a pure callable, and
the native guardrail is assembled lazily.
"""

from __future__ import annotations

from typing import Any, Callable


def drako_tripwire(check_text: Callable[[str], bool], user_input: Any) -> bool:
    """Pure verdict (testable): True means BLOCK (trip the wire)."""
    try:
        text = user_input if isinstance(user_input, str) else str(user_input)
    except Exception:
        return True  # unrenderable input fails closed
    try:
        return bool(check_text(text))
    except Exception:
        return True  # checker failure fails closed


def make_drako_input_guardrail(
    check_text: Callable[[str], bool],
    *,
    output_info: Any = None,
):
    """Build a NATIVE @input_guardrail backed by a Drako check (lazy).

    check_text(text) -> True means block. Raises an informative
    ImportError when the `agents` package is not installed instead of
    silently running unguarded.
    """
    try:
        from agents import GuardrailFunctionOutput, input_guardrail
    except ImportError:
        raise ImportError(
            "drako[openai-agents] requires the 'openai-agents' package "
            "(pip install openai-agents) — refusing to run unguarded"
        )

    @input_guardrail
    async def _drako_guardrail(ctx: Any, agent: Any, input: Any) -> Any:
        return GuardrailFunctionOutput(
            output_info=output_info or {"drako": "input-guardrail"},
            tripwire_triggered=drako_tripwire(check_text, input),
        )

    return _drako_guardrail


def make_drako_output_guardrail(
    check_text: Callable[[str], bool],
    *,
    output_info: Any = None,
):
    """Build a NATIVE @output_guardrail backed by a Drako check (lazy)."""
    try:
        from agents import GuardrailFunctionOutput, output_guardrail
    except ImportError:
        raise ImportError(
            "drako[openai-agents] requires the 'openai-agents' package "
            "(pip install openai-agents) — refusing to run unguarded"
        )

    @output_guardrail
    async def _drako_guardrail(ctx: Any, agent: Any, output: Any) -> Any:
        return GuardrailFunctionOutput(
            output_info=output_info or {"drako": "output-guardrail"},
            tripwire_triggered=drako_tripwire(check_text, output),
        )

    return _drako_guardrail
