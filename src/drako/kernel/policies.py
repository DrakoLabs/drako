"""ACS-profile policies: YAML in, compiled Guardian profile out.

Profile schema (v1, drako-acs-profile):
  spec_pin: AGENT-HOOKS-0.1        # required, pinned (Q2)
  default_effect: deny             # deny | permit (deny recommended)
  tiers: {read: auto, irreversible: consent}   # anti-fatigue C8
  tools:
    <tool>:
      id: unique rule id
      effect: allow | deny | modify
      reason: human-readable
      conditions: [{id, when: "<closed-grammar expr>", effect}]
      modifications: {...}         # for effect: modify
      approval_liftable: true      # deny + consent seam
"""

from __future__ import annotations

from typing import Any

from drako.kernel import ACS_SPEC_PIN
from drako.kernel.envelope import Guardian
from drako.kernel.eval import UnsafeExpressionError, evaluate_condition


class ProfileError(Exception):
    pass


def compile_profile(doc: dict[str, Any]) -> dict[str, Any]:
    """Validate + normalize an ACS-profile document. Raises ProfileError."""
    if not isinstance(doc, dict):
        raise ProfileError("profile must be a mapping")
    if doc.get("spec_pin") != ACS_SPEC_PIN:
        raise ProfileError(f"spec_pin must be {ACS_SPEC_PIN!r} (Q2 pin)")
    default_effect = doc.get("default_effect", "deny")
    if default_effect not in ("deny", "permit"):
        raise ProfileError("default_effect must be deny|permit")
    tools = doc.get("tools", {})
    if not isinstance(tools, dict):
        raise ProfileError("tools must be a mapping")
    compiled: dict[str, Any] = {}
    for name, rule in tools.items():
        if not isinstance(rule, dict):
            raise ProfileError(f"rule {name!r} must be a mapping")
        effect = rule.get("effect", "deny")
        if effect not in ("allow", "deny", "modify"):
            raise ProfileError(f"rule {name!r}: bad effect {effect!r}")
        # Pre-validate every condition's GRAMMAR now (fail at compile time,
        # never at enforcement time). Unknown *names* are fine here — they
        # resolve against runtime args; only structural violations reject.
        for cond in rule.get("conditions", []):
            try:
                evaluate_condition(cond.get("when", "False"), {})
            except UnsafeExpressionError as e:
                if "Unknown variable" not in str(e):
                    raise ProfileError(f"rule {name!r} condition {cond.get('id')!r}: {e}")
        compiled[name] = {
            "id": rule.get("id", f"rule:{name}"),
            "effect": effect,
            "reason": rule.get("reason", ""),
            "conditions": rule.get("conditions", []),
            "modifications": rule.get("modifications"),
            "approval_liftable": bool(rule.get("approval_liftable", False)),
        }
    return {
        "spec_pin": ACS_SPEC_PIN,
        "default_effect": default_effect,
        "tiers": doc.get("tiers", {"read": "auto", "irreversible": "consent"}),
        "tools": compiled,
    }


def guardian_from_yaml(text: str) -> Guardian:
    import yaml

    return Guardian(compile_profile(yaml.safe_load(text)))
