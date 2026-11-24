"""Scope-drift detection: scan baseline vs effective authority (T6).

Maps to ATLAS v2026.08 *Scope Drift Detection*: the permissions an agent
EFFECTIVELY holds at runtime (Guardian profile: tool effects +
default_effect + granted scopes) drift away from what the last `drako
scan` baseline recorded. Drift is how "governed in CI, feral in prod"
happens — a tool added without a scan, a finding nobody wired into the
profile, an effect flipped by a config push.

Pure function, offline, no network. Consumers: CI gates (fail on
`widened`/`flipped`), `drako-gate` action, periodic re-scan jobs.
Kinds:

- uncovered: baseline finding with NO runtime enforcement (the scan
  fired, but the profile neither gates the tool nor records the rule —
  the finding is decorative).
- widened: effective authority grants a capability ABSENT from the
  baseline (new tool/scope since the scan — re-scan required).
- flipped: same capability, different enforcement detail (effect or
  conditions changed under the baseline's feet).
- stale: baseline metadata older than max_age_days (informational —
  drift detection itself degrades with stale input; honest about it).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class AuthorityEntry:
    """One capability, from EITHER side. Same shape, two provenances."""

    id: str      # tool name ("web_search") or rule id ("SEC-010")
    kind: str    # "tool" | "finding"
    detail: str  # effect ("allow:..." / "deny") or severity+title


@dataclass(frozen=True)
class DriftItem:
    kind: str  # "uncovered" | "widened" | "flipped" | "stale"
    id: str
    message: str


@dataclass
class DriftReport:
    items: list[DriftItem] = field(default_factory=list)

    @property
    def blocking(self) -> list[DriftItem]:
        """Drift that should fail a gate (stale is advisory only)."""
        return [i for i in self.items if i.kind in ("uncovered", "widened", "flipped")]

    @property
    def clean(self) -> bool:
        return not self.blocking


def _norm(detail: str) -> str:
    return " ".join(detail.strip().lower().split())


def detect_drift(
    baseline: Sequence[AuthorityEntry],
    effective: Sequence[AuthorityEntry],
    baseline_issued_at: str | None = None,
    max_age_days: int = 30,
    now: datetime | None = None,
) -> DriftReport:
    """Compare baseline vs effective authority. Deny-closed on confusion.

    Matching is by (kind, id). Findings are matched against tools by a
    documented convention: a finding uncovers when NEITHER its own rule
    id NOR its `for_tool` suffix appears effectively — callers encode
    the tool as 'RULE_ID@tool' detail when known. Unknown shapes widen,
    never silently pass.
    """
    report = DriftReport()
    eff_by_key = {(e.kind, e.id): e for e in effective}
    base_by_key = {(b.kind, b.id): b for b in baseline}

    for b in baseline:
        match = eff_by_key.get((b.kind, b.id))
        if match is None:
            if b.kind == "finding":
                # A fired rule with zero runtime counterpart.
                report.items.append(DriftItem(
                    "uncovered", b.id,
                    f"baseline finding {b.id} ({b.detail}) has no effective "
                    "enforcement — wire it into the profile or accept the gap",
                ))
            else:
                report.items.append(DriftItem(
                    "widened", b.id,
                    f"baseline capability {b.id} vanished from effective "
                    "authority — removal or profile regression",
                ))
        elif _norm(match.detail) != _norm(b.detail):
            report.items.append(DriftItem(
                "flipped", b.id,
                f"{b.id}: baseline {b.detail!r} → effective {match.detail!r}",
            ))

    for e in effective:
        if (e.kind, e.id) not in base_by_key:
            report.items.append(DriftItem(
                "widened", e.id,
                f"effective authority grants {e.kind} {e.id} "
                f"({e.detail}) absent from baseline — re-scan required",
            ))

    if baseline_issued_at:
        try:
            normalized = (
                baseline_issued_at[:-1] + "+00:00"
                if baseline_issued_at.endswith("Z")
                else baseline_issued_at
            )
            issued = datetime.fromisoformat(normalized)
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=timezone.utc)
            age_days = ((now or datetime.now(timezone.utc)) - issued).days
            if age_days > max_age_days:
                report.items.append(DriftItem(
                    "stale", "(baseline)",
                    f"baseline is {age_days}d old (>{max_age_days}d) — "
                    "drift signal degrades with stale input",
                ))
        except ValueError:
            report.items.append(DriftItem(
                "stale", "(baseline)",
                "baseline timestamp unparseable — treat drift as advisory",
            ))
    return report
