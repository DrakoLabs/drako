# ADR-0005: Standards Alignment — OWASP 2026, OWASP ACS (`AGENT-HOOKS-0.1`) & MITRE ATLAS

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

In late 2026, enterprise AI security converged around three open vendor-neutral anchors:
- **OWASP Top 10 for Agentic Applications 2026 (`ASI01–ASI10`)** + **OWASP LLM Top 10 2026 (`LLM01–LLM10`)**, shifting from prompt-only filtering to **Least Agency** and blast-radius control.
- **OWASP Agent Control Standard (ACS)** and the **`AGENT-HOOKS-0.1`** conformance test kit (`agent-hooks-sdk`), standardizing framework-neutral runtime interception (`allow` / `deny` / `transform`).
- **MITRE ATLAS v2026.08**, which codified **AI Agent Scope Drift Detection** as a first-class mitigation.

## Decision

1. **Adopt `ASI01–ASI10` as Drako's threat-model index** alongside verified `LLM01–LLM10:2026` mappings in `docs/owasp-2026-mapping.md`, explicitly owning current detection-light gaps (`LLM07`, `LLM10`).
2. **Pin ACS specification & CTK (`Q2`):** Pin `ACS_SPEC_PIN = "AGENT-HOOKS-0.1"` and `CTK_PIN = "agent-hooks-sdk==0.1.0a5"` in `drako.kernel`, and publish formal conformance declarations in `conformance/CLAIMS.md` and `conformance/declared_surface.json` (*44/44 applicable vectors passing, 3 capability-gated skips, 0 failures*).
3. **Implement Scope Drift Detection (`drako.kernel.drift` + `drako drift`):** Compare static `drako scan` baselines against effective Guardian ACS profiles, failing CI on `uncovered`, `widened`, or `flipped` capabilities.
4. **No proprietary dialect:** Policy profiles compile standard ACS YAML structures; advisories remain extensions over SLSA/in-toto rather than competing standards.

## Alternatives Considered

- **Maintain Drako-specific ABSS as a standalone standard:** Risks ecosystem fragmentation and vendor-lock-in friction.

## Consequences

- Upstream standard revisions will require explicit pin bumps and CTK re-verification in CI.
- Gives users vendor-neutral portability aligned with Drako's own `VCR-*` anti-lock-in rules.

## Verification

- `tests/test_kernel_ctk.py` (44 passed, 3 skipped, 0 failed), `tests/test_kernel_drift.py`, and `docs/owasp-2026-mapping.md`.
