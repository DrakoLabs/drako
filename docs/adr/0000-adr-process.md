# ADR-0000: Architecture Decision Records Process

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Drako v4.0 consolidates a previously split open-core architecture (a private SaaS monorepo plus a public CLI mirror) into a single, lean, local-first security kernel repository (`DrakoLabs/drako`). Without written decision records, security invariants, deliberate non-goals, and pruned surfaces get forgotten or silently re-introduced.

## Decision

All material architectural, security, cryptographic, protocol, licensing, and scope decisions in `DrakoLabs/drako` are tracked as numbered Markdown files under `docs/adr/NNNN-short-title.md` following a lightweight MADR structure:

1. **Status & Date** (`Proposed`, `Accepted`, `Deprecated`, or `Superseded by ADR-XXXX`).
2. **Context** — the technical problem, threat model, or ecosystem standard driving the change.
3. **Decision** — the concrete, enforceable design choice.
4. **Alternatives Considered** — rejected options and why.
5. **Consequences** — trade-offs, residual limitations, and maintenance impact.
6. **Verification** — exact tests, CI gates, or invariants proving the decision holds in code.

Once an ADR reaches `Accepted`, its historical text is not rewritten to hide past decisions; changes create a new ADR that marks the prior one `Superseded by ADR-XXXX`.

## Alternatives Considered

- **Wiki or private notes only:** Splits architectural rationale away from code review and contributors.
- **No formal process:** Led directly to documentation drift, duplicated implementations, and conflicting claims across v2–v3.

## Consequences

- Every major module or removal in v4.0 is auditable directly in git history alongside its tests.
- Contributors and security reviewers can verify *why* boundaries exist (and what is explicitly out of scope).

## Verification

- `docs/adr/README.md` indexes every `docs/adr/[0-9][0-9][0-9][0-9]-*.md` file and is checked in CI.
