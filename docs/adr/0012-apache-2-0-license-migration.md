# ADR-0012: Migration from BUSL-1.1 to Apache-2.0 License

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

In September 2026, `drako` adopted `BUSL-1.1` (Business Source License) solely to prevent commercial cloning of a planned managed SaaS backend (`agentmesh-backend`). With the permanent retirement of the SaaS backend (ADR-0001), retaining a source-available license creates three major liabilities with zero offsetting benefit:

1. **Enterprise & developer procurement friction:** Security teams routinely block non-OSI licenses in CI/CD toolchains and runtime dependencies.
2. **Ecosystem misalignment in Q4 2026:** Every peer infrastructure security project ships under a permissive OSI license — OWASP Agent Control Standard (`Apache-2.0`), `snyk/agent-scan` (`Apache-2.0`), `microsoft/agent-governance-toolkit` (`MIT`), and OpenAI/Cisco `shirudo-dev/shirudo` (`BSD-2-Clause`, Nov 2026).
3. **Upstream contribution hygiene:** Contributing Guardian samples or adapters back to OWASP ACS (`Apache-2.0`) required awkward per-file license splits under BUSL.

## Decision

Relicense `DrakoLabs/drako` from `BUSL-1.1` to **Apache License 2.0 (`Apache-2.0`)** effective with `v4.0.0`, updating `LICENSE`, `pyproject.toml` (`license = "Apache-2.0"`, OSI classifier), and `README.md`.

## Alternatives Considered

- **Retain `BUSL-1.1`:** Protects a SaaS product that no longer exists while penalizing open-source adoption.
- **Dual-license (Apache core + BUSL advanced):** Adds REUSE/SPDX maintenance overhead without a commercial control plane to protect.

## Consequences

- Frictionless adoption in commercial, enterprise, and CI environments, including explicit patent grant protection (Apache-2.0 Section 3).
- Clean two-way interoperability with OWASP ACS and community contributors.

## Verification

- `LICENSE` contains the canonical Apache License 2.0 text; `pyproject.toml` declares `license = "Apache-2.0"` and `License :: OSI Approved :: Apache Software License`.
