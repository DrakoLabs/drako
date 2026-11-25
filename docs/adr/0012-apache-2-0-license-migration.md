# ADR-0012: Migration from BUSL-1.1 to Apache-2.0 License

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Drako previously shipped under `BUSL-1.1` (Business Source License, source-available). With v4.0 moving to a fully open, local-first security kernel (ADR-0001), moving to an OSI-approved permissive open-source license removes adoption barriers across three dimensions:

1. **Enterprise & developer procurement:** Security teams routinely restrict non-OSI licenses in CI/CD toolchains and runtime dependencies.
2. **Ecosystem alignment:** Peer agent-security infrastructure ships under permissive OSI licenses — OWASP Agent Control Standard (`Apache-2.0`), `snyk/agent-scan` (`Apache-2.0`), `microsoft/agent-governance-toolkit` (`MIT`), and `shirudo-dev/shirudo` (`BSD-2-Clause`).
3. **Upstream & community collaboration:** Contributing adapters, conformance tests, or policy examples back to OWASP ACS (`Apache-2.0`) is frictionless under a matching permissive license.

## Decision

Relicense `DrakoLabs/drako` from `BUSL-1.1` to **Apache License 2.0 (`Apache-2.0`)** effective with `v4.0.0`, making the entire project 100% open source and free for personal, commercial, and CI/CD use. Update `LICENSE`, `pyproject.toml` (`license = "Apache-2.0"`, OSI classifier), and `README.md`.

## Alternatives Considered

- **Retain `BUSL-1.1`:** Creates legal review friction for enterprise and open-source adopters of a local-first library.
- **Dual-license (Apache core + source-available extensions):** Adds licensing complexity and contributor friction for minimal benefit.

## Consequences

- Frictionless adoption in commercial, enterprise, and CI environments, including explicit patent grant protection (Apache-2.0 Section 3).
- Clean two-way interoperability with OWASP ACS and community contributors.

## Verification

- `LICENSE` contains the canonical Apache License 2.0 text; `pyproject.toml` declares `license = "Apache-2.0"` and `License :: OSI Approved :: Apache Software License`.
