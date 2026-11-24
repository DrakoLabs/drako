# OWASP 2026 Threat-Model Mapping (Drako v4.0)

> Canonical references:
> - [OWASP Top 10 for Agentic Applications 2026 (`ASI01–ASI10`)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
> - [OWASP GenAI LLM Top 10 2026 (`LLM01–LLM10`)](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
>
> Boundary rule: model-as-component risks map to the **LLM Top 10**; the moment the model becomes an **actor** (tools, persistent memory, MCP/A2A delegation, downstream side effects), risks map to the **Agentic Top 10 (`ASI`)**. Drako uses `ASI01–ASI10` as its primary threat-model index.

---

## 1. OWASP Top 10 for Agentic Applications (2026)

| ID | Risk | Drako v4 Coverage | Surface / Module |
|---|---|---|---|
| **ASI01** | Agent Goal Hijack | Origin-bound authority lattice (tool outputs cannot assert `USER` trust) + instruction override detection (`INST-001`) + static `SEC-010` | `kernel/authority.py`, `desktop/instruction_rules.py`, `cli/policies/security.py` |
| **ASI02** | Tool Misuse & Exploitation | Single chokepoint `Guardian` (Progent-style closed AST conditions, `modify` + T-5 re-govern) + `INST-004` + static `ODD-*` / `FW-*` | `kernel/envelope.py`, `adapters/base.py`, `desktop/instruction_rules.py` |
| **ASI03** | Identity & Privilege Abuse | Operator-signed `ConsentToken` (Ed25519 + `args_hash` anti-TOCTOU) + `OriginAttester` + static `ID-001..003` | `kernel/authority.py`, `cli/kernel_command.py`, `cli/policies/identity.py` |
| **ASI04** | Agentic Supply Chain Vulnerabilities | `mcp.lock` SHA-512 hash-pinning + `drako mcp audit` + `tools/list` runtime drift (*Deadbugz*) + CycloneDX 1.7 AgBOM + `INST-002`/`INST-005` | `mcp_guard/{lock,admission,drift,agbom,audit}.py`, `desktop/instruction_rules.py` |
| **ASI05** | Unexpected Code Execution (RCE) | Static AST detection (`SEC-005`, `FW-AUTOGEN-*`), `INST-003` pipe-to-shell rules, closed AST condition evaluator (zero `eval()`). *Gap owned: no OS/container sandbox; pair with gVisor/containers.* | `kernel/eval.py`, `cli/policies/security.py`, `desktop/instruction_rules.py` |
| **ASI06** | Memory & Context Poisoning | Dedicated `memory_write` side-effect class requiring non-empty origin, bounded unexpired TTL, and `>= AGENT` lattice floor (regressed against MPBench) | `kernel/memory_gate.py`, `kernel/host.py` |
| **ASI07** | Insecure Inter-Agent Communication | A2A v1.0 RFC 7515 Detached JWS (EdDSA) + RFC 8785 JCS Signed Agent Cards (`drako a2a sign/verify`) + SSRF egress guard + static `A2A-001..003` | `a2a/cards.py`, `kernel/egress.py`, `cli/policies/a2a.py` |
| **ASI08** | Cascading Failures | Repetition `LoopBreaker` (`kernel:loop-breaker`) + `drako drift` (ATLAS Scope Drift) + static `RES-*` / `MULTI-*` | `kernel/loop_breaker.py`, `kernel/drift.py`, `proxy/proxy_server.py` |
| **ASI09** | Human-Agent Trust Exploitation | Anti-fatigue side-effect tiering (`read` auto, `irreversible` requires operator-signed `ConsentToken` bound to exact JCS `args_hash`) + `drako why` provenance subgraph | `kernel/authority.py`, `kernel/envelope.py`, `cli/why_command.py` |
| **ASI10** | Rogue Agents | Repetition circuit-breaker (`LoopBreaker`), fail-closed `default_effect: deny`, tamper-evident Ed25519 hash-chained receipts (`drako verify`) | `kernel/host.py`, `kernel/loop_breaker.py`, `kernel/receipts.py` |

---

## 2. OWASP LLM Top 10 (2026)

| ID | Risk | Drako v4 Coverage |
|---|---|---|
| **LLM01** | Prompt Injection (incl. cross-modal) | Blast-radius containment via `authority.py` + `SEC-010` + `INST-001` + `mcp_guard/drift.py` |
| **LLM03** | Excessive Agency | `Guardian` fail-closed default, side-effect tiers, operator `ConsentToken`, `LoopBreaker`, `ODD-*` / `MAG-*` |
| **LLM07** | Misinformation | *Detection-light gap owned openly* — static guidance only; Drako does not run LLM fact-checking in the loop |
| **LLM08** | Hidden Context Exposure | Proxy DLP checks, `INST-002` secret exfil rules, prompt-hash-only BOM (`drako bom`) |
| **LLM09** | Vector & Embedding Weaknesses | `kernel/memory_gate.py` provenance + mandatory TTL on every write |
| **LLM10** | Improper Output Handling | *Detection-light gap owned openly* — flagged statically where applicable; runtime output escaping belongs to the consumer sink |
