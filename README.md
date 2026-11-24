<div align="center">
  <h1>Drako 🐉</h1>
  <p><strong>The Portable Authority Kernel for AI Agents.</strong></p>
  <p>
    <em>Every action answers. Receipts, not logs.</em><br />
    Deterministic governance, origin-bound authority lattice, memory firewall, MCP/A2A guards,
    and offline-verifiable Ed25519 receipts.<br />
    <strong>100% local-first. Zero LLM in the loop. Zero API keys. Apache-2.0.</strong>
  </p>
  <p>
    <a href="https://pypi.org/project/drako/"><img src="https://img.shields.io/pypi/v/drako?style=flat-square&color=3776AB&logo=pypi&logoColor=white" alt="PyPI"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=yellow" alt="Python 3.10+"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-2ea44f.svg?style=flat-square" alt="License: Apache-2.0"></a>
    <a href="conformance/CLAIMS.md"><img src="https://img.shields.io/badge/ACS-AGENT--HOOKS--0.1%20(44%2F44)-6366F1.svg?style=flat-square" alt="AGENT-HOOKS-0.1"></a>
    <img src="https://img.shields.io/badge/AST%20rules-82%20(99%20checks)-6366F1.svg?style=flat-square" alt="82 rules / 99 checks">
  </p>
</div>

```bash
pip install --pre drako && drako scan .
```

> `drako scan .` is **100% read-only** by default — zero files created, zero `.gitignore` edits, zero network calls. *(v4.0 is currently in alpha: `4.0.0a1`.)*

---

## Why Drako v4?

Traditional guardrails try to build a model that cannot be fooled. **Drako assumes the model will be fooled** — and constrains what an untrusted input is allowed to authorize while minting a cryptographically signed **Receipt** for every decision.

### The Authority Charter
1. **Fooled is expected. Unauthorized is impossible** *(within the kernel boundary — property-tested non-malleability)*.
2. **Provenance travels with data; authority travels with intent.** Tool outputs (`tool:*`) can never assert `USER` trust.
3. **AI proposes, human signs.** Irreversible actions require an operator-signed Ed25519 `ConsentToken` bound to the canonical `args_hash` (anti-TOCTOU). Operator private keys never need to touch target agent runtimes.
4. **Every action answers.** Every `permit`, `deny`, or `modify` mints a hash-chained, Ed25519-signed `drako-receipt/v1` verifiable offline (`drako verify`) and queryable as a provenance graph (`drako why`).
5. **Open standards, zero vendor lock-in.** Aligned with **OWASP Agentic Top 10 (2026, `ASI01–ASI10`)**, **OWASP LLM Top 10 (2026)**, **OWASP ACS (`AGENT-HOOKS-0.1`)**, **MITRE ATLAS Scope Drift**, **MCP `2026-07-28` GA**, **A2A v1.0 RFC 7515 JWS**, and **CycloneDX 1.7 (ECMA-424)**.

---

## 5-Minute Quickstart (100% Offline)

```bash
# 1. Bootstrap: scan codebase (82 unique AST rules / 99 Python+TS checks) + Agent BOM
drako scan . --baseline
drako bom . --format cyclonedx > agent-bom.cdx.json

# 2. Scan coding-agent instruction & skill files (SKILL.md, CLAUDE.md, AGENTS.md, .cursor/rules)
drako desktop skills . --fail-on high

# 3. Initialize local .drako.yaml + ACS policy profile (pinned to AGENT-HOOKS-0.1)
drako init --level balanced

# 4. Audit MCP server configs & generate CycloneDX 1.7 AgBOM from mcp.lock
drako mcp audit
drako mcp pin @modelcontextprotocol/server-filesystem@1.2.3 --by alice
drako mcp agbom --format cyclonedx > agbom.cdx.json

# 5. Generate operator Ed25519 keys (keep private key off target agent nodes)
drako kernel keygen --out-dir .drako/keys --name operator

# 6. Verify scope drift, hermetic benchmarks, and signed receipts offline
drako drift
drako kernel bench --iterations 200
drako verify .drako/receipts.jsonl --pubkey-file .drako/keys/operator.pub
drako why <receipt_id> --pubkey-file .drako/keys/operator.pub
```

---

## Runtime Authority Kernel in Python

### One-Line Guard (Zero Disk I/O, Fail-Closed)

```python
from drako import guard

# Fail-closed by default; supports glob patterns across LangGraph, OpenAI Agents,
# Claude Agent SDK, MAF, ADK, CrewAI, or plain Python tool callables.
agent = guard(my_agent, allow=["search_*"], deny=["delete_*"])
```

### Explicit Host, Memory Firewall & Ed25519 Receipts

```python
from drako.kernel import ACS_SPEC_PIN
from drako.kernel.authority import Label, TrustLevel
from drako.kernel.envelope import Guardian
from drako.kernel.host import Host, HostConfig
from drako.kernel.receipts import generate_keypair, verify_receipt

priv, pub = generate_keypair()
profile = {
    "spec_pin": ACS_SPEC_PIN,
    "default_effect": "deny",
    "tools": {
        "search_docs": {"id": "rule:search", "effect": "allow"},
        "delete_volume": {"id": "rule:delete", "effect": "deny", "approval_liftable": True},
    },
}

host = Host(
    Guardian(profile),
    HostConfig(agent_id="research-bot", store_path=".drako/receipts.jsonl", private_pem=priv, public_pem=pub),
)

# Tool output is capped at TOOL trust; cannot authorize irreversible side effects
decision, receipt = host.govern_tool_call(
    "search_docs",
    {"q": "owasp asi06"},
    provenance=[Label("user:prompt", TrustLevel.USER, frozenset({"read"}))],
    side_effect_class="read",
)
assert decision.verdict == "permit" and verify_receipt(receipt, pub)

# Memory Firewall (OWASP ASI06): denies sourceless, immortal, or tool-laundered writes
mem_decision, mem_receipt = host.govern_memory_write(
    "session-memory",
    [Label("memory:verified", TrustLevel.AGENT, frozenset({"memory_write"}), ttl_seconds=3600)],
)
```

### Unified Offline Framework Adapters
All adapters translate framework calls directly into `drako.kernel.Host` with zero external network dependencies and enforce the **T-5 re-govern-after-modify + loop-guard** invariant:

| Framework | Module | Integration Surface |
|---|---|---|
| **LangGraph** | `drako.adapters.langgraph` | `wrap_tool_node(node_fn, host)` |
| **OpenAI Agents SDK** | `drako.adapters.openai_agents` | `wrap_openai_agent(agent, host)` |
| **Microsoft Agent Framework** | `drako.adapters.maf` | `wrap_maf_agent(agent, host)` *(Agent Hooks boundary)* |
| **Claude Agent SDK** | `drako.adapters.claude_agent` | `wrap_claude_agent(options, host)` *(`PreToolUse` hook)* |
| **Google ADK** | `drako.adapters.google_adk` | `wrap_adk_agent(agent, host)` *(`before_tool_callback`)* |
| **CrewAI** | `drako.adapters.crewai` | `wrap_crew(crew, host)` |
| **Local HTTP Proxy** | `drako proxy start` | Loopback `127.0.0.1:8990`, `LoopBreaker`, `egress`, optional `Host` |

---

## Protocol & Supply-Chain Security (Q4 2026)

| Capability | Command / Module | Standard / Threat Covered |
|---|---|---|
| **Static AST Governance** | `drako scan .` | **82 unique rules (99 checks: 82 Python + 17 TypeScript)** across 16 categories |
| **Skill & Instruction Scanner** | `drako desktop skills .` | **`INST-001..005`** for `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/*.mdc` (`ASI01`/`ASI04`/`ASI05`) |
| **MCP Supply-Chain & Drift** | `drako mcp {audit, pin, agbom, check-drift}` | `mcp.lock` SHA-512 pinning, mid-session `tools/list` drift (*Deadbugz*), **CycloneDX 1.7 (ECMA-424)**, **MCP `2026-07-28` GA** stateless client |
| **A2A v1.0 Signed Agent Cards** | `drako a2a {sign, verify, inspect}` | **RFC 7515 Detached JWS (EdDSA) + RFC 8785 JCS** (`ASI07`) |
| **Memory Firewall** | `drako.kernel.memory_gate` | Mandatory origin + bounded TTL + `AGENT` floor regressed against **MPBench** (`ASI06`) |
| **Runaway Loop Breaker** | `drako.kernel.loop_breaker` | Repetition-based circuit breaker stopping Denial-of-Wallet loops (`ASI08`/`ASI10`) |
| **SSRF Egress Guard** | `drako.kernel.egress` | Fail-closed public-IP + per-hop redirect validation (`ToolHive` class) |
| **ACS CTK Conformance** | `conformance/CLAIMS.md` | **Conformant on declared surface (`AGENT-HOOKS-0.1`: 44/44 applicable, 3 capability-gated skips, 0 failures)** |
| **EU AI Act Pack (`[comply]`)** | `drako comply` | Digital Omnibus schedule (**Art. 50** active Aug 2, 2026 / watermarking grace ends Dec 2, 2026; **Annex III High-Risk** Dec 2, 2027; **Annex I** Aug 2, 2028) + local Ed25519 receipts for **Art. 12** |

---

## Optional Extras

```bash
pip install "drako[guardian]"     # AGENT-HOOKS-0.1 CTK + Rust JCS canonicalizer
pip install "drako[proxy]"        # Local loopback HTTP/LLM proxy (FastAPI + Uvicorn)
pip install "drako[typescript]"   # Tree-sitter TypeScript/JavaScript AST scanner
pip install "drako[comply]"       # EU AI Act DOCX/PDF pack generation
```

---

## Documentation & Architecture Decision Records

- **[Architecture Overview](docs/architecture.md)** — 4-layer local-first design
- **[Authority Kernel Reference](docs/authority-kernel.md)** — Lattice, Memory Gate, Signed `ConsentToken`, Ed25519 Receipts, Q1 HMAC grading
- **[OWASP 2026 Threat Mapping](docs/owasp-2026-mapping.md)** — `ASI01–ASI10` & `LLM01–LLM10:2026`
- **[Known Limitations](docs/known-limitations.md)** — Honest boundaries (in-process hooks, DNS TOCTOU, heuristic reachability, AgentDyn)
- **[Migration Guide (v3 → v4)](docs/migration-v4.md)** — `drako upgrade --v4` & breaking changes
- **[Architecture Decision Records (ADR-0000 – ADR-0013)](docs/adr/README.md)** — Every architectural, protocol, pruning, and licensing decision

---

## License

Licensed under the **[Apache License 2.0](LICENSE)** (`Apache-2.0`). See [ADR-0012](docs/adr/0012-apache-2-0-license-migration.md).
