# Changelog

All notable changes to Drako are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)


## [4.0.0a1] - 2026-11-24

### Added
- **Zero-Friction Runtime Facade (`drako.guard`, `drako.build_host`)**: one-line offline agent/tool wrapper with fail-closed defaults, glob pattern rules (`allow=["search_*"]`, `deny=["delete_*"]`, deny-wins on tie), and zero disk I/O unless `receipts=` is explicitly passed.
- **Authority Kernel (`drako.kernel`)**: single fail-closed chokepoint (`Proposal -> Guardian -> Host -> Ed25519 Receipt`), origin-bound trust lattice (`tool:* <= TOOL`, `memory:* <= AGENT`, `ctk:* <= UNTRUSTED`), `OriginAttester`, operator-signed Ed25519 `ConsentToken`s bound to JCS `args_hash`, `MemoryGate` (`ASI06`), MITRE ATLAS `Scope Drift` (`drako drift`), thread-safe repetition `LoopBreaker` (`ASI08`/`ASI10`), and SSRF `egress` chokepoint.
- **Cryptographic Receipts & Operator/Target Separation**: `drako why <receipt_id>`, offline-default `drako verify`, `drako kernel {keygen, sign-consent, bench}`, in-toto/SLSA v1 export, and Q1 RFC 8032 HMAC `"telemetry"` grading (`verify_receipt_hmac`).
- **OWASP ACS Conformance (`AGENT-HOOKS-0.1`)**: `conformance/CLAIMS.md` and `conformance/declared_surface.json` (44/44 applicable CTK vectors passing, 3 capability-gated skips, 0 failures).
- **MCP Guard (`drako.mcp_guard`)**: `mcp.lock` SHA-512 hash-pinning, `admission`, mid-session `tools/list` drift detection (*Deadbugz*), **CycloneDX 1.7 (ECMA-424)** AgBOM (`drako mcp agbom`, `drako bom --format cyclonedx`), and stateless **MCP `2026-07-28` GA** client (`drako mcp check-drift`).
- **A2A v1.0 Signed Agent Cards (`drako.a2a`)**: RFC 7515 Detached JWS (`EdDSA`) + RFC 8785 JCS (`drako a2a {sign, verify, inspect}`).
- **Unified Offline Framework Adapters (`drako.adapters`)**: LangGraph, OpenAI Agents SDK, Microsoft Agent Framework (Agent Hooks), Claude Agent SDK (`PreToolUse`), Google ADK (`before_tool_callback`), and CrewAI — all enforcing T-5 re-govern-after-modify with signed `supersedes_receipt_id`.
- **Skill & Instruction-File Poisoning Scanner**: `drako desktop skills` (`INST-001..005`) scanning `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/*.mdc`, and `.claude/settings*.json`.
- **EU AI Act Digital Omnibus Alignment (`drako[comply]`)**: Art. 50 (Aug/Dec 2026) and Annex III/I (2027/2028) schedule plus local Ed25519 receipt-chain ingestion for Art. 12 evidence.
- **Public Architecture Decision Records (`docs/adr/0000` – `0013`)** and full GitHub Actions CI (`test.yml`, `drako-gate.yml`, `publish.yml`).
- **`drako upgrade --v4`**: idempotent migration from v3 `.drako.yaml` to v4 local-first schema.

### Changed
- **Relicensed from `BUSL-1.1` to `Apache-2.0`** ([ADR-0012](docs/adr/0012-apache-2-0-license-migration.md)).
- Moved to a 100% local-first architecture (`DrakoLabs/drako`) with zero network calls by default and zero API keys required ([ADR-0001](docs/adr/0001-single-repo-local-first-consolidation.md)).
- **Read-only `drako scan` by default**: no longer writes `.drako/.last_scan.json` or edits `.gitignore` unless `--save-cache` is explicitly passed; `drako init` runs live in-memory discovery when no cache exists.
- Proxy server (`drako.proxy.proxy_server`) hardened for FastAPI annotation resolution, loopback-only default binding (`127.0.0.1`), bearer authentication on `/status` and `/audit`, and wired to `LoopBreaker`, `egress`, and optional `kernel.Host`.
- Updated rule fixtures (`CV-001`, `CV-002`, `HOOK-002`, `HOOK-003`, `COM-005`), scoring tests, and lazy optional `tree-sitter` imports.

### Removed
- Removed remote API client (`DrakoClient`), remote telemetry, `push/status/history/diff/rollback/simulate/serve` CLI commands, `scan --upload`, `scan --share` (`share.py`, `scorecard.py`), remote-coupled `middleware/*` (including AutoGen), legacy `src/drako/mcp` (`2024-11-05` + SSE), `simple/` (replaced by `scan --compact`), `nocode/`, auxiliary scripts (`tools/`), and legacy manifests ([ADR-0006](docs/adr/0006-surface-pruning-v4.md)).

---


## [3.0.0] - 2026-04-10

### Changed
- **Unified versioning**: SDK, backend, public repo, and MCP manifests now
  share version 3.0.0. All version references synchronized across
  pyproject.toml, `__init__.py`, server.json, and OpenAPI spec.
- License classifier corrected to match BUSL-1.1 license field

### Added
- **`drako scan --simple`** — indie-developer-friendly output mode. Filters findings to a curated whitelist of 12 high-signal rules, renders plain text with severity markers (capped at 10 findings), and emits framework-aware remediation snippets for CrewAI, LangChain, LangGraph, AutoGen, and direct API integrations. Mutually exclusive with `--format sarif` and `--details`.
- **`drako nocode`** — governance scanner for no-code agent workflows. Parses n8n and Flowise exports into a normalized graph, runs BFS taint propagation from user-input nodes, and evaluates 10 rules (NC-001 → NC-010) covering unsanitized input, code execution, credential exposure, missing human-in-the-loop, and more. Ships `drako nocode scan` and `drako nocode bom` with text/JSON/markdown output, reusing the existing scoring engine for coherence with `drako scan`.
- **`drako[comply]`** — optional extra for EU AI Act documentation generation. Runs a 30-question interactive assessment, merges answers with the latest scan cache and BOM, and generates DOCX and PDF drafts for Articles 9 (Risk Management), 11 (Technical Documentation), 12 (Record-Keeping), and 14 (Human Oversight). Every generated document carries a hardcoded legal disclaimer stating that the output is a draft requiring qualified legal review. Install with `pip install drako[comply]`.
- **Desktop Agent Scanning** improvements and stabilization
- TypeScript scanner with Tree-sitter (17 dedicated rules)
- 97 total governance rules (up from 25 in v1.0.1)
- Determinism scoring, benchmark system, baseline scanning
- Proxy mode, policy templates, Helm chart
- `govern()` universal wrapper for runtime compliance enforcement

---

## [2.5.0] - 2026-04-01

### Added
- **Desktop Agent Scanning** — `drako desktop scan/bom/govern` commands
  - Auto-discovery of MCP servers across 8 clients: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Codex CLI, Gemini CLI, Kiro
  - Cross-platform config path detection (macOS, Linux, Windows)
  - 8 MCP-specific security rules (MCP-001 → MCP-008): unrestricted filesystem, shell capability, untrusted source, unrestricted network, plaintext credentials, unencrypted transport, elevated privileges, compound capabilities
  - `drako desktop govern` — scan + activate runtime proxy to intercept MCP traffic
  - Desktop Governance Score separate from project scoring
  - Output formats: text, JSON, SARIF, markdown
- **RFC 3161 timestamping** on audit trail — externally verifiable by EU AI Act auditors
  - TSA redundancy: FreeTSA primary, DFN backup
  - Offline verification via embedded certificate chain
  - `tsa_token` column on audit_logs table
  - GET /api/v1/audit/verify/{entry_id} endpoint
- **Threat Intel Bootstrap** — automated daily sync from AlienVault OTX and abuse.ch
  - Quality gate: rejects pulses with <10 subscribers or zero indicators
  - Maps external threats to DRAKO-ABSS format with `external: true` metadata
  - GitHub Action cron: daily 6 AM UTC
- **Scanner Limitations Documentation** — `docs/scanner-limitations.md`
  - Transparent disclosure of 5 known gaps: interprocedural taint, TS type resolution, semantic injection, in-process enforcement, cross-agent taint
  - Roadmap issue labels on GitHub for each gap

### Fixed
- MCP server Dockerfile: corrected CMD to use `drako serve` instead of broken module path
- `drako/mcp/__main__.py` added to enable `python -m drako.mcp`
- server.json version sync with SDK version

---

## [2.4.2] - 2026-03-30

### Fixed
- **Windows encoding crash** — `drako push` and other commands no longer crash on cp1252 with box-drawing characters
  - Systemic fix via `configure_output()` at CLI startup
  - `errors='replace'` fallback for non-UTF-8 terminals
- **`drako simulate`** now reads API key from `.drako.yaml` (was ignoring `api_key_env`)
- **`drako validate`** auto-detects `.drako.yaml` in current directory when argument omitted
- **`drako scan --threshold`** flag added (was only `--threshold-det`)
- **`drako scan --benchmark`** panel now renders (was silent)
- **`drako scan --share`** texts include `getdrako.com` URL (was only pip install)
- **`drako init`** correctly validates API key against backend (was "Could not reach backend" on valid keys)
- **Backend upgrade URLs** — all references to `useagentmesh.com` replaced with `getdrako.com` in 403 responses and feature-gating messages

### Changed
- Command ordering in `drako --help` — journey-linear (scan → init → push) instead of alphabetical
- Quickstart hint added to `drako` help output
- Post-scan CTA no longer suggests `pip install drako` (user already has it)
- First-scan output truncated to top 10 findings with `... and X more` footer
- Benchmark panel labeled "benchmark dataset" instead of "100 scanned projects"

---

## [2.4.1] - 2026-03-29

### Added
- **SSO via WorkOS** (Enterprise tier) — Okta, Azure AD, SAML, Google Workspace
  - GET /api/v1/auth/sso/authorize?email=X
  - GET /api/v1/auth/sso/callback
  - POST /api/v1/settings/sso/enable (owner only, enterprise plan)
  - CSRF state tokens via Redis (10min TTL, one-time use) with HMAC fallback
  - Auto-provisioning of users matching tenant's sso_domain
  - Password login blocked server-side for SSO-enforced domains
  - Domain normalization (case-insensitive comparison)
- 28 SSO tests (CSRF state, password blocking, domain validation, enable/disable flows)

---

## [2.4.0] - 2026-03-28

### Added
- **Production Dashboard** — full observability UI at getdrako.com/dashboard
  - Stats grid with MetricCards (audit entries, agents, policy blocks, trust score)
  - Governance Score Trend (TimeSeriesChart)
  - Tool Health Grid (circuit breaker status per tool)
  - Recent Activity feed with 30s auto-refresh
  - Governance Roadmap component (conversion hook with tier-tagged action items)
- **Observability page** — 4 tabs (Overview, Metrics, Violations, Alerts)
  - P50/P95/P99 latency charts
  - Bottleneck detection
  - Cost breakdown by model (DonutChart)
  - Violation heatmap (7 days × severity)
- **FinOps page** — cost tracking, budget burn-down, model/agent breakdown
- **Settings page** — config viewer, snapshot history, feature status
- recharts integration for all visualizations
- PlanGate component for Pro/Enterprise feature gating

---

## [2.3.1] - 2026-03-26

### Fixed
- **10 integration test issues** discovered in E2E testing
- **govern() module/function shadowing** — renamed `govern.py` → `governance_wrapper.py` to eliminate namespace collision
- **Scoring recalibration** — reduced per-finding deductions (CRITICAL -10, HIGH -5, MEDIUM -2, LOW -1) to prevent score floor at 0
- **DET-001** now detects missing temperature on CrewAI `Agent()` constructors
- **LangGraph tools** detected in BOM via `ToolNode([...])` and `tools=[...]` patterns
- **VCR-001** extracts vendors from `ChatOpenAI()`, `ChatAnthropic()`, `ChatGoogleGenerativeAI()` constructors
- **Global governance rules** reclassified — ODD-001, MAG-001, ID-001, HOOK-001, CV-001, FIN-001, RES-001, CI-001, MULTI-004 now finding_type="recommendation" (do not affect score)
- **validate command** UnicodeEncodeError on Windows (systemic fix via CAN_UNICODE pattern)
- **drako bom --format text** exit code (now 0 even with 0 agents found)
- **Telemetry endpoint** no longer requires auth (anonymous events)
- **Config push API schema** aligned (flat payload accepted)

---

## [2.3.0] - 2026-03-25

### Added
- **TypeScript Scanner** — Tree-sitter based TS/JS scanning alongside Python
  - Framework detection: LangChain.js, Vercel AI SDK, Mastra, AutoGen.js
  - 17 TypeScript rules covering Security (10), Governance (3), Determinism (2), Compliance (1), Operational (1)
  - TS BOM extraction: agents, tools, models, prompts from `.ts/.tsx/.js/.jsx/.mts/.mjs` files
  - Mixed Python+TypeScript projects supported with merged scoring
  - Optional dependency: `pip install drako[typescript]`
  - 15 TypeScript rule fixtures with vulnerable/safe pairs
  - 34 TypeScript tests
- **Clean project output** — projects without AI agent components show friendly message instead of generic findings
- **Graceful degradation** — TS files detected without tree-sitter installed show install hint, Python scan continues

### Changed
- Policy count: 97 total (80 Python + 17 TypeScript)
- Rule count badge updated across README, docs, and scoring section

## [2.2.2] - 2026-03-24

### Fixed
- Re-release of 2.2.1 (PyPI upload conflict resolved)

## [2.2.1] - 2026-03-23

### Fixed
- Framework detection for LangGraph/AutoGen in subdirectories (parent directory walk-up)
- AutoGen new package names support (`autogen_agentchat`, `autogen_core`, `ag2`)
- Jupyter notebook `.ipynb` scanning with IPython magic line stripping
- CrewAI `@CrewBase` pattern: agent extraction from YAML config files
- Unconditional exit code 1 on critical findings removed (only with `--threshold-det`)
- MULTI-002 false positive on constructor calls (Crew, Task, Agent)

### Added
- Finding type classification: `vulnerability` vs `recommendation`
- Terminal report split into FINDINGS and RECOMMENDATIONS sections
- Recommendations excluded from governance score
- `finding_type` field in JSON and SARIF output formats

## [2.2.0] - 2026-03-22

### Added
- **Determinism Score** — second score (0-100) measuring agent reliability (unset temperatures, missing timeouts, no retries)
- **Execution path reachability analysis** on findings — unreachable tools are dimmed
- **25 DRAKO-ABSS security advisories** (OWASP Top 10 for LLMs, MITRE ATLAS, framework CVEs)
- **Vendor Concentration Risk rules** (VCR-001, VCR-002, VCR-003)
- **Framework-specific security rules** (FW-AUTOGEN-001/002, FW-CREWAI-001/002/003, FW-LANGGRAPH-001/002, FW-PYDANTIC-001, FW-SK-001/002)
- **Detection rules** (DET-001 → DET-007) for determinism scoring
- **Benchmark comparison system** (`--benchmark` flag)
- **Baseline system** for incremental scanning (`--baseline` flag, `drako baseline show/reset`)
- **Structured impact explanations** on all rules (`--details` flag with impact, attack_scenario, references)
- **GitHub Action** for PR governance comments
- **Score card SVG generation** (`--share` with scorecard + badge SVGs)
- **PQL telemetry** (anonymous, opt-in)
- **Framework security monitor** (6 frameworks, daily)
- **HITL test harness** (`test_mode()`, `MockHITLResolver`)
- **Policy simulation** (`drako simulate`)
- **Config validation** (`drako validate`)
- **Behavioral versioning**
- **Policy templates** (fintech, healthcare, eu-ai-act, startup, enterprise)
- **Out-of-process enforcement proxy** (`drako proxy start/stop/status`)
- **Property-based testing** (28 Hypothesis tests)
- **Helm chart** for Kubernetes deployment
- **Type safety** (`mypy --strict` on new modules)

### Changed
- Renamed from AgentMesh to Drako
- 80 rules total (up from 55)
- 647 tests (up from 277)
- Domain: getdrako.com
- PyPI: `drako` (was `useagentmesh`)

---

## [2.1.0] - 2026-03-18

### Added
- **Autopilot Mode** — `drako init` now generates smart defaults from scan results (audit-first). Governance levels: `--autopilot` (default), `--balanced`, `--strict`, `--manual`
- **`drako upgrade`** command — upgrade governance level in-place (`--balanced`, `--strict`)
- **Proxy Mode** — out-of-process LLM API governance proxy. Intercepts every LLM call at the network layer with full governance pipeline (ODD, DLP, Magnitude, HITL). `drako proxy start/stop/status`
- **Policy Templates** — 6 industry-specific governance presets: `base`, `fintech`, `healthcare`, `eu-ai-act`, `startup`, `enterprise`. Template inheritance via `extends:` in config. `drako templates list/show`
- **Property-Based Testing** — 28 Hypothesis tests covering scoring invariants, grade monotonicity, deep merge, ODD/DLP/Magnitude enforcement
- **Helm Chart** — Kubernetes deployment for the governance proxy (`deploy/helm/drako-proxy/`)
- `governance_level` config field — `autopilot | balanced | strict | custom`
- `extends` config field — template inheritance (e.g. `extends: fintech`)
- `test_mode()` context manager and `MockHITLResolver` for testing governed agents in CI
- Docker Compose file for proxy deployment

### Changed
- `drako init` default mode is now autopilot (was manual)
- Config `load()` now resolves template inheritance automatically

---

## [2.0.1] - 2026-03-17

### Fixed
- Sync `__version__` in `__init__.py` with `pyproject.toml` — CLI now reports correct version

---

## [2.0.0] - 2026-03-17

### Changed
- **Version bump to 2.0.0** — reflects production maturity and comprehensive governance coverage
- CI: add `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` to publish workflow for Node.js 24 migration

### Fixed
- Publish workflow: suppress Node.js 20 deprecation warnings on GitHub Actions

---

## [0.2.0] - 2026-03-16

### Added
- 26 new governance rules (60 total, up from 34)
- New rule categories: Multi-Agent (MULTI-001→004), Hooks (HOOK-001→003), Context Versioning (CV-001→002), FinOps (FIN-001→003), Resilience (RES-001→002), A2A (A2A-001→003), Best Practices (BP-001→005)
- `drako scan --share` viral sharing with pre-written posts for LinkedIn, X, Bluesky
- `drako history`, `diff`, `rollback` commands for policy version management
- `govern()` universal one-liner — auto-detects CrewAI, LangGraph, AutoGen
- Per-tool interception: every tool call evaluated through the enforcement pipeline
- Prompt Injection Detection (5 pattern categories, bidirectional)
- Circuit Breaker per-tool (CLOSED/OPEN/HALF_OPEN state machine)
- Human-in-the-Loop checkpoints (configurable triggers, webhook notifications)
- Intent Fingerprinting (SHA-256 + Ed25519 two-gate verification)
- Programmable Hooks (pre/post action, Python scripts + YAML conditions)
- Context Versioning (immutable snapshots on every push)
- Agentic FinOps (cost tracking, model routing, semantic cache, budgets)
- Deterministic Fallback (failover to code/agent/human/retry queue)
- Secure A2A Gateway (DID auth, channel policies, prompt worm prevention)
- Multi-Agent Topology (directed graph, conflict detection, cascade analysis)
- Chaos Engineering (7 fault types, governance grading A-F)
- Collective Intelligence (anonymous IOC sharing, quality scoring)
- Observability platform (session traces, latency metrics, drift detection)
- Alerting engine (configurable rules, Slack/email/PagerDuty)
- OTEL & SIEM export (OpenTelemetry, STIX 2.1, CEF)
- MCP local server for Claude Desktop integration
- AutoGen middleware support
- `drako serve` command for local MCP server
- `drako verify` command for configuration validation

### Changed
- `govern()` now wraps individual tools (was session-level only)
- Config-as-code: full governance configurable from `.drako.yaml`
- `drako push` translates YAML to enforcement engine
- Scoring updated for 13 rule categories (was 4)
- Policy engine evaluates all 60 rules in <2ms (P50)

## [0.1.9] - 2026-03-10

### Fixed
- CLI UX improvements across all commands
- API quota handling — graceful fallback on rate limit

## [0.1.8] - 2026-03-06

### Added
- Compact output mode (`drako scan --compact`)
- Autofix dry-run (`drako fix --dry-run`)
- `--project` flag to specify project root
- Governance badge URL generation for CI/CD
- BUSL-1.1 license version update

### Changed
- Scan output refined for readability

## [0.1.5] - 2026-03-04

### Added
- Operational Design Domain (ODD) scan rules: ODD-001 to ODD-004
- Magnitude limit scan rules: MAG-001 to MAG-003
- Agent Identity scan rules: ID-001 to ID-003
- 10 new rules total (34 total, up from 24)

## [0.1.4] - 2026-03-03

### Added
- API key YAML fallback — `api_key_env` field in `.drako.yaml`
- Cross-platform environment variable hint in scan output

### Fixed
- `drako scan` and `drako init` command edge cases

## [0.1.2] - 2026-02-28

### Fixed
- Windows MAX_PATH crash in directory scanner
- Broken benchmarks link (sdk/ prefix removed)
- Corrected paths and BSL-1.1 license note for contributors

### Added
- Professional upgrade CTA in scan output

## [0.1.1] - 2026-02-27

### Added
- Initial release of Drako SDK
- 24 governance rules across 4 categories (Security, Governance, Compliance, Best Practices)
- Agent BOM (Bill of Materials) — AST-based discovery of agents, tools, models, prompts
- Framework support: CrewAI, LangGraph, AutoGen, LangChain, LlamaIndex, PydanticAI
- CLI commands: `drako scan`, `drako init`
- Output formats: Terminal (Rich), JSON, SARIF 2.1.0
- Governance scoring: A-F grades (0-100 scale)
- GitHub Code Scanning integration via SARIF
- Pre-commit hook support
- Performance benchmarks (<2ms full scan P50)
- PyPI package: `drako`
