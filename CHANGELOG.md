# Changelog

All notable changes to Drako are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

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
