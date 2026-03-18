# Changelog

All notable changes to Drako are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

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
