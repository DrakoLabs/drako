# ADR-0011: Static Scanning of Agent Instruction & Skill Files (`SKILL.md`, `.cursor/rules`, `CLAUDE.md`, `AGENTS.md`)

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

In H2 2026, supply-chain attacks shifted from binary/package malware to **executable Markdown configuration** automatically loaded by AI coding agents (Claude Code, Cursor, Windsurf, Codex). Campaigns such as *ClawHavoc*, *ToxicSkills*, and the *Miasma* worm planted prompt overrides, `.env`/SSH exfiltration commands, obfuscated `curl | sh` payloads, and wildcard `Bash(*)` approvals inside repository instruction files (`SKILL.md`, `.cursor/rules/*.mdc`, `CLAUDE.md`, `AGENTS.md`, `.claude/settings.json`).

## Decision

Add a dedicated, 100% deterministic, zero-LLM scanner module `drako.desktop.instruction_rules` exposed via `drako desktop skills [DIRECTORY]` (`--format text|json`, `--fail-on`):

- **`INST-001` (CRITICAL, `ASI01`):** Instruction override, system-prompt disregard, hidden HTML comment hijacks, or zero-width character steganography.
- **`INST-002` (CRITICAL, `ASI04`):** Sensitive credential sources (`.env`, `~/.ssh`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `/etc/passwd`) paired with outbound network/encoding sinks (`curl`, `wget`, `fetch`, webhook, `base64`).
- **`INST-003` (HIGH, `ASI05`):** Pipe-to-shell remote execution (`curl ... | sh`), decoded base64 piped to shell, or destructive `rm -rf` root/home directives.
- **`INST-004` (HIGH, `ASI02`):** Wildcard tool pre-approvals (`allowed-tools: *`, `Bash(*)`, `--dangerously-skip-permissions`, `autoApprove: true`).
- **`INST-005` (MEDIUM, `ASI04`):** Unpinned package auto-execution (`npx -y <pkg>` without `@version`, unpinned `pip install git+https://...`).

## Alternatives Considered

- **LLM-based skill classifier:** Slow, requires API keys, nondeterministic across CI runs, and vulnerable to prompt injection inside the scanned file itself.

## Consequences

- Zero-latency CI gate for PRs modifying coding-agent rules or third-party skills.
- Honest limitation: purely semantic social-engineering prose without override/sink/exec signatures is out of scope for deterministic regex/AST detection.

## Verification

- `tests/test_instruction_rules.py` covering every rule (`INST-001`..`005`) with vulnerable, safe, and CLI JSON/`--fail-on` assertions.
