"""Deterministic scanner for AI coding-agent instruction & skill files (ADR-0011).

Covers H2 2026 supply-chain poisoning surfaces (ClawHavoc / ToxicSkills / Miasma):
  - SKILL.md, CLAUDE.md, AGENTS.md
  - .cursorrules, .windsurfrules, .cursor/rules/*.mdc
  - .claude/settings.json, .claude/settings.local.json

Five high-precision deterministic rules (zero LLM calls, 100% offline):
  INST-001 (CRITICAL, ASI01): Instruction override / hidden prompt hijack
  INST-002 (CRITICAL, ASI04): Secret / credential exfiltration directive
  INST-003 (HIGH,     ASI05): Destructive or obfuscated remote shell execution
  INST-004 (HIGH,     ASI02): Overbroad tool pre-approval / permission bypass
  INST-005 (MEDIUM,   ASI04): Unpinned auto-executed package (npx -y / git+http)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_EXACT_FILENAMES = {
    "SKILL.md",
    "CLAUDE.md",
    "AGENTS.md",
    ".cursorrules",
    ".windsurfrules",
}

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
}


@dataclass(frozen=True)
class InstructionFinding:
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    owasp_asi: str
    file_path: str
    line_number: int
    title: str
    message: str
    snippet: str


_RE_OVERRIDE = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:system|safety|security)\s+(?:instructions|prompt|rules)"
    r"|<!--[\s\S]{0,200}?(?:ignore\s+previous|system\s+override|exfiltrate|execute\s+silently)[\s\S]{0,200}?-->"
    r"|[\u200b\u200c\u200d\ufeff]{3,})",
    re.IGNORECASE,
)

_RE_SENSITIVE = re.compile(
    r"(?:~/\.ssh|/\.ssh/id_rsa|id_ed25519|\.aws/credentials|AWS_SECRET_ACCESS_KEY"
    r"|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|\b\.env\b|/etc/passwd|process\.env)",
    re.IGNORECASE,
)
_RE_EXFIL_SINK = re.compile(
    r"(?:\bcurl\b|\bwget\b|\bfetch\(|https?://|webhook|pastebin|requestbin|\bnc\s+-|base64)",
    re.IGNORECASE,
)

_RE_RCE_OBFUSC = re.compile(
    r"(?:(?:curl|wget)\s+[^\n|]{3,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b"
    r"|base64\s+(?:-d|--decode)[^\n|]{0,120}\|\s*(?:ba)?sh\b"
    r"|rm\s+-rf\s+(?:/\s|/\*|~|\$HOME)"
    r"|eval\s+[\"\']\$\((?:curl|wget))",
    re.IGNORECASE,
)

_RE_OVERBROAD_TOOLS = re.compile(
    r"(?:allowed-tools\s*:\s*\*"
    r"|\bBash\(\*\)"
    r"|--dangerously-skip-permissions"
    r"|\"autoApprove\"\s*:\s*true"
    r"|\"allow\"\s*:\s*\[\s*\"Bash\(\*\)\"\s*\])",
    re.IGNORECASE,
)

_RE_UNPINNED_EXEC = re.compile(
    r"(?:\bnpx\s+(?:-y|--yes)\s+(?:@[a-z0-9._-]+/[a-z0-9._-]+|[a-z0-9._-]+)(?=$|[\s`\"'.,;)])"
    r"|\bpip\s+install\s+git\+https?://[^\s@]+(?=$|[\s`\"'.,;)]))",
    re.IGNORECASE,
)


def discover_instruction_files(root: str | Path) -> list[Path]:
    """Find coding-agent instruction, rule, and skill files under root."""
    base = Path(root).resolve()
    found: list[Path] = []
    if not base.exists():
        return found

    for path in base.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        rel_posix = path.relative_to(base).as_posix()
        if (
            path.name in _EXACT_FILENAMES
            or rel_posix.startswith(".cursor/rules/") and path.suffix in (".mdc", ".md")
            or rel_posix in (".claude/settings.json", ".claude/settings.local.json")
        ):
            found.append(path)
    return sorted(found)


def scan_instruction_content(content: str, rel_path: str) -> list[InstructionFinding]:
    """Run INST-001..005 deterministically over a single instruction file."""
    findings: list[InstructionFinding] = []
    lines = content.splitlines()

    # INST-001: Multi-line check for hidden HTML comment / zero-width / override
    m_ov = _RE_OVERRIDE.search(content)
    if m_ov:
        lineno = content[: m_ov.start()].count("\n") + 1
        snippet = lines[lineno - 1].strip()[:140] if lineno <= len(lines) else ""
        findings.append(
            InstructionFinding(
                rule_id="INST-001",
                severity="CRITICAL",
                owasp_asi="ASI01",
                file_path=rel_path,
                line_number=lineno,
                title="Prompt override or hidden hijack in instruction file",
                message=f"Instruction file '{rel_path}' contains override/obfuscated hijack directives.",
                snippet=snippet,
            )
        )

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # INST-002: Sensitive secret source + network sink on same line (or adjacent context)
        window = "\n".join(lines[max(0, idx - 1) : min(len(lines), idx + 2)])
        if _RE_SENSITIVE.search(stripped) and _RE_EXFIL_SINK.search(window):
            findings.append(
                InstructionFinding(
                    rule_id="INST-002",
                    severity="CRITICAL",
                    owasp_asi="ASI04",
                    file_path=rel_path,
                    line_number=idx,
                    title="Credential/secret exfiltration directive in instruction file",
                    message=f"'{rel_path}' combines sensitive credential access with outbound network/encoding sink.",
                    snippet=stripped[:140],
                )
            )

        if _RE_RCE_OBFUSC.search(stripped):
            findings.append(
                InstructionFinding(
                    rule_id="INST-003",
                    severity="HIGH",
                    owasp_asi="ASI05",
                    file_path=rel_path,
                    line_number=idx,
                    title="Destructive or pipe-to-shell command in instruction file",
                    message=f"'{rel_path}' directs the agent to run unverified remote/obfuscated shell commands.",
                    snippet=stripped[:140],
                )
            )

        if _RE_OVERBROAD_TOOLS.search(stripped):
            findings.append(
                InstructionFinding(
                    rule_id="INST-004",
                    severity="HIGH",
                    owasp_asi="ASI02",
                    file_path=rel_path,
                    line_number=idx,
                    title="Overbroad tool pre-approval or permission bypass",
                    message=f"'{rel_path}' grants wildcard shell/tool approval or disables permission checks.",
                    snippet=stripped[:140],
                )
            )

        if _RE_UNPINNED_EXEC.search(stripped):
            findings.append(
                InstructionFinding(
                    rule_id="INST-005",
                    severity="MEDIUM",
                    owasp_asi="ASI04",
                    file_path=rel_path,
                    line_number=idx,
                    title="Unpinned package auto-execution in instruction file",
                    message=f"'{rel_path}' invokes unpinned npx -y or git+https dependency without exact version/commit pin.",
                    snippet=stripped[:140],
                )
            )

    # Deduplicate same (rule_id, file_path, line_number)
    seen: set[tuple[str, str, int]] = set()
    unique: list[InstructionFinding] = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_instruction_files(root: str | Path) -> tuple[list[Path], list[InstructionFinding]]:
    """Discover and scan all coding-agent instruction/skill files under root."""
    base = Path(root).resolve()
    files = discover_instruction_files(base)
    all_findings: list[InstructionFinding] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(base).as_posix()
        all_findings.extend(scan_instruction_content(text, rel))
    return files, all_findings
