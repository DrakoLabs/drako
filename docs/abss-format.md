# DRAKO-ABSS: Agent Behavioral Security Standard

DRAKO-ABSS is a machine-readable format for describing security vulnerabilities specific to AI agent systems.

## Format

**ID:** `DRAKO-ABSS-{YEAR}-{SEQUENTIAL}`

Each advisory is a YAML file containing:
- Affected frameworks and conditions
- IOC patterns with normalized hashes
- Taint path (source → sink)
- References to OWASP, MITRE ATLAS, CVEs
- Mapping to Drako scan rules
- Remediation guidance

## Why a new format?

CVE tracks software vulnerabilities. DRAKO-ABSS tracks **agent behavioral vulnerabilities** — problems that emerge from how an agent uses its tools, processes untrusted input, or interacts with other agents. These are not bugs in code; they are risks in configuration and behavior.

## Schema

```yaml
id: DRAKO-ABSS-2026-001          # Unique advisory ID
title: "Short descriptive title"   # Human-readable title
category: owasp-llm               # owasp-llm | mitre-atlas | framework-cve | prompt-injection
severity: 9                       # 1-10 (10 = most severe)
confidence: 0.95                   # 0.0-1.0

affected:
  frameworks: [crewai, langchain]  # Affected AI agent frameworks
  conditions:                      # Conditions that make the vulnerability exploitable
    - "Condition description"

ioc:
  type: PROMPT_INJECTION           # IOC category
  patterns:                        # Detectable patterns (strings, regexes)
    - "pattern string"
  pattern_hashes:                  # SHA-256 of normalized patterns
    - "hex_hash_string"

taint_path:
  source: "user_input"             # Where the attack originates
  sink: "system_prompt_disclosure"  # What gets compromised
  via: ["step1", "step2"]          # Attack chain steps

references:
  - type: owasp                    # owasp | mitre_atlas | cve | research | github_issue
    id: "LLM01:2025"
    url: "https://..."

mitigation:
  drako_rules: [SEC-007, SEC-008]  # Drako scan rules that detect this
  description: "How to remediate"
  remediation_effort: low          # low | moderate | significant

metadata:
  published: "2026-03-20"
  updated: "2026-03-20"
  author: "Drako Security Research"
```

## Categories

| Category | Description | Count |
|---|---|---|
| `owasp-llm` | OWASP Top 10 for LLM Applications 2025 | 10 |
| `mitre-atlas` | MITRE ATLAS tactics and techniques | 5 |
| `framework-cve` | Known CVEs/issues in AI agent frameworks | 5 |
| `prompt-injection` | Documented prompt injection attack patterns | 5 |

## IOC Pattern Hashes

Pattern hashes are SHA-256 digests of normalized patterns (lowercase, stripped). This allows runtime matching without distributing raw patterns:

```python
import hashlib
normalized = pattern.strip().lower()
hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
```

## Contributing

Found a new agent vulnerability? Submit via GitHub issue using the advisory YAML template above.

1. Fork the repository
2. Create a new YAML file in `src/drako/data/advisories/`
3. Follow the schema above
4. Submit a pull request with:
   - The advisory YAML file
   - A brief description of the vulnerability
   - At least one reference (paper, CVE, issue, blog post)

## License

DRAKO-ABSS advisories are published under CC-BY-4.0.
