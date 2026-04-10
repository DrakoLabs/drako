# Security Policy

## Supported Versions

Drako follows a rapid release model. Only the latest **2.x** branch receives security updates.

| Version       | Supported          | Security Updates |
|---------------|--------------------|------------------|
| 2.x (latest)  | ✅ Yes             | ✅ Yes           |
| 1.x           | ❌ No (EOL)        | ❌ No            |

Always use the latest stable release from [PyPI](https://pypi.org/project/drako/) or the
[GitHub Releases](https://github.com/DrakoLabs/drako/releases) page.

---

## Scope

The following components are **in scope** for security reports:

| Component | Examples of relevant issues |
|---|---|
| **Static scan engine** | Critical false negatives in SEC-\*, GOV-\*, COM-\*, FW-\* rules; rule bypass via AST manipulation |
| **Runtime enforcement pipeline** | Tool call bypass, DLP evasion, HITL bypass, ODD boundary escape |
| **Out-of-process proxy** | Request/response tampering, auth bypass, credential exposure in transit |
| **Audit trail** | SHA-256 chain break, Ed25519 signature forgery, log injection, tamper-evident log bypass |
| **Collective Intelligence / IOC sharing** | Poisoning, spoofing, amplification, data exfiltration via IOC payloads |
| **Desktop agent scanning** | MCP config parsing exploits, privilege escalation, shell injection |
| **CLI & configuration** | Arbitrary code execution via `.drako.yaml`, path traversal, insecure defaults |
| **Policy versioning / rollback** | Snapshot corruption, unauthorized rollback, policy downgrade attacks |
| **DRAKO-ABSS advisory format** | Advisory injection, hash collision in IOC pattern matching |
| **Trust Score & Intent Fingerprinting** | Score manipulation, fingerprint collision |

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report these upstream; mention them to us if you believe they affect Drako specifically)
- Issues already disclosed in a published DRAKO-ABSS advisory
- Findings from automated scanners submitted without a reproduction case
- Social engineering or phishing attacks against DrakoLabs personnel
- Governance score disagreements (i.e., "I think rule X is too strict") — use GitHub Discussions instead

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Preferred channel

Use **[GitHub Private Vulnerability Reporting](https://github.com/DrakoLabs/drako/security/advisories/new)**
(the "Report a vulnerability" button in the Security tab). This creates an encrypted, private thread
directly with the maintainers and is our fastest path to triage.

### Fallback

If GitHub PVR is unavailable or you prefer email:

📧 **hello@getdrako.com**

### What to include

A useful report significantly reduces our triage time. Please provide:

```
1. Affected component and version (`drako --version`)
2. Description of the vulnerability and its security impact
   (confidentiality / integrity / availability / safety of governed agents)
3. Step-by-step reproduction instructions
4. Environment details (OS, Python version, framework if relevant)
5. Expected vs. actual behavior
6. Suggested fix or mitigation (if you have one)
7. PoC, logs, SARIF output, or screenshots where applicable
```

For **runtime bypass** or **proxy** issues, include the `.drako.yaml` config and a minimal
agent snippet that triggers the behavior.

For **audit trail** issues, include the exported audit log and any relevant output from
`drako history` or `drako diff`.

---

## Response Timeline

| Stage | Target |
|---|---|
| Acknowledgment | ≤ 48 hours |
| Initial triage & severity assessment | ≤ 5 business days |
| Patch or mitigation for Critical / High | ≤ 14 days from confirmation |
| Patch or mitigation for Medium / Low | Next scheduled release |
| Public disclosure | Coordinated — after patch is available, with reporter's consent |

We follow **coordinated disclosure**. We will not disclose your report publicly until a fix is
available, and we will credit you in the advisory unless you prefer to remain anonymous.

If we are unable to reproduce the issue or determine it is not a vulnerability, we will explain
our reasoning. You are welcome to provide additional information to reopen the case.

---

## Severity Classification

We use **CVSS v3.1** as a baseline and adjust for AI-agent-specific impact. In addition to
standard CIA triad scoring, we consider:

- **Agent safety impact**: Can the vulnerability cause an AI agent to take unintended real-world
  actions (financial transactions, code execution, data exfiltration)?
- **Audit integrity**: Does the vulnerability undermine the tamper-evident audit trail or allow
  log injection that survives independent verification?
- **Governance bypass**: Can the vulnerability allow a governed agent to execute a tool call that
  policy explicitly forbids?
- **Collective Intelligence abuse**: Can the vulnerability be used to poison IOC feeds across
  multiple Drako deployments?

| Severity | Examples |
|---|---|
| **Critical** | Runtime enforcement bypass, Ed25519 forgery, proxy auth bypass, IOC feed poisoning |
| **High** | DLP bypass for Critical PII, HITL suppression, audit chain break, arbitrary code via config |
| **Medium** | False negative in a SEC-\* or FW-\* rule class, Trust Score manipulation, path traversal |
| **Low** | Scan result information leakage, low-impact rule gaps, desktop scan parser issues |

---

## Security Advisories

Confirmed vulnerabilities are published as **DRAKO-ABSS advisories**
([format spec](https://github.com/DrakoLabs/drako/blob/main/docs/abss-format.md)) in the
[GitHub Security Advisories](https://github.com/DrakoLabs/drako/security/advisories) tab
and referenced in the [CHANGELOG](https://github.com/DrakoLabs/drako/blob/main/CHANGELOG.md).

Advisory identifiers follow the format: `DRAKO-ABSS-YYYY-NNN`

You can subscribe to advisory notifications by **watching** this repository and selecting
*"Security alerts"* in your notification settings.

---

## Hall of Fame

We are grateful to the security researchers who help keep Drako and the AI agents it governs safe.
Reporters of confirmed Critical or High vulnerabilities will be credited here (with permission).

*No entries yet — be the first.*

---

## Hardening Drako in Your Environment

While not a substitute for reporting vulnerabilities, the following practices reduce your attack
surface:

- Pin to a specific Drako version in CI and verify the PyPI SHA256 hash
- Commit your `.drako.yaml` to version control and use `drako history` and `drako diff`
  to detect unauthorized policy changes; use `drako rollback` to restore a known-good state
- Run the proxy in a dedicated network namespace or container; do not expose port 8990 publicly
- Enable `dlp.mode: enforce` before production deployment, not just `audit`
- Use `drako scan --fail-on critical` as a hard CI gate, not just advisory
- Use `drako scan --baseline` to track new findings separately from acknowledged ones,
  so regressions are never silently absorbed into the baseline

---

## Out-of-Scope Conduct

The following actions are **not permitted** during security research and will not be considered
good-faith disclosure regardless of findings:

- Accessing, modifying, or exfiltrating data from production systems or customer deployments
- Denial-of-service attacks against getdrako.com or the Collective Intelligence infrastructure
- Testing against third-party systems or agents that have not granted explicit permission
- Publishing vulnerability details before coordinated disclosure is complete

---

*This policy is versioned alongside the codebase. Last reviewed: 2026.*
