# Security Policy

## Supported Versions

Drako follows an active release model. Security updates are delivered on the current **4.x** branch.

| Version        | Supported     | Security Updates |
|----------------|---------------|------------------|
| 4.x (current)  | Yes           | Yes              |
| 3.x            | No (EOL)      | No               |
| 2.x            | No (EOL)      | No               |
| 1.x            | No (EOL)      | No               |

Always install from [PyPI](https://pypi.org/project/drako/) or verify releases on the
[GitHub Releases](https://github.com/DrakoLabs/drako/releases) page.

---

## Scope

The following components are **in scope** for security reports:

| Component | Examples of relevant issues |
|---|---|
| **Authority Kernel** | Origin trust ceiling bypass, taint lattice escape, glob deny-wins bypass, `ConsentToken` verification bypass |
| **Memory Gate (ASI06)** | Untrusted write quarantine bypass, persistent memory poisoning across trust boundaries |
| **Ed25519 Receipts & JCS** | RFC 8785 JCS canonicalization mismatch, SHA-256 hash-chain break, Ed25519 signature forgery, `drako verify` false pass |
| **MCP Guard** | `mcp.lock` hash-pinning bypass, `tools/list` schema drift evasion, SSRF in `MCPGAClient`, argv confusion |
| **A2A JWS** | Detached RFC 7515 EdDSA JWS verification bypass, SSRF in `fetch_and_verify_agent_card` |
| **Instruction Scanner (`INST-001..005`)** | Bypassing `drako desktop skills` detection for prompt hijack, secret exfiltration, or remote shell execution |
| **Local Enforcement Proxy** | Loopback/CORS bypass, `/status` or `/audit` bearer auth (`DRAKO_PROXY_TOKEN`) bypass, `LoopBreaker` or `EgressGuard` bypass |
| **Static Scan Engine & CLI** | Critical false negatives or AST bypasses in `SEC-*`, `GOV-*`, `COM-*`, `FW-*` rules; path traversal or code execution via `.drako.yaml` |

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report upstream and notify us if Drako is specifically impacted)
- Findings from automated scanners submitted without a minimal reproduction case
- Social engineering or phishing against maintainers
- Policy strictness debates — use GitHub Issues or Discussions instead

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Primary Channel

Use **[GitHub Private Vulnerability Reporting](https://github.com/DrakoLabs/drako/security/advisories/new)**
(the **"Report a vulnerability"** button in the repository's **Security** tab). This creates an
encrypted, private advisory thread directly with the maintainers and is the fastest path to triage.

### What to Include

Please provide:

```text
1. Affected component and version (`drako --version`)
2. Description of the vulnerability and security impact
3. Step-by-step reproduction instructions or minimal PoC
4. Environment details (OS, Python version, agent framework if relevant)
5. Expected vs. actual behavior
6. Suggested fix or mitigation (if available)
```

For **Authority Kernel**, **adapter**, or **proxy** issues, include the `.drako.yaml` / `drako-policy.yaml`
configuration and a minimal reproduction snippet.

For **receipt chain** issues, include the `.drako/receipts.jsonl` file and the output of
`drako verify .drako/receipts.jsonl --pubkey-file <pub.pem>`.

---

## Response Timeline

| Stage | Target |
|---|---|
| Acknowledgment | <= 48 hours |
| Initial triage & severity assessment | <= 5 business days |
| Patch or mitigation for Critical / High | <= 14 days from confirmation |
| Patch or mitigation for Medium / Low | Next scheduled release |
| Public disclosure | Coordinated — after patch is available, with reporter's consent |

We follow **coordinated disclosure**. We will not disclose your report publicly until a fix is
available, and we will credit you in the advisory unless you prefer to remain anonymous.

---

## Severity Classification

We use **CVSS v3.1** as a baseline, adjusted for AI-agent authority impact:

- **Authority / Kernel bypass**: Can an untrusted input or tool call cross a trust boundary or execute a denied tool?
- **Cryptographic receipt integrity**: Can an attacker forge Ed25519 receipts or tamper with a hash chain undetected by `drako verify`?
- **Protocol supply-chain bypass**: Can a mutated MCP server (`mcp.lock` / `tools/list`) or unsigned A2A Agent Card slip past admission?
- **Proxy isolation**: Can an unauthenticated client read `/audit` / `/status` or trigger SSRF via the proxy?

| Severity | Examples |
|---|---|
| **Critical** | Authority Kernel enforcement bypass, Ed25519/JWS signature forgery, `ConsentToken` bypass, proxy auth bypass |
| **High** | Memory Gate quarantine bypass, `mcp.lock` pin bypass, SSRF egress bypass, arbitrary code execution via config |
| **Medium** | False negative in `SEC-*` / `INST-*` / `FW-*` rule classes, `LoopBreaker` evasion, path traversal |
| **Low** | Non-sensitive scan metadata leakage, minor CLI edge cases |

---

## Security Advisories

Confirmed vulnerabilities are published in the
[GitHub Security Advisories](https://github.com/DrakoLabs/drako/security/advisories) tab and
referenced in [CHANGELOG.md](CHANGELOG.md).

---

## Hardening Drako in Your Environment

- Pin a specific Drako version in CI and verify package hashes.
- Commit `.drako.yaml`, `drako-policy.yaml`, and `mcp.lock` to version control; run `drako drift` in CI to catch unauthorized scope widening.
- Keep the operator signing key (`drako kernel keygen`) strictly separated from runtime receipt-signing keys and outside agent-accessible paths.
- Bind `drako proxy start` to `127.0.0.1` (default) and always set `DRAKO_PROXY_TOKEN` before exposing `/status` or `/audit`.
- Gate PRs with `drako scan . --fail-on critical` and `drako desktop skills . --fail-on high`.
- Verify local audit trails offline with `drako verify .drako/receipts.jsonl --pubkey-file <pub.pem>`.

---

## Out-of-Scope Conduct

The following actions are **not permitted** during security research:

- Accessing, modifying, or exfiltrating data from production systems or third-party deployments
- Testing against third-party systems or agents without explicit authorization
- Publishing vulnerability details before coordinated disclosure is complete

---

*This policy is versioned alongside the codebase. Last reviewed: 2026.*
