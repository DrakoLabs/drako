# Demo: CrewAI with Governance Gaps

This project contains **intentional** security and governance issues for testing Drako scan.

## Run

```bash
pip install drako
drako scan .
```

## Expected Findings

| Rule | Severity | What |
|------|----------|------|
| SEC-001 | CRITICAL | Hardcoded API key |
| SEC-003 | HIGH | Unrestricted filesystem access |
| SEC-005 | CRITICAL | Arbitrary code execution (exec) |
| SEC-007 | HIGH | Prompt injection via f-string |
| GOV-001 | HIGH | No audit logging |
| GOV-006 | CRITICAL | Agent modifies own prompt |
| GOV-009 | CRITICAL | Destructive actions without HITL |
| ODD-001 | CRITICAL | No operational boundaries |
| MAG-001 | CRITICAL | No spend cap |

Expected score: **~35** (Grade F)

This is a teaching tool. Do not deploy this code.
