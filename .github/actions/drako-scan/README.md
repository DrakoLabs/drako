# Drako Governance Scan - GitHub Action

Scan your AI agent codebase for governance and compliance gaps directly in your CI pipeline. Drako analyzes Python code offline using AST and posts findings as PR review comments with inline annotations.

## Quick Start

```yaml
name: Governance
on: [pull_request]

jobs:
  drako-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write  # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: angelnicolasc/drako-scan@v1
```

## Full Configuration

```yaml
- uses: angelnicolasc/drako-scan@v1
  with:
    path: '.'                # Directory to scan
    threshold: '70'          # Fail if score is below 70
    fail-on: 'high'          # Fail on high or critical findings
    comment-on-pr: 'true'    # Post inline PR review comments
    upload-sarif: 'true'     # Upload SARIF to GitHub Code Scanning
    benchmark: 'true'        # Include benchmark comparison data
    baseline: 'true'         # Only report new findings (requires .drako/.baseline.json)
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to the directory to scan |
| `threshold` | `0` | Minimum governance score (0-100). Exits with code 1 if below. |
| `fail-on` | `critical` | Fail on findings at this severity or above: `critical`, `high`, `medium`, `low` |
| `comment-on-pr` | `true` | Post findings as PR review with inline comments |
| `upload-sarif` | `true` | Upload SARIF results to GitHub Code Scanning |
| `benchmark` | `true` | Include anonymized benchmark comparison in JSON output |
| `baseline` | `true` | Use `.drako/.baseline.json` to suppress known findings |
| `github-token` | `${{ github.token }}` | Token for API calls (PR comments, SARIF upload) |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Governance score from 0 to 100 |
| `grade` | Letter grade: A (90+), B (75-89), C (60-74), D (40-59), F (0-39) |
| `findings-count` | Total number of findings detected |

### Using Outputs

```yaml
- uses: angelnicolasc/drako-scan@v1
  id: scan
- run: echo "Score is ${{ steps.scan.outputs.score }} (${{ steps.scan.outputs.grade }})"
```

## Permissions Required

```yaml
permissions:
  contents: read          # Read repository files
  pull-requests: write    # Post PR review comments
  security-events: write  # Upload SARIF to Code Scanning (optional)
```

If you only want the scan without PR comments or SARIF, `contents: read` is sufficient:

```yaml
permissions:
  contents: read
```

## PR Review Comments

When running on a `pull_request` event with `comment-on-pr: true`, the action will:

1. Fetch the list of files changed in the PR.
2. Filter scan findings to only those in changed files.
3. Post a single PR review containing:
   - A summary comment with the governance score, grade, and severity breakdown table.
   - Up to 20 inline comments on the exact lines where findings were detected, sorted by severity (critical first).
4. On subsequent pushes, the old Drako review is dismissed and replaced with a fresh one.

Each inline comment includes the policy ID, severity, description, and a suggested fix when available.

## SARIF Integration

When `upload-sarif: true`, the action generates a SARIF 2.1.0 report and uploads it to GitHub Code Scanning. Findings then appear in the **Security** tab of your repository.

Requirements:
- The `security-events: write` permission must be granted.
- GitHub Advanced Security must be enabled (free for public repos, requires license for private repos).

## Baseline Workflow

To avoid noise from pre-existing findings, use Drako's baseline feature:

```bash
# One-time: save current findings as baseline
pip install drako
drako scan . --baseline
git add .drako/.baseline.json
git commit -m "chore: save drako baseline"
```

With `baseline: true` (the default), the action only reports **new** findings not present in the baseline. Resolved findings are automatically removed from future scans.

## Troubleshooting

### Fork PRs

When a PR comes from a fork, the `GITHUB_TOKEN` has limited permissions and cannot create PR reviews. The action automatically detects this and falls back to posting a regular issue comment on the PR instead.

### Token Permissions

If you see warnings about failed API calls:
- Ensure the workflow has `pull-requests: write` permission.
- For SARIF uploads, add `security-events: write`.
- If using a custom token, verify it has the `repo` scope.

### SARIF Upload Failures

- SARIF upload requires GitHub Advanced Security to be enabled.
- For private repositories, this requires a GitHub Advanced Security license.
- Public repositories get Code Scanning for free.

### No Findings in PR Review

If findings exist but are not shown in the PR review:
- The action only annotates files that were changed in the PR.
- Use `drako scan .` locally to see all findings across the project.

## Local Development

Run the scan locally to see the same results:

```bash
pip install drako
drako scan .                    # Terminal output
drako scan . --format json      # JSON for CI parsing
drako scan . --format sarif     # SARIF for Code Scanning
drako scan . --benchmark        # Include benchmark comparison
```

## License

MIT
