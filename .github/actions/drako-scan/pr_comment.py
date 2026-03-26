"""Post Drako governance scan findings as a GitHub PR review.

Reads /tmp/scan.json, filters findings to changed files, and posts
an inline PR review with up to 20 comments sorted by severity.

Environment variables (provided by GitHub Actions):
    GITHUB_TOKEN        - Authentication token
    GITHUB_REPOSITORY   - owner/repo
    GITHUB_EVENT_PATH   - Path to the event JSON payload
    INPUT_GITHUB_TOKEN  - Fallback token from action input
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCAN_JSON = "/tmp/scan.json"
MARKER = "<!-- drako-governance-scan -->"
MAX_INLINE_COMMENTS = 20
API_BASE = "https://api.github.com"
MAX_RETRIES = 4
INITIAL_BACKOFF = 1.0

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_token() -> str:
    """Resolve the GitHub token from environment."""
    token = os.environ.get("INPUT_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("::error::No GitHub token available for PR comments")
        sys.exit(1)
    return token


def _get_pr_number() -> int:
    """Extract PR number from the GitHub event payload."""
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path or not Path(event_path).is_file():
        print("::error::GITHUB_EVENT_PATH not set or file not found")
        sys.exit(1)

    with open(event_path) as f:
        event = json.load(f)

    pr_number = event.get("pull_request", {}).get("number")
    if not pr_number:
        print("::error::Could not find pull_request.number in event payload")
        sys.exit(1)
    return int(pr_number)


def _api_request(
    method: str,
    url: str,
    token: str,
    **kwargs: Any,
) -> requests.Response:
    """Make a GitHub API request with exponential backoff on rate limits."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    backoff = INITIAL_BACKOFF

    for attempt in range(MAX_RETRIES + 1):
        resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

        if resp.status_code not in (403, 429):
            return resp

        # Rate limited -- retry with backoff
        retry_after = resp.headers.get("Retry-After")
        wait = float(retry_after) if retry_after else backoff
        if attempt < MAX_RETRIES:
            print(f"::debug::Rate limited (HTTP {resp.status_code}), retrying in {wait:.1f}s")
            time.sleep(wait)
            backoff *= 2
        else:
            return resp

    return resp  # type: ignore[possibly-undefined]


# ---------------------------------------------------------------------------
# PR changed files
# ---------------------------------------------------------------------------


def get_changed_files(owner: str, repo: str, pr_number: int, token: str) -> set[str]:
    """Fetch the set of file paths changed in this PR."""
    files: set[str] = set()
    page = 1

    while True:
        url = f"{API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        resp = _api_request("GET", url, token, params={"per_page": 100, "page": page})
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        for f in batch:
            files.add(f["filename"])
        if len(batch) < 100:
            break
        page += 1

    return files


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def filter_findings_to_changed(
    findings: list[dict[str, Any]],
    changed_files: set[str],
) -> list[dict[str, Any]]:
    """Return only findings whose file_path is in the PR diff."""
    return [f for f in findings if f.get("file_path") in changed_files]


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort findings by severity (critical first), then by file path."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "LOW"), 99), f.get("file_path", "")),
    )


# ---------------------------------------------------------------------------
# Comment body
# ---------------------------------------------------------------------------


def build_summary_body(
    scan_data: dict[str, Any],
    pr_findings_count: int,
    total_findings: int,
    baseline_count: int = 0,
) -> str:
    """Build the markdown summary body for the PR review."""
    score = scan_data.get("score", 0)
    grade = scan_data.get("grade", "?")
    summary = scan_data.get("summary", {})

    lines = [
        MARKER,
        "",
        f"## Drako Governance Scan",
        "",
        f"**Score:** {score}/100 ({grade})",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {summary.get('critical', 0)} |",
        f"| High | {summary.get('high', 0)} |",
        f"| Medium | {summary.get('medium', 0)} |",
        f"| Low | {summary.get('low', 0)} |",
        f"| **Total** | **{total_findings}** |",
        "",
    ]

    if baseline_count > 0:
        lines.append(f"_{baseline_count} baselined finding(s) suppressed._")
        lines.append("")

    if pr_findings_count == 0:
        lines.append("No governance findings in the changed files. All clear!")
    elif pr_findings_count > MAX_INLINE_COMMENTS:
        lines.append(
            f"Showing top {MAX_INLINE_COMMENTS} of {pr_findings_count} findings "
            f"in changed files. Run `drako scan` locally for the full report."
        )
    else:
        lines.append(
            f"{pr_findings_count} finding(s) in changed files (see inline comments)."
        )

    lines.extend([
        "",
        "---",
        "_Run `pip install drako && drako scan .` locally for the full report._",
    ])

    return "\n".join(lines)


def build_review_comments(
    findings: list[dict[str, Any]],
    commit_sha: str,
) -> list[dict[str, str | int]]:
    """Build inline review comment objects for the GitHub API."""
    comments: list[dict[str, str | int]] = []

    for finding in findings[:MAX_INLINE_COMMENTS]:
        severity = finding.get("severity", "LOW")
        emoji = SEVERITY_EMOJI.get(severity, "")
        policy_id = finding.get("policy_id", "")
        title = finding.get("title", "")
        message = finding.get("message", "")
        fix = finding.get("fix_snippet", "")

        body_parts = [f"{emoji} **{severity}** `{policy_id}` {title}", "", message]
        if fix:
            body_parts.extend(["", "**Suggested fix:**", f"```python\n{fix}\n```"])

        line = finding.get("line_number")
        path = finding.get("file_path", "")

        comment: dict[str, str | int] = {
            "path": path,
            "body": "\n".join(body_parts),
        }
        if line and isinstance(line, int) and line > 0:
            comment["line"] = line
        else:
            # If no valid line, use line 1 as fallback
            comment["line"] = 1

        comments.append(comment)

    return comments


# ---------------------------------------------------------------------------
# Review management (find / dismiss old, create new)
# ---------------------------------------------------------------------------


def find_existing_review(
    owner: str,
    repo: str,
    pr_number: int,
    token: str,
) -> int | None:
    """Find an existing Drako review by checking for the marker comment."""
    url = f"{API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    resp = _api_request("GET", url, token, params={"per_page": 100})
    if resp.status_code != 200:
        return None

    for review in resp.json():
        body = review.get("body", "") or ""
        if MARKER in body:
            return review.get("id")
    return None


def dismiss_review(
    owner: str,
    repo: str,
    pr_number: int,
    review_id: int,
    token: str,
) -> None:
    """Dismiss an old Drako review."""
    url = f"{API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/reviews/{review_id}/dismissals"
    _api_request(
        "PUT",
        url,
        token,
        json={"message": "Superseded by new Drako scan."},
    )


def create_review(
    owner: str,
    repo: str,
    pr_number: int,
    token: str,
    body: str,
    comments: list[dict[str, str | int]],
    commit_sha: str,
) -> bool:
    """Create a PR review. Returns True on success."""
    url = f"{API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    payload: dict[str, Any] = {
        "commit_id": commit_sha,
        "body": body,
        "event": "COMMENT",
    }
    if comments:
        payload["comments"] = comments

    resp = _api_request("POST", url, token, json=payload)

    if resp.status_code == 200 or resp.status_code == 201:
        return True

    # Fork PRs may lack permission for reviews -- fall back to issue comment
    if resp.status_code == 403 or resp.status_code == 422:
        print("::warning::Cannot create PR review (fork or permissions). Falling back to issue comment.")
        return post_issue_comment(owner, repo, pr_number, token, body)

    print(f"::error::Failed to create review: HTTP {resp.status_code} {resp.text[:500]}")
    return False


def post_issue_comment(
    owner: str,
    repo: str,
    pr_number: int,
    token: str,
    body: str,
) -> bool:
    """Fall back to a plain issue comment when review creation fails."""
    url = f"{API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/comments"

    # Check for existing comment with our marker and update it
    list_resp = _api_request("GET", url, token, params={"per_page": 100})
    if list_resp.status_code == 200:
        for comment in list_resp.json():
            if MARKER in (comment.get("body", "") or ""):
                update_url = f"{API_BASE}/repos/{owner}/{repo}/issues/comments/{comment['id']}"
                update_resp = _api_request("PATCH", update_url, token, json={"body": body})
                if update_resp.status_code == 200:
                    print("::notice::Updated existing issue comment")
                    return True

    resp = _api_request("POST", url, token, json={"body": body})
    if resp.status_code in (200, 201):
        print("::notice::Posted issue comment as fallback")
        return True

    print(f"::error::Failed to post issue comment: HTTP {resp.status_code}")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    """Entry point. Returns 0 on success, non-zero on API errors."""
    # Load scan results
    try:
        with open(SCAN_JSON) as f:
            scan_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"::error::Failed to read scan results: {exc}")
        return 1

    # Resolve context
    token = _get_token()
    pr_number = _get_pr_number()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repository:
        print("::error::GITHUB_REPOSITORY not set or invalid")
        return 1

    owner, repo = repository.split("/", 1)
    commit_sha = os.environ.get("GITHUB_SHA", "HEAD")

    # Get changed files
    try:
        changed_files = get_changed_files(owner, repo, pr_number, token)
    except requests.HTTPError as exc:
        print(f"::error::Failed to fetch changed files: {exc}")
        return 1

    # Filter findings to changed files
    all_findings = scan_data.get("findings", [])
    pr_findings = filter_findings_to_changed(all_findings, changed_files)
    pr_findings = sort_findings(pr_findings)

    total_findings = scan_data.get("summary", {}).get("total", len(all_findings))

    # Build comment body
    body = build_summary_body(
        scan_data,
        pr_findings_count=len(pr_findings),
        total_findings=total_findings,
    )

    # Build inline comments
    comments = build_review_comments(pr_findings, commit_sha)

    # Dismiss old review if present
    old_review_id = find_existing_review(owner, repo, pr_number, token)
    if old_review_id is not None:
        dismiss_review(owner, repo, pr_number, old_review_id, token)

    # Create the review
    success = create_review(owner, repo, pr_number, token, body, comments, commit_sha)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
