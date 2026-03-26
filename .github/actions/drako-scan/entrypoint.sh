#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Drako Governance Scan  --  GitHub Action entrypoint
# ---------------------------------------------------------------------------

SCAN_PATH="${INPUT_PATH:-.}"
THRESHOLD="${INPUT_THRESHOLD:-0}"
FAIL_ON="${INPUT_FAIL_ON:-critical}"
COMMENT_ON_PR="${INPUT_COMMENT_ON_PR:-true}"
UPLOAD_SARIF="${INPUT_UPLOAD_SARIF:-true}"
USE_BENCHMARK="${INPUT_BENCHMARK:-true}"
USE_BASELINE="${INPUT_BASELINE:-true}"
GITHUB_TOKEN="${INPUT_GITHUB_TOKEN:-}"

SCAN_JSON="/tmp/scan.json"
SARIF_FILE="/tmp/scan.sarif"

# ---------------------------------------------------------------------------
# 1. Build scan command
# ---------------------------------------------------------------------------
SCAN_CMD="drako scan ${SCAN_PATH} --format json"

if [ "${USE_BENCHMARK}" = "true" ]; then
    SCAN_CMD="${SCAN_CMD} --benchmark"
fi

if [ "${USE_BASELINE}" = "true" ] && [ -f "${SCAN_PATH}/.drako/.baseline.json" ]; then
    echo "::debug::Baseline found at ${SCAN_PATH}/.drako/.baseline.json"
    # Baseline filtering is automatic when .baseline.json exists
fi

# ---------------------------------------------------------------------------
# 2. Run the scan (always exit 0 here; we decide exit code later)
# ---------------------------------------------------------------------------
echo "::group::Running Drako scan"
set +e
eval "${SCAN_CMD}" > "${SCAN_JSON}" 2>/dev/null
SCAN_EXIT=$?
set -e
echo "::endgroup::"

# Validate that we got valid JSON
if ! jq empty "${SCAN_JSON}" 2>/dev/null; then
    echo "::error::Drako scan did not produce valid JSON output"
    exit 2
fi

# ---------------------------------------------------------------------------
# 3. Extract results
# ---------------------------------------------------------------------------
SCORE=$(jq -r '.score' "${SCAN_JSON}")
GRADE=$(jq -r '.grade' "${SCAN_JSON}")
TOTAL=$(jq -r '.summary.total' "${SCAN_JSON}")
CRITICAL=$(jq -r '.summary.critical' "${SCAN_JSON}")
HIGH=$(jq -r '.summary.high' "${SCAN_JSON}")
MEDIUM=$(jq -r '.summary.medium' "${SCAN_JSON}")
LOW=$(jq -r '.summary.low' "${SCAN_JSON}")

echo "::notice::Drako Score: ${SCORE}/100 (${GRADE}) | Findings: ${TOTAL} (${CRITICAL}C/${HIGH}H/${MEDIUM}M/${LOW}L)"

# ---------------------------------------------------------------------------
# 4. Set outputs
# ---------------------------------------------------------------------------
{
    echo "score=${SCORE}"
    echo "grade=${GRADE}"
    echo "findings-count=${TOTAL}"
} >> "${GITHUB_OUTPUT}"

# ---------------------------------------------------------------------------
# 5. SARIF upload (if enabled)
# ---------------------------------------------------------------------------
if [ "${UPLOAD_SARIF}" = "true" ]; then
    echo "::group::Generating SARIF"
    SARIF_CMD="drako scan ${SCAN_PATH} --format sarif"
    set +e
    eval "${SARIF_CMD}" > "${SARIF_FILE}" 2>/dev/null
    set -e

    if jq empty "${SARIF_FILE}" 2>/dev/null; then
        echo "SARIF written to ${SARIF_FILE}"
        # Upload via the GitHub Code Scanning API
        if [ -n "${GITHUB_TOKEN}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
            SARIF_B64=$(gzip -c "${SARIF_FILE}" | base64 -w 0)
            COMMIT_SHA="${GITHUB_SHA:-$(git -C "${SCAN_PATH}" rev-parse HEAD 2>/dev/null || echo "unknown")}"
            REF="${GITHUB_REF:-refs/heads/main}"

            HTTP_CODE=$(curl -s -o /tmp/sarif_response.json -w "%{http_code}" \
                -X POST \
                -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                -H "Accept: application/vnd.github+json" \
                -H "X-GitHub-Api-Version: 2022-11-28" \
                "https://api.github.com/repos/${GITHUB_REPOSITORY}/code-scanning/sarifs" \
                -d "{\"commit_sha\":\"${COMMIT_SHA}\",\"ref\":\"${REF}\",\"sarif\":\"${SARIF_B64}\",\"tool_name\":\"drako\"}")

            if [ "${HTTP_CODE}" -ge 200 ] && [ "${HTTP_CODE}" -lt 300 ]; then
                echo "::notice::SARIF uploaded to GitHub Code Scanning"
            else
                echo "::warning::SARIF upload returned HTTP ${HTTP_CODE}"
            fi
        else
            echo "::warning::Skipping SARIF upload (missing token or repository context)"
        fi
    else
        echo "::warning::SARIF generation did not produce valid JSON"
    fi
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 6. PR comment (if enabled and running on a pull_request event)
# ---------------------------------------------------------------------------
if [ "${COMMENT_ON_PR}" = "true" ] && [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; then
    echo "::group::Posting PR review"
    set +e
    python /pr_comment.py
    PR_EXIT=$?
    set -e
    if [ "${PR_EXIT}" -ne 0 ]; then
        echo "::warning::PR comment script exited with code ${PR_EXIT}"
    fi
    echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# 7. Determine exit code
# ---------------------------------------------------------------------------

# Check threshold
if [ "${THRESHOLD}" -gt 0 ] && [ "${SCORE}" -lt "${THRESHOLD}" ]; then
    echo "::error::Governance score ${SCORE} is below threshold ${THRESHOLD}"
    exit 1
fi

# Check fail-on severity
EXIT_CODE=0
case "${FAIL_ON}" in
    critical)
        [ "${CRITICAL}" -gt 0 ] && EXIT_CODE=1
        ;;
    high)
        [ "${CRITICAL}" -gt 0 ] || [ "${HIGH}" -gt 0 ] && EXIT_CODE=1
        ;;
    medium)
        [ "${CRITICAL}" -gt 0 ] || [ "${HIGH}" -gt 0 ] || [ "${MEDIUM}" -gt 0 ] && EXIT_CODE=1
        ;;
    low)
        [ "${TOTAL}" -gt 0 ] && EXIT_CODE=1
        ;;
    *)
        # Unknown level -- only fail on critical
        [ "${CRITICAL}" -gt 0 ] && EXIT_CODE=1
        ;;
esac

if [ "${EXIT_CODE}" -ne 0 ]; then
    echo "::error::Scan failed: findings at or above '${FAIL_ON}' severity detected"
fi

exit "${EXIT_CODE}"
