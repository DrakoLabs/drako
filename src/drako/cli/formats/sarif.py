"""SARIF 2.1.0 output format for GitHub Code Scanning integration.

Generates SARIF JSON that can be uploaded to GitHub via:
  gh api repos/{owner}/{repo}/code-scanning/sarifs -f sarif=@results.sarif
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.scanner import ScanResult

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Map our severity levels to SARIF levels
_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def format_sarif(result: ScanResult) -> str:
    """Generate SARIF 2.1.0 JSON for GitHub Code Scanning."""

    # Build rules from unique policy IDs
    seen_rules: dict[str, int] = {}
    rules = []

    for finding in result.findings:
        if finding.policy_id not in seen_rules:
            seen_rules[finding.policy_id] = len(rules)
            rules.append({
                "id": finding.policy_id,
                "name": finding.policy_id.replace("-", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.message},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "note"),
                },
                "properties": {
                    "tags": [finding.category.lower()],
                },
            })

    # Build results
    sarif_results = []
    for finding in result.findings:
        sarif_result: dict = {
            "ruleId": finding.policy_id,
            "ruleIndex": seen_rules[finding.policy_id],
            "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "note"),
            "message": {"text": finding.message},
        }

        # Add location if we have file info
        if finding.file_path:
            location: dict = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                },
            }
            if finding.line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line_number,
                }
            sarif_result["locations"] = [location]

        # Add fix if available
        if finding.fix_snippet:
            sarif_result["fixes"] = [{
                "description": {"text": "Suggested fix"},
                "artifactChanges": [{
                    "artifactLocation": {
                        "uri": finding.file_path or "unknown",
                    },
                    "replacements": [{
                        "deletedRegion": {
                            "startLine": finding.line_number or 1,
                        },
                        "insertedContent": {
                            "text": finding.fix_snippet,
                        },
                    }],
                }],
            }]

        sarif_results.append(sarif_result)

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Drako",
                    "informationUri": "https://useagentmesh.com",
                    "version": "0.1.0",
                    "rules": rules,
                },
            },
            "results": sarif_results,
        }],
    }

    return json.dumps(sarif, indent=2)
