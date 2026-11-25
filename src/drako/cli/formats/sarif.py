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


def format_sarif(
    result: ScanResult,
    baseline_fingerprints: set[str] | None = None,
) -> str:
    """Generate SARIF 2.1.0 JSON for GitHub Code Scanning."""

    # Build rules from unique policy IDs
    seen_rules: dict[str, int] = {}
    rules = []

    for finding in result.findings:
        if finding.policy_id not in seen_rules:
            seen_rules[finding.policy_id] = len(rules)
            full_desc = finding.message
            if finding.impact:
                full_desc += f"\n\nImpact: {finding.impact}"

            rule_entry: dict = {
                "id": finding.policy_id,
                "name": finding.policy_id.replace("-", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": full_desc},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "note"),
                },
                "properties": {
                    "tags": [finding.category.lower()],
                },
            }

            if finding.references:
                rule_entry["helpUri"] = finding.references[0]
                rule_entry["properties"]["references"] = finding.references
            if finding.attack_scenario:
                rule_entry["properties"]["attack_scenario"] = finding.attack_scenario
            if finding.remediation_effort:
                rule_entry["properties"]["remediation_effort"] = finding.remediation_effort
            rule_entry["properties"]["finding_type"] = getattr(finding, "finding_type", "vulnerability")

            # Add advisory references if available
            matched = result.matched_advisories.get(finding.policy_id, [])
            if matched:
                rule_entry["properties"]["advisories"] = [
                    {"id": adv.id, "title": adv.title} for adv in matched
                ]

            rules.append(rule_entry)

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

        # Baseline state
        if baseline_fingerprints is not None:
            from drako.cli.baseline import fingerprint
            fp = fingerprint(finding)
            if fp in baseline_fingerprints:
                sarif_result["baselineState"] = "unchanged"
            else:
                sarif_result["baselineState"] = "new"

        sarif_results.append(sarif_result)

    run_properties = {
        "governance_score": result.score,
        "governance_grade": result.grade,
        "determinism_score": result.determinism_score,
        "determinism_grade": result.determinism_grade,
    }

    from drako import __version__ as drako_version

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Drako",
                    "informationUri": "https://github.com/DrakoLabs/drako",
                    "version": drako_version,
                    "rules": rules,
                },
            },
            "results": sarif_results,
            "properties": run_properties,
        }],
    }

    return json.dumps(sarif, indent=2)
