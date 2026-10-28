"""
sarif.py — SARIF 2.1.0 JSON exporter for GitHub Code Scanning and IDE integration.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from javadecompiler.security import PRODUCT_NAME, TOOL_VERSION
from javadecompiler.security.models import Finding, ScanResult, Severity


def severity_to_sarif_level(severity: str) -> str:
    """Maps internal severity levels to SARIF 2.1.0 level strings ('error', 'warning', 'note')."""
    s = severity.lower()
    if s in (Severity.CRITICAL.value, Severity.HIGH.value):
        return "error"
    elif s == Severity.MEDIUM.value:
        return "warning"
    else:
        return "note"


def to_sarif(
    scan_result: ScanResult,
    indent: int = 2,
) -> str:
    """Converts a ScanResult into standard SARIF 2.1.0 JSON format."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    results_list: List[Dict[str, Any]] = []

    all_findings = scan_result.allFindings

    for finding in all_findings:
        rule_id = finding.ruleId
        if rule_id not in rules_dict:
            tags = ["security"]
            if finding.cwe:
                tags.extend(finding.cwe)
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe[0].replace('CWE-', '')}.html" if finding.cwe else "",
                "properties": {
                    "category": finding.category,
                    "kind": finding.kind,
                    "defaultSeverity": finding.severity,
                    "tags": tags,
                },
            }

        # Determine file URI and line
        artifact_uri = finding.location.jarEntryPath or (finding.location.className.replace(".", "/") + ".java")
        start_line = finding.location.liftedLineNumbers[0] if finding.location.liftedLineNumbers else 1

        sarif_result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": severity_to_sarif_level(finding.severity),
            "message": {"text": f"{finding.title}: {finding.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, start_line),
                            "startColumn": 1,
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": finding.location.methodName or finding.location.className,
                            "kind": "function" if finding.location.methodName else "class",
                            "fullyQualifiedName": f"{finding.location.className}#{finding.location.methodName}" if finding.location.methodName else finding.location.className,
                        }
                    ],
                }
            ],
            "properties": {
                "confidence": round(finding.confidence, 2),
                "remediation": finding.remediation,
                "origin": finding.origin,
                "findingId": finding.findingId,
            },
        }

        # Related locations / evidence
        if finding.evidence:
            sarif_ev = []
            for ev in finding.evidence:
                sarif_ev.append({
                    "message": {"text": f"[{ev.type.upper()}] {ev.text}"},
                })
            sarif_result["properties"]["evidence"] = sarif_ev

        results_list.append(sarif_result)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": PRODUCT_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/Sibi-Chakravarthi/JavaDecompiler",
                        "rules": list(rules_dict.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": scan_result.timestamp,
                    }
                ],
                "results": results_list,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)


def save_sarif(
    scan_result: ScanResult,
    output_path: str,
    indent: int = 2,
) -> None:
    """Saves SARIF 2.1.0 report directly to file."""
    sarif_str = to_sarif(scan_result, indent=indent)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(sarif_str)
