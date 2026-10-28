"""
json_out.py — Schema-versioned JSON report serializer.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from javadecompiler.security.models import ScanResult, Severity


def to_json(
    scan_result: ScanResult,
    indent: int = 2,
    min_severity: Optional[str] = None,
) -> str:
    """Serializes a ScanResult object to a clean, schema-compliant JSON string."""
    d = scan_result.to_dict()

    if min_severity and min_severity.lower() != "info":
        sev_rank = {
            Severity.INFO.value: 1,
            Severity.LOW.value: 2,
            Severity.MEDIUM.value: 3,
            Severity.HIGH.value: 4,
            Severity.CRITICAL.value: 5,
        }
        min_rank = sev_rank.get(min_severity.lower(), 1)

        # Filter jar findings
        d["jarFindings"] = [f for f in d.get("jarFindings", []) if sev_rank.get(f.get("severity", "info"), 1) >= min_rank]

        # Filter class and method findings
        for c in d.get("classes", {}).values():
            c["findings"] = [f for f in c.get("findings", []) if sev_rank.get(f.get("severity", "info"), 1) >= min_rank]
            for m in c.get("methods", {}).values():
                m["findings"] = [f for f in m.get("findings", []) if sev_rank.get(f.get("severity", "info"), 1) >= min_rank]

    return json.dumps(d, indent=indent)


def save_json(
    scan_result: ScanResult,
    output_path: str,
    indent: int = 2,
    min_severity: Optional[str] = None,
) -> None:
    """Writes ScanResult JSON directly to the specified file path."""
    payload = to_json(scan_result, indent=indent, min_severity=min_severity)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(payload)
