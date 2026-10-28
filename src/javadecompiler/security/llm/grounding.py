"""
grounding.py — Anti-hallucination evidence verification for LLM auditor harness.

Verifies every citation (I:0x.., CP:.., L:..) emitted by the LLM against the real
method artifacts (disassembled offsets, constant pool indices, lifted source lines).
Drops ungrounded findings and downweights partially grounded findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from javadecompiler.security.models import (
    Category,
    Evidence,
    Finding,
    Kind,
    Location,
    Origin,
    Severity,
)


@dataclass
class GroundingResult:
    status: str  # "valid" | "partial" | "dropped"
    grounded_finding: Optional[Finding] = None
    dropped_reason: Optional[str] = None
    original_evidence_count: int = 0
    valid_evidence_count: int = 0


def parse_evidence_id(ev_id: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Parses an evidence ID string:
      'I:0x1a' -> ('instruction', 26)
      'I:26'   -> ('instruction', 26)
      'CP:14'  -> ('constantPool', 14)
      'L:8'    -> ('liftedLine', 8)
    """
    ev_id = ev_id.strip()
    if ev_id.startswith("I:"):
        raw_val = ev_id[2:].strip()
        try:
            val = int(raw_val, 16) if raw_val.startswith("0x") or raw_val.startswith("0X") else int(raw_val)
            return ("instruction", val)
        except ValueError:
            return (None, None)
    elif ev_id.startswith("CP:"):
        try:
            return ("constantPool", int(ev_id[3:].strip()))
        except ValueError:
            return (None, None)
    elif ev_id.startswith("L:"):
        try:
            return ("liftedLine", int(ev_id[2:].strip()))
        except ValueError:
            return (None, None)
    return (None, None)


def verify_finding_grounding(
    raw_finding: Dict[str, Any],
    class_name: str,
    method_name: str,
    descriptor: str,
    valid_offsets: Set[int],
    valid_cp_indices: Set[int],
    valid_line_numbers: Set[int],
    offset_to_text: Optional[Dict[int, str]] = None,
    cp_to_text: Optional[Dict[int, str]] = None,
    line_to_text: Optional[Dict[int, str]] = None,
    model_name: Optional[str] = None,
    model_digest: Optional[str] = None,
    prompt_version: str = "1.0.0",
) -> GroundingResult:
    """
    Verifies that all evidence IDs in raw_finding are grounded in actual method artifacts.
    - Zero valid evidence IDs -> drop finding completely.
    - Partial evidence IDs -> keep valid, scale confidence * 0.6.
    - Caps severity at MEDIUM for purely LLM-generated findings without corroboration.
    """
    raw_evidence_ids = raw_finding.get("evidenceIds", [])
    if not isinstance(raw_evidence_ids, list):
        raw_evidence_ids = []

    valid_evidences: List[Evidence] = []
    matched_offsets: List[int] = []
    matched_lines: List[int] = []

    for ev_id in raw_evidence_ids:
        if not isinstance(ev_id, str):
            continue
        ev_type, ev_val = parse_evidence_id(ev_id)
        if ev_type is None or ev_val is None:
            continue

        if ev_type == "instruction" and ev_val in valid_offsets:
            ins_text = (offset_to_text or {}).get(ev_val, f"offset 0x{ev_val:02x}")
            valid_evidences.append(Evidence(
                id=f"I:0x{ev_val:02x}",
                type="instruction",
                text=ins_text,
                offset=ev_val,
            ))
            matched_offsets.append(ev_val)

        elif ev_type == "constantPool" and ev_val in valid_cp_indices:
            cp_text = (cp_to_text or {}).get(ev_val, f"CP index {ev_val}")
            valid_evidences.append(Evidence(
                id=f"CP:{ev_val}",
                type="constantPool",
                text=cp_text,
                index=ev_val,
            ))

        elif ev_type == "liftedLine" and ev_val in valid_line_numbers:
            line_text = (line_to_text or {}).get(ev_val, f"line {ev_val}")
            valid_evidences.append(Evidence(
                id=f"L:{ev_val}",
                type="liftedLine",
                text=line_text,
                line=ev_val,
            ))
            matched_lines.append(ev_val)

    original_count = len(raw_evidence_ids)
    valid_count = len(valid_evidences)

    # Rule: If ZERO cited evidence IDs exist, discard finding completely
    if valid_count == 0:
        return GroundingResult(
            status="dropped",
            dropped_reason=f"Zero valid evidence citations found out of {original_count} cited.",
            original_evidence_count=original_count,
            valid_evidence_count=0,
        )

    # Initial confidence
    confidence = float(raw_finding.get("confidence", 0.8))
    status = "valid"

    # If partial, downweight confidence
    if valid_count < original_count:
        confidence = round(confidence * 0.6, 3)
        status = "partial"

    # Severity handling: purely LLM-generated findings capped at MEDIUM
    raw_sev = str(raw_finding.get("severity", Severity.MEDIUM.value)).lower()
    sev_values = [s.value for s in Severity]
    if raw_sev not in sev_values:
        raw_sev = Severity.MEDIUM.value

    # Cap LLM-only findings without static corroboration to at most medium
    if raw_sev in (Severity.CRITICAL.value, Severity.HIGH.value):
        raw_sev = Severity.MEDIUM.value

    title = str(raw_finding.get("title", "LLM-identified Security Issue")).strip()
    rationale = str(raw_finding.get("rationale", "")).strip()
    remediation = str(raw_finding.get("remediation", "Review method logic for potential security issues.")).strip()
    cwe = [str(c) for c in raw_finding.get("cwe", []) if isinstance(c, str)]

    # Category and Kind validation
    kind = str(raw_finding.get("kind", Kind.VULNERABILITY.value)).lower()
    if kind not in [k.value for k in Kind]:
        kind = Kind.VULNERABILITY.value

    category = str(raw_finding.get("category", Category.EXECUTION.value)).lower()
    if category not in [c.value for c in Category]:
        category = Category.EXECUTION.value

    location = Location(
        className=class_name,
        methodName=method_name,
        descriptor=descriptor,
        bytecodeOffsets=matched_offsets,
        liftedLineNumbers=matched_lines,
    )

    finding = Finding(
        ruleId="JD-LLM-AUDIT",
        title=title,
        description=rationale or title,
        remediation=remediation,
        kind=kind,
        category=category,
        severity=raw_sev,
        confidence=confidence,
        confidenceSources={"llm_auditor": confidence},
        cwe=cwe,
        location=location,
        evidence=valid_evidences,
        origin=Origin.LLM.value,
        ruleVersion="1.0.0",
        promptVersion=prompt_version,
        modelName=model_name,
        modelDigest=model_digest,
        llmRationale=rationale,
    )

    return GroundingResult(
        status=status,
        grounded_finding=finding,
        original_evidence_count=original_count,
        valid_evidence_count=valid_count,
    )
