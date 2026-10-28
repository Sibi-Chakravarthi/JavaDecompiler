"""
scoring.py — Risk scoring (0-100), severity modifiers, and verdict aggregation logic.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from javadecompiler.security.models import (
    Category,
    Finding,
    Kind,
    Severity,
    Verdict,
)

SEVERITY_WEIGHTS: Dict[str, float] = {
    Severity.CRITICAL.value: 40.0,
    Severity.HIGH.value: 25.0,
    Severity.MEDIUM.value: 12.0,
    Severity.LOW.value: 4.0,
    Severity.INFO.value: 1.0,
}


def calculate_risk_score(
    findings: List[Finding],
    has_clinit_reachability: bool = False,
) -> float:
    """Computes a composite risk score (0-100) based on findings, category diversity, and load-time reachability."""
    if not findings:
        return 0.0

    # Group findings by category to apply diminishing returns for duplicates
    by_category: Dict[str, List[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    score = 0.0
    for cat, cat_findings in by_category.items():
        # Sort by base weight descending
        sorted_f = sorted(
            cat_findings,
            key=lambda x: SEVERITY_WEIGHTS.get(x.severity, 0.0) * x.confidence,
            reverse=True,
        )
        for idx, f in enumerate(sorted_f):
            base_w = SEVERITY_WEIGHTS.get(f.severity, 4.0) * f.confidence
            if idx == 0:
                diminishing_factor = 1.0
            elif idx == 1:
                diminishing_factor = 0.6
            else:
                diminishing_factor = 0.3
            score += base_w * diminishing_factor

    # Co-occurrence bonus: 3+ distinct suspicious categories present
    distinct_categories = set(by_category.keys())
    high_threat_cats = {
        Category.EXECUTION.value,
        Category.NETWORK.value,
        Category.EVASION.value,
        Category.DYNAMIC_LOADING.value,
        Category.PERSISTENCE.value,
    }
    if len(distinct_categories.intersection(high_threat_cats)) >= 3:
        score += 15.0

    # Load-time reachability bonus
    if has_clinit_reachability or any(f.ruleId == "JD-LOAD-001" or f.ruleId == "JD-CHAIN-CLINIT" for f in findings):
        score += 15.0

    return min(100.0, round(score, 1))


def determine_verdict(
    risk_score: float,
    findings: List[Finding],
    partial_coverage_count: int = 0,
    failed_methods_count: int = 0,
) -> Tuple[str, List[str]]:
    """Determines final Verdict enum and extracts top 3 plain-English reasons."""
    reasons: List[str] = []

    # Check for critical malicious indicators or exploit chains
    malicious_indicators = [
        f
        for f in findings
        if f.kind == Kind.MALICIOUS_INDICATOR.value
        or f.ruleId.startswith("JD-CHAIN-")
        or (f.severity == Severity.CRITICAL.value and f.kind != Kind.VULNERABILITY.value)
    ]

    has_critical_exploit = any(f.severity == Severity.CRITICAL.value for f in findings)
    has_high_suspicious = any(
        f.severity in (Severity.HIGH.value, Severity.CRITICAL.value) and f.kind in (Kind.SUSPICIOUS_BEHAVIOR.value, Kind.MALICIOUS_INDICATOR.value)
        for f in findings
    )
    has_vulnerability = any(f.kind == Kind.VULNERABILITY.value for f in findings)

    # 1. LIKELY_MALICIOUS
    if risk_score >= 70.0 or len(malicious_indicators) >= 2 or (has_critical_exploit and malicious_indicators):
        verdict = Verdict.LIKELY_MALICIOUS.value
        for f in malicious_indicators[:3]:
            loc = f"{f.location.className}#{f.location.methodName}" if f.location.methodName else f.location.className
            reasons.append(f"{f.title} detected in {loc}")

    # 2. SUSPICIOUS
    elif risk_score >= 40.0 or has_high_suspicious:
        verdict = Verdict.SUSPICIOUS.value
        for f in [f for f in findings if f.severity in (Severity.HIGH.value, Severity.CRITICAL.value)][:3]:
            loc = f"{f.location.className}#{f.location.methodName}" if f.location.methodName else f.location.className
            reasons.append(f"{f.title} detected in {loc}")

    # 3. VULNERABLE
    elif has_vulnerability or any(f.severity in (Severity.HIGH.value, Severity.MEDIUM.value) for f in findings):
        verdict = Verdict.VULNERABLE.value
        for f in [f for f in findings if f.kind == Kind.VULNERABILITY.value][:3]:
            loc = f"{f.location.className}#{f.location.methodName}" if f.location.methodName else f.location.className
            reasons.append(f"{f.title} in {loc} ({', '.join(f.cwe) if f.cwe else 'Security Weakness'})")

    # 4. REVIEW_RECOMMENDED
    elif partial_coverage_count > 0 or failed_methods_count > 0 or risk_score > 10.0 or findings:
        verdict = Verdict.REVIEW_RECOMMENDED.value
        if partial_coverage_count > 0:
            reasons.append(f"{partial_coverage_count} method(s) had partial analysis coverage due to unsupported opcodes or obfuscation")
        if failed_methods_count > 0:
            reasons.append(f"{failed_methods_count} method(s) failed disassembly")
        for f in findings[:2]:
            reasons.append(f"{f.title} ({f.severity})")

    # 5. CLEAN (Strict check: 0 findings AND 0 partial/failed methods)
    else:
        verdict = Verdict.CLEAN.value
        reasons.append("Zero security findings or malicious indicators identified.")
        reasons.append("Full analysis coverage across all methods.")

    # Never return CLEAN if partial coverage exists!
    if verdict == Verdict.CLEAN.value and (partial_coverage_count > 0 or failed_methods_count > 0):
        verdict = Verdict.REVIEW_RECOMMENDED.value
        reasons = [f"Analysis coverage partial ({partial_coverage_count} methods partial, {failed_methods_count} failed). Manual review advised."]

    # Fallback reasons if empty
    if not reasons:
        reasons = ["Automated scan completed successfully."]

    return verdict, reasons[:3]
