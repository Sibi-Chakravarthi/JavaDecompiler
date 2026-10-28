"""
NeuroDecomp Security Auditing Layer (Phase 4).
"""

PRODUCT_NAME = "NeuroDecomp Security Auditor"
TOOL_VERSION = "0.1.0"

from javadecompiler.security.models import (
    Severity,
    Category,
    Kind,
    Verdict,
    Origin,
    Evidence,
    Location,
    Finding,
    MethodAnalysis,
    ClassAnalysis,
    CoverageStats,
    LlmStats,
    ScanResult,
)

__all__ = [
    "PRODUCT_NAME",
    "TOOL_VERSION",
    "Severity",
    "Category",
    "Kind",
    "Verdict",
    "Origin",
    "Evidence",
    "Location",
    "Finding",
    "MethodAnalysis",
    "ClassAnalysis",
    "CoverageStats",
    "LlmStats",
    "ScanResult",
]
