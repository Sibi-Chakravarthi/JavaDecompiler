"""
scanner.py — Security Scanner Orchestrator for NeuroDecomp Phase 4.

Coordinates:
  - Layer A: Static Rule Engine (rules/)
  - Layer B: Behavior Chains & Taint-Lite (behavior.py)
  - Layer C: Local LLM Auditor (llm/harness.py)
  - Scoring & Verdicts (scoring.py)
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from javadecompiler.class_parser import ClassInfo, parseClassFile, parseJarFile
from javadecompiler.security.models import (
    ClassAnalysis,
    CoverageStats,
    Finding,
    LlmStats,
    MethodAnalysis,
    ScanResult,
    Verdict,
)
from javadecompiler.security.rules.base import SecurityRule, get_all_rules


class SecurityScanner:
    """Orchestrates static rules, behavior chains, LLM audit, and scoring."""

    def __init__(
        self,
        enable_llm: bool = False,
        audit_model: str = "qwen2.5-coder:14b",
        llm_scope: str = "suspicious",
        llm_investigate: bool = False,
        llm_votes: int = 1,
        min_severity: str = "info",
        enabled_rules: Optional[List[str]] = None,
        disabled_rules: Optional[List[str]] = None,
        no_cache: bool = False,
        refresh_cache: bool = False,
    ) -> None:
        self.enable_llm = enable_llm
        self.audit_model = audit_model
        self.llm_scope = llm_scope
        self.llm_investigate = llm_investigate
        self.llm_votes = llm_votes
        self.min_severity = min_severity
        self.enabled_rules = enabled_rules or []
        self.disabled_rules = disabled_rules or []
        self.no_cache = no_cache
        self.refresh_cache = refresh_cache
        self.rules: List[SecurityRule] = get_all_rules(self.enabled_rules, self.disabled_rules)

    def scan_bytes(self, file_bytes: bytes, file_name: str) -> ScanResult:
        """Scans in-memory bytes of a .class or .jar file."""
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Initial baseline ScanResult for Milestone 1
        result = ScanResult(
            schemaVersion="1.0.0",
            inputSha256=sha256,
            inputName=file_name,
            timestamp=timestamp,
            toolVersion="0.1.0",
            config={
                "enable_llm": self.enable_llm,
                "audit_model": self.audit_model,
                "llm_scope": self.llm_scope,
                "min_severity": self.min_severity,
            },
            overallVerdict=Verdict.CLEAN.value,
            overallRiskScore=0.0,
            topReasons=["No security findings identified."],
            classes={},
            jarFindings=[],
            coverageStats=CoverageStats(totalMethods=0, fullCoverageMethods=0),
            llmStats=LlmStats(enabled=self.enable_llm, model=self.audit_model),
        )
        return result

    def scan_file(self, file_path: str) -> ScanResult:
        """Scans a file from disk (.class or .jar)."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target file not found: {file_path}")

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        return self.scan_bytes(file_bytes, os.path.basename(file_path))
