"""
scanner.py — Security Scanner Orchestrator for NeuroDecomp Phase 4.

Coordinates:
  - Archive/JAR checks & limits (jar_checks.py)
  - Layer A: Deterministic Static Rule Engine (rules/)
  - Layer B: Behavior Chains & Taint-Lite (behavior.py)
  - Layer C: Local LLM Auditor (llm/harness.py)
  - Scoring & Verdicts (scoring.py)
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from javadecompiler.class_parser import ClassInfo
from javadecompiler.disassembler import disassembleMethod
from javadecompiler.lifter import liftMethod
from javadecompiler.security.behavior import BehaviorDetector
from javadecompiler.security.callgraph import CallGraph
from javadecompiler.security.jar_checks import (
    ArchiveBounds,
    inspect_jar_archive,
    safe_parse_class_bytes,
)
from javadecompiler.security.models import (
    ClassAnalysis,
    CoverageStats,
    Evidence,
    Finding,
    Kind,
    LlmStats,
    Location,
    MethodAnalysis,
    ScanResult,
    Severity,
    Verdict,
)
from javadecompiler.security.rules.base import SecurityRule, get_all_rules
from javadecompiler.security.scoring import calculate_risk_score, determine_verdict


class SecurityScanner:
    """Orchestrates archive inspection, static rules, behavior chains, LLM harness, and scoring."""

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
        archive_bounds: Optional[ArchiveBounds] = None,
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
        self.bounds = archive_bounds or ArchiveBounds()
        self.rules: List[SecurityRule] = get_all_rules(self.enabled_rules, self.disabled_rules)

    def scan_file(self, file_path: str) -> ScanResult:
        """Scans a .class or .jar file from disk."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target file not found: {file_path}")

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        file_name = os.path.basename(file_path)
        return self.scan_bytes(file_bytes, file_name)

    def scan_bytes(self, file_bytes: bytes, file_name: str) -> ScanResult:
        """Scans raw bytes in memory with full parser hardening and behavioral inspection."""
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        timestamp = datetime.utcnow().isoformat() + "Z"
        is_jar = file_name.endswith(".jar") or file_bytes.startswith(b"PK\x03\x04")

        classes: List[ClassInfo] = []
        jar_findings: List[Finding] = []
        raw_class_dict: Dict[str, bytes] = {}

        # 1. Unpacking & Parsing
        if is_jar:
            classes, jar_findings, raw_class_dict = inspect_jar_archive(file_bytes, bounds=self.bounds)
        else:
            c_info, parse_findings = safe_parse_class_bytes(file_bytes, file_name)
            jar_findings.extend(parse_findings)
            if c_info:
                classes.append(c_info)

        # 2. Build CallGraph across all extracted classes
        call_graph = CallGraph.build(classes)
        behavior_detector = BehaviorDetector(call_graph=call_graph)

        # 3. Disassembly, Lifting, and Rule Execution
        total_methods = 0
        full_coverage_methods = 0
        partial_coverage_methods = 0
        failed_methods = 0
        limitations: List[str] = []

        class_analyses: Dict[str, ClassAnalysis] = {}

        for c_info in classes:
            c_name = c_info.class_name
            class_findings: List[Finding] = []

            # Execute class-level static rules
            for rule in self.rules:
                try:
                    c_res = rule.analyze_class(c_info, call_graph=call_graph)
                    class_findings.extend(c_res)
                except Exception as e:
                    limitations.append(f"Rule {rule.rule_id} error on class {c_name}: {e}")

            # Disassemble & Lift methods
            methods_analysis: Dict[str, MethodAnalysis] = {}
            raw_lifted_methods: Dict[str, str] = {}
            instructions_by_method: Dict[str, List[Dict[str, Any]]] = {}

            for m_name, m_info in c_info.methods.items():
                total_methods += 1
                coverage = "full"
                partial_reason: Optional[str] = None
                lifted_code = ""
                instructions: List[Dict[str, Any]] = []

                if not m_info.bytecode:
                    # Native or abstract
                    methods_analysis[m_name] = MethodAnalysis(
                        methodName=m_name,
                        descriptor=m_info.descriptor,
                        isStatic=m_info.is_static,
                        analysisCoverage="full",
                        liftedCode="/* abstract or native method */",
                    )
                    full_coverage_methods += 1
                    continue

                # Disassemble instructions
                try:
                    instructions = disassembleMethod(m_name, m_info.bytecode)
                    instructions_by_method[m_name] = instructions
                except Exception as e:
                    coverage = "partial"
                    partial_reason = f"Disassembler failure: {e}"
                    partial_coverage_methods += 1
                    limitations.append(f"{c_name}#{m_name}: {partial_reason}")

                # Lift pseudo-code
                try:
                    lifted_code = liftMethod(c_info, m_name, m_info)
                    raw_lifted_methods[m_name] = lifted_code
                except Exception as e:
                    if coverage == "full":
                        coverage = "partial"
                        partial_reason = f"Lifter fallback: {e}"
                        partial_coverage_methods += 1
                        limitations.append(f"{c_name}#{m_name}: {partial_reason}")
                    lifted_code = f"// Lifter fallback: {e}"
                    raw_lifted_methods[m_name] = lifted_code

                if coverage == "full":
                    full_coverage_methods += 1

                # Execute method-level static rules
                method_findings: List[Finding] = []
                lifted_lines = lifted_code.splitlines()

                for rule in self.rules:
                    try:
                        m_res = rule.analyze_method(
                            c_info,
                            m_name,
                            m_info,
                            lifted_lines=lifted_lines,
                            instructions=instructions,
                            call_graph=call_graph,
                        )
                        method_findings.extend(m_res)
                    except Exception as e:
                        limitations.append(f"Rule {rule.rule_id} error on {c_name}#{m_name}: {e}")

                # Compute method risk score
                m_score = calculate_risk_score(method_findings)

                methods_analysis[m_name] = MethodAnalysis(
                    methodName=m_name,
                    descriptor=m_info.descriptor,
                    isStatic=m_info.is_static,
                    analysisCoverage=coverage,
                    partialReason=partial_reason,
                    liftedCode=lifted_code,
                    bytecodeInstructions=instructions,
                    riskScore=m_score,
                    findings=method_findings,
                )

            # Execute Layer B behavior chains across methods of the class
            try:
                chains = behavior_detector.detect_chains(
                    c_info,
                    raw_methods=raw_lifted_methods,
                    instructions_by_method=instructions_by_method,
                )
                for chain in chains:
                    target_m = chain.location.methodName
                    if target_m and target_m in methods_analysis:
                        methods_analysis[target_m].findings.append(chain)
                        methods_analysis[target_m].riskScore = calculate_risk_score(methods_analysis[target_m].findings)
                    else:
                        class_findings.append(chain)
            except Exception as e:
                limitations.append(f"Behavior detector error on {c_name}: {e}")

            # Compute class risk score
            all_class_level_findings = list(class_findings)
            for m in methods_analysis.values():
                all_class_level_findings.extend(m.findings)
            c_score = calculate_risk_score(all_class_level_findings)

            class_analyses[c_name] = ClassAnalysis(
                className=c_name,
                superClass=c_info.super_class,
                interfaces=c_info.interfaces,
                majorVersion=c_info.major_version,
                minorVersion=c_info.minor_version,
                analysisCoverage="partial" if any(m.analysisCoverage == "partial" for m in methods_analysis.values()) else "full",
                riskScore=c_score,
                methods=methods_analysis,
                findings=class_findings,
            )

        # 4. Optional Layer C: LLM Auditor Harness
        llm_stats = LlmStats(
            enabled=self.enable_llm,
            model=self.audit_model,
        )

        if self.enable_llm:
            try:
                from javadecompiler.security.llm.client import OllamaClient
                from javadecompiler.security.llm.harness import LlmAuditorHarness
                client = OllamaClient(model_name=self.audit_model)
                harness = LlmAuditorHarness(
                    client=client,
                    scope=self.llm_scope,
                    enable_cache=not self.no_cache,
                    votes=self.llm_votes,
                    investigate=self.llm_investigate,
                    call_graph=call_graph,
                )
                temp_scan_result = ScanResult(
                    classes=class_analyses,
                    jarFindings=jar_findings,
                )
                raw_methods_dict = {
                    c.class_name: {m: raw_lifted_methods.get(m, "") for m in c.methods}
                    for c in classes
                }
                temp_scan_result = harness.run_audit(
                    scan_result=temp_scan_result,
                    classes=classes,
                    raw_methods=raw_methods_dict,
                )
                llm_stats = temp_scan_result.llmStats

                # Recalculate method and class scores after LLM findings
                for c in class_analyses.values():
                    c_findings_all = list(c.findings)
                    for m in c.methods.values():
                        m.riskScore = calculate_risk_score(m.findings)
                        c_findings_all.extend(m.findings)
                    c.riskScore = calculate_risk_score(c_findings_all)
            except Exception as e:
                limitations.append(f"LLM Auditor error: {e}")

        # 5. Filter by min_severity if configured
        sev_rank = {
            Severity.INFO.value: 1,
            Severity.LOW.value: 2,
            Severity.MEDIUM.value: 3,
            Severity.HIGH.value: 4,
            Severity.CRITICAL.value: 5,
        }
        min_rank = sev_rank.get(self.min_severity.lower(), 1)

        filtered_jar_findings = [f for f in jar_findings if sev_rank.get(f.severity.lower(), 1) >= min_rank]
        for c in class_analyses.values():
            c.findings = [f for f in c.findings if sev_rank.get(f.severity.lower(), 1) >= min_rank]
            for m in c.methods.values():
                m.findings = [f for f in m.findings if sev_rank.get(f.severity.lower(), 1) >= min_rank]

        # 5. Overall Scoring & Verdict
        all_final_findings: List[Finding] = list(filtered_jar_findings)
        for c in class_analyses.values():
            all_final_findings.extend(c.findings)
            for m in c.methods.values():
                all_final_findings.extend(m.findings)

        overall_score = calculate_risk_score(all_final_findings)
        verdict, top_reasons = determine_verdict(
            overall_score,
            all_final_findings,
            partial_coverage_count=partial_coverage_methods,
            failed_methods_count=failed_methods,
        )

        coverage_stats = CoverageStats(
            totalMethods=total_methods,
            fullCoverageMethods=full_coverage_methods,
            partialCoverageMethods=partial_coverage_methods,
            failedMethods=failed_methods,
            limitations=limitations,
        )

        return ScanResult(
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
                "enabled_rules": self.enabled_rules,
                "disabled_rules": self.disabled_rules,
            },
            overallVerdict=verdict,
            overallRiskScore=overall_score,
            topReasons=top_reasons,
            classes=class_analyses,
            jarFindings=filtered_jar_findings,
            coverageStats=coverage_stats,
            llmStats=llm_stats,
        )
