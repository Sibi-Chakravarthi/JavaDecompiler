"""
harness.py — Multi-stage local LLM auditor pipeline.

Coordinates:
  1. Triage: Ranks methods needing deep inspection
  2. Deep Dive: Method-level security auditing with strict evidence grounding
  3. Synthesis: Cross-method attack chain detection
  4. Automatic repair retry on schema failure
  5. Disk caching and hallucination filtering
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from javadecompiler.class_parser import ClassInfo
from javadecompiler.security.llm.cache import LlmDiskCache
from javadecompiler.security.llm.client import LlmClient, FakeLlmClient, OllamaClient
from javadecompiler.security.llm.context import (
    format_bytecode_with_offsets,
    format_constant_pool_strings,
    format_lifted_code_with_lines,
    generate_boundary,
    sanitize_untrusted_text,
)
from javadecompiler.security.llm.grounding import verify_finding_grounding
from javadecompiler.security.llm.schema import (
    make_repair_prompt,
    validate_schema,
)
from javadecompiler.security.models import (
    ClassAnalysis,
    Finding,
    LlmStats,
    MethodAnalysis,
    ScanResult,
    Severity,
)

PROMPTS_DIR = Path(__file__).parent / "prompts"


def load_prompt_template(name: str) -> str:
    """Loads a prompt template file from prompts directory."""
    path = PROMPTS_DIR / f"{name}.txt"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


class LlmAuditorHarness:
    """Orchestrates structured LLM auditing over decompiled code."""

    def __init__(
        self,
        client: Optional[LlmClient] = None,
        cache: Optional[LlmDiskCache] = None,
        scope: str = "suspicious",
        enable_cache: bool = True,
        prompt_version: str = "1.0.0",
        votes: int = 1,
        investigate: bool = False,
        call_graph: Optional[Any] = None,
    ) -> None:
        self.client = client or OllamaClient()
        self.cache = cache or LlmDiskCache(enabled=enable_cache)
        self.scope = scope  # "suspicious" | "all"
        self.prompt_version = prompt_version
        self.votes = max(1, votes)
        self.investigate = investigate
        self.call_graph = call_graph
        self.stats = LlmStats(
            enabled=True,
            model=getattr(self.client, "model_name", "qwen2.5-coder:14b"),
        )

    def run_audit(
        self,
        scan_result: ScanResult,
        classes: List[ClassInfo],
        raw_methods: Dict[str, Dict[str, str]],
    ) -> ScanResult:
        """Runs the LLM auditing pipeline over scan_result."""
        if not self.client.is_available():
            self.stats.enabled = False
            scan_result.llmStats = self.stats
            return scan_result

        class_map = {c.class_name: c for c in classes}

        for class_name, c_analysis in scan_result.classes.items():
            c_info = class_map.get(class_name)
            if not c_info:
                continue

            # Determine audit target methods
            target_method_names = self._select_target_methods(c_info, c_analysis, raw_methods.get(class_name, {}))

            # Run deep-dive per target method
            for m_name in target_method_names:
                m_info = c_info.methods.get(m_name)
                m_analysis = c_analysis.methods.get(m_name)
                if not m_info or not m_analysis:
                    continue

                raw_code = raw_methods.get(class_name, {}).get(m_name, "")
                self._audit_method(c_info, m_name, m_info, m_analysis, raw_code)

            # Cross-method synthesis if multiple methods audited
            if len(c_analysis.methods) > 1 and len(target_method_names) > 0:
                self._run_synthesis(c_info, c_analysis)

            # Bounded Investigator loop if enabled
            if self.investigate:
                try:
                    from javadecompiler.security.llm.investigator import BoundedInvestigator
                    for m_name in target_method_names:
                        investigator = BoundedInvestigator(
                            client=self.client,
                            classes=classes,
                            raw_methods=raw_methods,
                            call_graph=self.call_graph,
                            static_findings=scan_result.allFindings,
                            max_steps=8,
                        )
                        inv_res = investigator.investigate(class_name, m_name)
                        self.stats.investigationTraces.extend(inv_res.traces)
                        m_analysis = c_analysis.methods.get(m_name)
                        if m_analysis and inv_res.findings:
                            m_analysis.findings.extend(inv_res.findings)
                except Exception:
                    pass

        # Update final stats
        self.stats.calls = getattr(self.client, "call_count", self.stats.calls)
        self.stats.totalLatencyMs = getattr(self.client, "total_latency_ms", self.stats.totalLatencyMs)
        scan_result.llmStats = self.stats
        return scan_result

    def _select_target_methods(
        self,
        c_info: ClassInfo,
        c_analysis: ClassAnalysis,
        raw_methods: Dict[str, str],
    ) -> List[str]:
        """Chooses which methods to send for deep dive based on scope and triage."""
        all_methods = [m for m, minfo in c_info.methods.items() if minfo.bytecode]
        if self.scope == "all":
            return all_methods

        # Default 'suspicious' scope: select methods with existing static findings or high risk
        suspicious = [
            m for m, ma in c_analysis.methods.items()
            if len(ma.findings) > 0 or ma.riskScore > 0
        ]

        if suspicious:
            return suspicious

        # If none statically flagged, run triage prompt to find potentially suspicious methods
        try:
            triage_selected = self._run_triage(c_info, c_analysis, raw_methods)
            if triage_selected:
                return triage_selected
        except Exception:
            pass

        return []

    def _run_triage(
        self,
        c_info: ClassInfo,
        c_analysis: ClassAnalysis,
        raw_methods: Dict[str, str],
    ) -> List[str]:
        """Executes triage prompt to prioritize methods."""
        template = load_prompt_template("triage")
        if not template:
            return []

        boundary = generate_boundary()
        methods_summary_lines = []
        for m_name, m_info in c_info.methods.items():
            if not m_info.bytecode:
                continue
            methods_summary_lines.append(f"- {m_name}{m_info.descriptor} ({len(m_info.bytecode)} bytes)")

        static_findings_summary = []
        for m_name, ma in c_analysis.methods.items():
            for f in ma.findings:
                static_findings_summary.append(f"- [{f.severity.upper()}] {m_name}: {f.ruleId} {f.title}")

        prompt = template.format(
            boundary=boundary,
            class_name=sanitize_untrusted_text(c_info.class_name),
            super_class=sanitize_untrusted_text(c_info.super_class),
            interfaces=", ".join(sanitize_untrusted_text(i) for i in c_info.interfaces),
            static_findings_count=len(static_findings_summary),
            methods_summary="\n".join(methods_summary_lines),
            static_findings_summary="\n".join(static_findings_summary) or "None",
        )

        resp_text = self._generate_with_repair(prompt, "triage")
        if not resp_text:
            return []

        try:
            data = json.loads(resp_text)
            recs = data.get("recommendedMethods", [])
            # Match method names
            selected = []
            for rec in recs:
                rec_name = rec.split("(")[0].strip()
                if rec_name in c_info.methods:
                    selected.append(rec_name)
            return selected
        except Exception:
            return []

    def _audit_method(
        self,
        c_info: ClassInfo,
        m_name: str,
        m_info: Any,
        m_analysis: MethodAnalysis,
        raw_code: str,
    ) -> None:
        """Performs deep-dive audit with evidence grounding on a single method."""
        template = load_prompt_template("deep_dive")
        if not template:
            return

        # Prepare artifacts
        formatted_lifted, line_map = format_lifted_code_with_lines(raw_code)

        try:
            from javadecompiler.disassembler import disassembleMethod
            ins_list = disassembleMethod(m_name, m_info.bytecode)
        except Exception:
            ins_list = []

        formatted_bc, offset_map = format_bytecode_with_offsets(ins_list)
        formatted_cp, cp_map = format_constant_pool_strings(c_info.constant_pool)

        boundary = generate_boundary()
        static_summary = []
        for f in m_analysis.findings:
            static_summary.append(f"- [{f.severity.upper()}] {f.ruleId}: {f.title} ({f.description})")

        prompt = template.format(
            boundary=boundary,
            class_name=sanitize_untrusted_text(c_info.class_name),
            method_name=sanitize_untrusted_text(m_name),
            descriptor=sanitize_untrusted_text(m_info.descriptor),
            access_flags=getattr(m_info, "access_flags", 0),
            callers="N/A",
            callees="N/A",
            lifted_source=sanitize_untrusted_text(formatted_lifted, boundary=boundary),
            bytecode_disassembly=sanitize_untrusted_text(formatted_bc, boundary=boundary),
            constant_pool_strings=sanitize_untrusted_text(formatted_cp, boundary=boundary),
            static_findings="\n".join(static_summary) or "None",
        )

        # Check Cache
        model_name = getattr(self.client, "model_name", "qwen2.5-coder:14b")
        cache_key = self.cache.compute_key(
            m_info.bytecode,
            raw_code,
            self.prompt_version,
            model_name,
            {"method": m_name, "stage": "deep_dive"},
        )

        cached_response = self.cache.get(cache_key)
        if cached_response:
            self.stats.cacheHits += 1
            reply_text = cached_response
        else:
            reply_text = self._generate_with_repair(prompt, "deep_dive")
            if reply_text:
                self.cache.put(cache_key, reply_text)

        if not reply_text:
            return

        # Parse and Ground findings
        try:
            data = json.loads(reply_text)
            raw_findings = data.get("findings", [])
        except Exception:
            self.stats.failures += 1
            return

        valid_offsets = set(offset_map.keys())
        valid_cp = set(cp_map.keys())
        valid_lines = set(line_map.keys())

        for rf in raw_findings:
            ground_res = verify_finding_grounding(
                raw_finding=rf,
                class_name=c_info.class_name,
                method_name=m_name,
                descriptor=m_info.descriptor,
                valid_offsets=valid_offsets,
                valid_cp_indices=valid_cp,
                valid_line_numbers=valid_lines,
                offset_to_text=offset_map,
                cp_to_text=cp_map,
                line_to_text=line_map,
                model_name=model_name,
                model_digest=getattr(self.client, "model_digest", None),
                prompt_version=self.prompt_version,
            )

            if ground_res.status == "dropped":
                self.stats.ungroundedDropped += 1
            elif ground_res.grounded_finding:
                gf = ground_res.grounded_finding
                # Run Adversarial Verifier pass for severity >= medium
                if gf.severity in (Severity.MEDIUM.value, Severity.HIGH.value, Severity.CRITICAL.value):
                    verdict = self._verify_finding(gf, c_info, m_name, raw_code)
                    gf.verifierVerdict = verdict
                    if verdict == "refuted":
                        self.stats.verifierRefuted += 1
                        continue  # Drop refuted finding
                # Append confirmed/unrefuted grounded finding to method analysis
                m_analysis.findings.append(gf)

    def _verify_finding(
        self,
        finding: Finding,
        c_info: ClassInfo,
        m_name: str,
        raw_code: str,
    ) -> str:
        """Executes adversarial Devil's Advocate verification pass with majority voting."""
        template = load_prompt_template("verify")
        if not template:
            return "confirmed"

        evidence_summary = ", ".join(f"[{e.type}] {e.text}" for e in finding.evidence)
        boundary = generate_boundary()
        prompt = template.format(
            boundary=boundary,
            rule_id=finding.ruleId,
            title=finding.title,
            severity=finding.severity,
            evidence_summary=evidence_summary or "None",
            rationale=finding.llmRationale or finding.description,
            class_name=sanitize_untrusted_text(c_info.class_name),
            method_name=sanitize_untrusted_text(m_name),
            method_code=sanitize_untrusted_text(raw_code, boundary=boundary),
        )

        votes_count = max(1, self.votes)
        verdict_counts: Dict[str, int] = {"confirmed": 0, "refuted": 0, "inconclusive": 0}

        for _ in range(votes_count):
            try:
                reply = self.client.generate(prompt, format_json=True)
                self.stats.calls += 1
                data = json.loads(reply)
                v = str(data.get("verdict", "confirmed")).lower()
                if v in verdict_counts:
                    verdict_counts[v] += 1
                else:
                    verdict_counts["confirmed"] += 1
            except Exception:
                verdict_counts["inconclusive"] += 1

        # Return majority verdict
        return max(verdict_counts, key=lambda k: verdict_counts[k])

    def _run_synthesis(self, c_info: ClassInfo, c_analysis: ClassAnalysis) -> None:
        """Executes cross-method synthesis for multi-method attack chains."""
        template = load_prompt_template("synthesis")
        if not template:
            return

        methods_summary = []
        for m_name, ma in c_analysis.methods.items():
            if ma.findings:
                f_titles = [f"{f.ruleId} ({f.severity})" for f in ma.findings]
                methods_summary.append(f"- Method {m_name}: findings = {', '.join(f_titles)}")

        if not methods_summary:
            return

        boundary = generate_boundary()
        prompt = template.format(
            boundary=boundary,
            class_name=sanitize_untrusted_text(c_info.class_name),
            call_graph_edges="Intra-class method invocations",
            methods_summary="\n".join(methods_summary),
        )

        resp_text = self._generate_with_repair(prompt, "synthesis")
        if not resp_text:
            return

        try:
            data = json.loads(resp_text)
            chains = data.get("chainsDetected", [])
            for ch in chains:
                c_analysis.findings.append(
                    Finding(
                        ruleId="JD-LLM-CHAIN",
                        title=ch.get("title", "Synthesized Attack Chain"),
                        description=ch.get("rationale", ""),
                        remediation=ch.get("remediation", "Review inter-method invocation flow."),
                        kind=ch.get("kind", "suspicious_behavior"),
                        category=ch.get("category", "execution"),
                        severity=ch.get("severity", "medium"),
                        confidence=float(ch.get("confidence", 0.85)),
                        location=Location(className=c_info.class_name),
                        origin="llm",
                    )
                )
        except Exception:
            pass

    def _generate_with_repair(self, prompt: str, schema_name: str) -> Optional[str]:
        """Calls LLM with 1 repair retry if schema validation fails."""
        try:
            raw_reply = self.client.generate(prompt, format_json=True)
            self.stats.calls += 1
        except Exception:
            self.stats.failures += 1
            return None

        # Try parsing JSON
        parsed_json = None
        try:
            parsed_json = json.loads(raw_reply)
        except Exception as e:
            parse_err = str(e)
            repair_prompt = make_repair_prompt(raw_reply, f"JSON parse error: {parse_err}", schema_name)
            try:
                raw_reply = self.client.generate(repair_prompt, format_json=True)
                self.stats.calls += 1
                parsed_json = json.loads(raw_reply)
            except Exception:
                self.stats.failures += 1
                return None

        # Validate schema
        valid, err = validate_schema(parsed_json, schema_name)
        if valid:
            return raw_reply

        # Retry with repair prompt
        repair_prompt = make_repair_prompt(raw_reply, f"Schema mismatch: {err}", schema_name)
        try:
            repaired_reply = self.client.generate(repair_prompt, format_json=True)
            self.stats.calls += 1
            repaired_json = json.loads(repaired_reply)
            v2, err2 = validate_schema(repaired_json, schema_name)
            if v2:
                return repaired_reply
            self.stats.failures += 1
            return None
        except Exception:
            self.stats.failures += 1
            return None
