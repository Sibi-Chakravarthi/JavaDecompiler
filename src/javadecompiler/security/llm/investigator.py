"""
investigator.py — Bounded agentic LLM investigator (max 8 steps).

Runs a model-agnostic, read-only JSON action loop to deeply investigate
suspicious methods by inspecting bytecode, decompiled source, call graph,
constant pool, and static findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from javadecompiler.class_parser import ClassInfo
from javadecompiler.security.callgraph import CallGraph
from javadecompiler.security.llm.client import LlmClient
from javadecompiler.security.llm.context import (
    format_bytecode_with_offsets,
    format_constant_pool_strings,
    format_lifted_code_with_lines,
    sanitize_untrusted_text,
)
from javadecompiler.security.llm.grounding import verify_finding_grounding
from javadecompiler.security.models import Finding


PROMPTS_DIR = Path(__file__).parent / "prompts"


@dataclass
class InvestigationResult:
    className: str
    methodName: str
    findings: List[Finding] = field(default_factory=list)
    traces: List[Dict[str, Any]] = field(default_factory=list)
    steps_taken: int = 0
    concluded: bool = False


class BoundedInvestigator:
    """Agentic investigator loop executing bounded read-only analytical actions."""

    def __init__(
        self,
        client: LlmClient,
        classes: List[ClassInfo],
        raw_methods: Dict[str, Dict[str, str]],
        call_graph: Optional[CallGraph] = None,
        static_findings: Optional[List[Finding]] = None,
        max_steps: int = 8,
    ) -> None:
        self.client = client
        self.classes_map: Dict[str, ClassInfo] = {c.class_name: c for c in classes}
        self.raw_methods = raw_methods
        self.call_graph = call_graph
        self.static_findings = static_findings or []
        self.max_steps = max(1, min(max_steps, 8))  # Max bounded to 8

    def investigate(
        self,
        class_name: str,
        method_name: str,
        goal: Optional[str] = None,
    ) -> InvestigationResult:
        """Runs the bounded investigation loop up to 8 steps."""
        c_info = self.classes_map.get(class_name)
        if not c_info:
            return InvestigationResult(className=class_name, methodName=method_name)

        effective_goal = goal or (
            f"Analyze method {class_name}#{method_name} to verify suspicious behavior, "
            "trace data flow, and determine if an exploitable vulnerability exists."
        )

        template_path = PROMPTS_DIR / "investigate.txt"
        template = template_path.read_text(encoding="utf-8") if template_path.exists() else ""
        if not template:
            return InvestigationResult(className=class_name, methodName=method_name)

        history: List[str] = []
        traces: List[Dict[str, Any]] = []
        final_findings: List[Finding] = []
        concluded = False

        for step in range(1, self.max_steps + 1):
            history_text = "\n".join(history) if history else "No previous steps executed yet."

            prompt = template.format(
                goal=effective_goal,
                history=history_text,
            )

            try:
                raw_reply = self.client.generate(prompt, format_json=True)
                step_data = json.loads(raw_reply)
            except Exception:
                # LLM response failed or not JSON
                traces.append({
                    "step": step,
                    "action": "error",
                    "error": "Failed to generate or parse JSON action",
                })
                break

            thought = str(step_data.get("thought", ""))
            action = str(step_data.get("action", "")).strip()
            args = step_data.get("arguments", {})
            if not isinstance(args, dict):
                args = {}

            # Execute read-only action
            result_str = self._execute_action(action, args, class_name, method_name)
            summary = result_str[:250] + ("..." if len(result_str) > 250 else "")

            trace_entry = {
                "step": step,
                "thought": thought,
                "action": action,
                "arguments": args,
                "result_summary": summary,
            }
            traces.append(trace_entry)

            history.append(f"Step {step}: Action={action}, Args={args}")
            history.append(f"Result: {result_str[:400]}")

            if action == "finish":
                concluded = True
                raw_finish_findings = args.get("findings", [])
                if isinstance(raw_finish_findings, list):
                    final_findings.extend(self._ground_finish_findings(raw_finish_findings, class_name, method_name))
                break

        return InvestigationResult(
            className=class_name,
            methodName=method_name,
            findings=final_findings,
            traces=traces,
            steps_taken=len(traces),
            concluded=concluded,
        )

    def _execute_action(
        self,
        action: str,
        args: Dict[str, Any],
        default_class: str,
        default_method: str,
    ) -> str:
        """Executes a strictly read-only analytical query."""
        c_name = str(args.get("className") or default_class)
        m_name = str(args.get("methodName") or default_method)

        c_info = self.classes_map.get(c_name)

        if action == "getMethodBytecode":
            if not c_info or m_name not in c_info.methods:
                return f"Method {c_name}#{m_name} not found."
            minfo = c_info.methods[m_name]
            try:
                from javadecompiler.disassembler import disassembleMethod
                ins = disassembleMethod(m_name, minfo.bytecode)
                formatted, _ = format_bytecode_with_offsets(ins)
                return formatted
            except Exception as e:
                return f"Disassembly error: {e}"

        elif action == "getLiftedSource":
            code = self.raw_methods.get(c_name, {}).get(m_name)
            if not code:
                return f"No lifted code found for {c_name}#{m_name}"
            formatted, _ = format_lifted_code_with_lines(code)
            return formatted

        elif action == "getCallers":
            if not self.call_graph:
                return "Call graph not available."
            callers = self.call_graph.get_callers(c_name, m_name)
            return f"Callers: {callers}"

        elif action == "getCallees":
            if not self.call_graph:
                return "Call graph not available."
            callees = self.call_graph.get_callees(c_name, m_name)
            return f"Callees: {callees}"

        elif action == "getConstants":
            if not c_info:
                return f"Class {c_name} not found."
            filter_str = str(args.get("filterStr", "")).lower()
            formatted, cp_map = format_constant_pool_strings(c_info.constant_pool)
            if filter_str:
                filtered = [f"CP:{k}: {v}" for k, v in cp_map.items() if filter_str in v.lower()]
                return "\n".join(filtered) or "No matching constants found."
            return formatted

        elif action == "getStaticFindings":
            matches = [
                f"- [{f.severity.upper()}] {f.ruleId}: {f.title} ({f.description})"
                for f in self.static_findings
                if f.location.className == c_name and (not m_name or f.location.methodName == m_name)
            ]
            return "\n".join(matches) or "No static findings for this method."

        elif action == "finish":
            return "Investigation completed."

        return f"Unknown action: {action}"

    def _ground_finish_findings(
        self,
        raw_findings: List[Dict[str, Any]],
        class_name: str,
        method_name: str,
    ) -> List[Finding]:
        """Validates and grounds findings returned by the finish action."""
        c_info = self.classes_map.get(class_name)
        if not c_info or method_name not in c_info.methods:
            return []

        minfo = c_info.methods[method_name]
        try:
            from javadecompiler.disassembler import disassembleMethod
            ins = disassembleMethod(method_name, minfo.bytecode)
        except Exception:
            ins = []

        _, offset_map = format_bytecode_with_offsets(ins)
        _, cp_map = format_constant_pool_strings(c_info.constant_pool)
        code = self.raw_methods.get(class_name, {}).get(method_name, "")
        _, line_map = format_lifted_code_with_lines(code)

        grounded = []
        for rf in raw_findings:
            if not isinstance(rf, dict):
                continue
            res = verify_finding_grounding(
                raw_finding=rf,
                class_name=class_name,
                method_name=method_name,
                descriptor=minfo.descriptor,
                valid_offsets=set(offset_map.keys()),
                valid_cp_indices=set(cp_map.keys()),
                valid_line_numbers=set(line_map.keys()),
                offset_to_text=offset_map,
                cp_to_text=cp_map,
                line_to_text=line_map,
                model_name=getattr(self.client, "model_name", "investigator-model"),
            )
            if res.grounded_finding:
                grounded.append(res.grounded_finding)

        return grounded
