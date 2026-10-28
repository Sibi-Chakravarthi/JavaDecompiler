"""
loadtime.py — Load-time trigger rules (<clinit>, Java Agent, ServiceLoader reachability).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from javadecompiler.class_parser import ClassInfo, MethodInfo
from javadecompiler.security.callgraph import CallGraph
from javadecompiler.security.models import (
    Category,
    Evidence,
    Finding,
    Kind,
    Location,
    Severity,
)
from javadecompiler.security.rules.base import SecurityRule, register_rule
from javadecompiler.security.rules.helpers import (
    find_matching_lines,
    get_call_info,
)

DANGEROUS_SINKS = {
    ("java/lang/Runtime", "exec"),
    ("java/lang/ProcessBuilder", "<init>"),
    ("java/lang/ProcessBuilder", "start"),
    ("java/net/Socket", "<init>"),
    ("java/lang/reflect/Method", "invoke"),
    ("java/lang/ClassLoader", "defineClass"),
    ("java/lang/System", "load"),
    ("java/lang/System", "loadLibrary"),
    ("javax/naming/InitialContext", "lookup"),
}


@register_rule
class LoadTimeTriggerRule(SecurityRule):
    """JD-LOAD-001: Dangerous sink reachable from <clinit> or load-time entry points (CWE-506)."""

    rule_id = "JD-LOAD-001"
    title = "Dangerous Sink Executed Automatically at Class Load Time (CWE-506)"
    description = (
        "Dangerous execution, network, reflection, or native loading sink is invoked or reachable "
        "directly from a static class initializer (<clinit>), executing without explicit method invocation."
    )
    remediation = (
        "Avoid invoking network, process, or reflective operations inside static initializers (<clinit>). "
        "Defer initialization to explicit calls."
    )
    kind = Kind.MALICIOUS_INDICATOR.value
    category = Category.LOADTIME.value
    severity = Severity.CRITICAL.value
    cwe = ["CWE-506"]
    mitre_attack = "T1547"

    def analyze_method(
        self,
        class_info: ClassInfo,
        method_name: str,
        method_info: MethodInfo,
        lifted_lines: List[str],
        instructions: List[Dict[str, Any]],
        cfg: Optional[Dict[int, Any]] = None,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        if method_name != "<clinit>":
            return findings

        cp = class_info.constant_pool

        # 1. Direct sink in <clinit>
        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue

            target_cls = call.get("class", "").replace(".", "/")
            target_m = call.get("name", "")

            if (target_cls, target_m) in DANGEROUS_SINKS or any(
                target_cls.startswith(k[0]) and target_m == k[1] for k in DANGEROUS_SINKS
            ):
                offset = instr.get("offset", 0)
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"Direct load-time sink: {target_cls}.{target_m}()",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["exec(", "Socket(", "lookup(", "invoke(", "loadLibrary("])
                line_nos = [m[0] for m in matched]
                for m in matched:
                    ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

                findings.append(
                    self.create_finding(
                        class_name=class_info.class_name,
                        method_name=method_name,
                        descriptor=method_info.descriptor,
                        bytecode_offsets=[offset],
                        lifted_lines=line_nos,
                        evidence=ev_list,
                        severity_override=Severity.CRITICAL.value,
                        title_override=f"Load-Time Execution Sink ({target_cls}.{target_m})",
                        description_override=(
                            f"Static initializer <clinit> invokes dangerous sink {target_cls}.{target_m}(). "
                            "Executes automatically at class/jar load time."
                        ),
                        confidence=0.98,
                    )
                )

        # 2. Transitive reachability via CallGraph
        if call_graph and isinstance(call_graph, CallGraph):
            for sink_cls, sink_m in DANGEROUS_SINKS:
                path = call_graph.find_path((class_info.class_name.replace(".", "/"), "<clinit>"), (sink_cls, sink_m))
                if path and len(path) > 2:  # Transitive call (len > 2 means clinit -> helper -> sink)
                    path_str = " -> ".join(f"{c}#{m}" for c, m in path)
                    ev = Evidence(id="CG:PATH", type="instruction", text=f"Call path: {path_str}")
                    findings.append(
                        self.create_finding(
                            class_name=class_info.class_name,
                            method_name=method_name,
                            descriptor=method_info.descriptor,
                            bytecode_offsets=[],
                            lifted_lines=[],
                            evidence=[ev],
                            severity_override=Severity.HIGH.value,
                            title_override="Transitive Load-Time Sink Reachability",
                            description_override=(
                                f"<clinit> transitively calls dangerous sink {sink_cls}#{sink_m} via {path_str}. "
                                "Executes automatically at class/jar load time."
                            ),
                            confidence=0.9,
                        )
                    )

        return findings
