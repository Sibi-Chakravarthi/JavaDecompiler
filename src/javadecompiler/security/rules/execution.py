"""
execution.py — Command execution rules (Runtime.exec, ProcessBuilder, shell invocations).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from javadecompiler.class_parser import ClassInfo, MethodInfo
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
    get_all_cp_strings,
    get_call_info,
    get_ldc_string,
    get_new_class,
)

SHELL_PATTERNS = {
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "/bin/sh",
    "/bin/bash",
    "bash",
    "sh",
    "zsh",
    "cmd",
}


@register_rule
class DynamicCommandExecutionRule(SecurityRule):
    """JD-EXEC-001: Process execution with dynamic arguments (CWE-78)."""

    rule_id = "JD-EXEC-001"
    title = "Dynamic OS Command Execution (CWE-78)"
    description = (
        "Process execution (Runtime.exec or ProcessBuilder) with dynamic/non-constant arguments "
        "allowing potential command injection."
    )
    remediation = (
        "Avoid invoking operating system shells. If unavoidable, use an allowlist of commands and "
        "pass arguments as separate array elements without string concatenation."
    )
    kind = Kind.VULNERABILITY.value
    category = Category.EXECUTION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-78"]
    mitre_attack = "T1059"

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
        cp = class_info.constant_pool

        # Track preceding ldc constants
        recent_ldc: Optional[Tuple[int, str]] = None

        for idx, instr in enumerate(instructions):
            ldc = get_ldc_string(cp, instr)
            if ldc:
                recent_ldc = ldc

            call = get_call_info(cp, instr)
            is_exec = False
            if call:
                target_cls = call.get("class", "").replace(".", "/")
                target_m = call.get("name", "")
                if target_cls == "java/lang/Runtime" and target_m == "exec":
                    is_exec = True
                elif target_cls == "java/lang/ProcessBuilder" and (target_m in ("<init>", "command", "start")):
                    is_exec = True

            if is_exec:
                offset = instr.get("offset", 0)
                # Check whether argument immediately preceded by a constant string
                is_constant = False
                prev_instr = instructions[idx - 1] if idx > 0 else None
                if prev_instr and prev_instr.get("mnemonic") in ("ldc", "ldc_w"):
                    is_constant = True

                if not is_constant:
                    ev_list = [
                        Evidence(
                            id=f"I:0x{offset:02x}",
                            type="instruction",
                            offset=offset,
                            text=f"{instr.get('mnemonic')} {call.get('class')}.{call.get('name')}",
                        )
                    ]
                    # Find matching lifted lines
                    matched = find_matching_lines(lifted_lines, ["exec(", "ProcessBuilder(", ".start("])
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
                            severity_override=Severity.HIGH.value,
                            confidence=0.9,
                        )
                    )

        return findings


@register_rule
class ConstantCommandExecutionRule(SecurityRule):
    """JD-EXEC-002: Process execution with constant string arguments (CWE-78)."""

    rule_id = "JD-EXEC-002"
    title = "Static OS Command Execution (CWE-78)"
    description = "Runtime.exec or ProcessBuilder invoked with hardcoded command string."
    remediation = "Replace OS command invocations with native Java APIs where possible."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.EXECUTION.value
    severity = Severity.LOW.value
    cwe = ["CWE-78"]
    mitre_attack = "T1059"

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
        cp = class_info.constant_pool

        for idx, instr in enumerate(instructions):
            call = get_call_info(cp, instr)
            if not call:
                continue
            target_cls = call.get("class", "").replace(".", "/")
            target_m = call.get("name", "")
            if (target_cls == "java/lang/Runtime" and target_m == "exec") or (
                target_cls == "java/lang/ProcessBuilder" and target_m in ("<init>", "command", "start")
            ):
                prev_instr = instructions[idx - 1] if idx > 0 else None
                if prev_instr and prev_instr.get("mnemonic") in ("ldc", "ldc_w"):
                    ldc_res = get_ldc_string(cp, prev_instr)
                    cmd_str = ldc_res[1] if ldc_res else ""
                    cp_idx = ldc_res[0] if ldc_res else 0
                    offset = instr.get("offset", 0)

                    ev_list = [
                        Evidence(
                            id=f"I:0x{offset:02x}",
                            type="instruction",
                            offset=offset,
                            text=f"{instr.get('mnemonic')} {target_cls}.{target_m}",
                        ),
                        Evidence(id=f"CP:{cp_idx}", type="constantPool", index=cp_idx, text=cmd_str),
                    ]
                    matched = find_matching_lines(lifted_lines, ["exec(", "ProcessBuilder(", ".start("])
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
                            severity_override=Severity.LOW.value,
                            description_override=f"Process execution with static command literal: \"{cmd_str}\".",
                            confidence=0.85,
                        )
                    )

        return findings


@register_rule
class ShellInvocationRule(SecurityRule):
    """JD-EXEC-003: Shell invocation constants combined with process execution (CWE-78)."""

    rule_id = "JD-EXEC-003"
    title = "Shell Invocation Pattern (CWE-78)"
    description = (
        "Operating system shell binary ('cmd.exe', 'powershell', '/bin/sh', 'bash') "
        "invoked via process execution."
    )
    remediation = "Do not spawn external system command shells from Java."
    kind = Kind.MALICIOUS_INDICATOR.value
    category = Category.EXECUTION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-78"]
    mitre_attack = "T1059"

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
        cp = class_info.constant_pool

        # Check if method uses Runtime.exec or ProcessBuilder
        has_exec = False
        exec_offsets: List[int] = []
        for instr in instructions:
            call = get_call_info(cp, instr)
            if call:
                cls_ = call.get("class", "").replace(".", "/")
                name_ = call.get("name", "")
                if (cls_ == "java/lang/Runtime" and name_ == "exec") or (
                    cls_ == "java/lang/ProcessBuilder" and name_ in ("<init>", "start", "command")
                ):
                    has_exec = True
                    exec_offsets.append(instr.get("offset", 0))

        if not has_exec:
            return findings

        # Check if shell constants appear in instructions or constant pool
        shell_cp_entries = []
        for idx, s in get_all_cp_strings(cp):
            s_clean = s.strip().lower()
            for shell in SHELL_PATTERNS:
                if shell in s_clean:
                    shell_cp_entries.append((idx, s))
                    break

        if shell_cp_entries:
            ev_list = []
            for off in exec_offsets:
                ev_list.append(Evidence(id=f"I:0x{off:02x}", type="instruction", offset=off, text="Process execution invocation"))
            for cp_idx, text in shell_cp_entries:
                ev_list.append(Evidence(id=f"CP:{cp_idx}", type="constantPool", index=cp_idx, text=text))

            matched = find_matching_lines(lifted_lines, ["exec(", "ProcessBuilder(", "cmd", "bash", "powershell", "sh"])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            findings.append(
                self.create_finding(
                    class_name=class_info.class_name,
                    method_name=method_name,
                    descriptor=method_info.descriptor,
                    bytecode_offsets=exec_offsets,
                    lifted_lines=line_nos,
                    evidence=ev_list,
                    severity_override=Severity.HIGH.value,
                    description_override=f"Shell command constant ('{shell_cp_entries[0][1]}') combined with process execution.",
                    confidence=0.95,
                )
            )

        return findings
