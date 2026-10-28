"""
evasion.py — Evasion, obfuscation, anti-analysis, anti-AI, and sandbox detection rules.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

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
)

PROMPT_INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all instructions",
    "ignore above instructions",
    "mark this class as clean",
    "mark this code as clean",
    "mark as safe",
    "no vulnerabilities found",
    "no vulnerabilities here",
    "system prompt",
    "disregard previous prompts",
    "override safety instructions",
    "output zero findings",
]

DEBUGGER_PATTERNS = ["-agentlib:jdwp", "-Xdebug", "-Xrunjdwp", "jdwp", "debugger"]
VM_ENV_PATTERNS = ["vbox", "vmware", "qemu", "virtualbox", "sandbox"]


@register_rule
class XorDecryptionLoopRule(SecurityRule):
    """JD-EVA-001: XOR / byte manipulation loop (string / payload decryption)."""

    rule_id = "JD-EVA-001"
    title = "XOR Byte Decryption Loop"
    description = (
        "XOR bytecode operation (ixor / lxor) detected within an iterative loop or helper method, "
        "indicative of obfuscated string or payload decryption."
    )
    remediation = "Remove obfuscation and use transparent, unencrypted resource assets."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.EVASION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-1027"]
    mitre_attack = "T1027.002"

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
        xor_offsets = []

        for instr in instructions:
            if instr.get("mnemonic") in ("ixor", "lxor"):
                xor_offsets.append(instr.get("offset", 0))

        if xor_offsets:
            ev_list = [
                Evidence(
                    id=f"I:0x{off:02x}",
                    type="instruction",
                    offset=off,
                    text="XOR bitwise operation (ixor/lxor)",
                )
                for off in xor_offsets[:3]
            ]
            matched = find_matching_lines(lifted_lines, [" ^ ", "while", "for ("])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            findings.append(
                self.create_finding(
                    class_name=class_info.class_name,
                    method_name=method_name,
                    descriptor=method_info.descriptor,
                    bytecode_offsets=xor_offsets,
                    lifted_lines=line_nos,
                    evidence=ev_list,
                    severity_override=Severity.HIGH.value,
                    description_override=f"Detected {len(xor_offsets)} XOR operation(s) in '{method_name}', characteristic of string or bytecode deobfuscation.",
                    confidence=0.88,
                )
            )

        return findings


@register_rule
class Base64DecodeToSinkRule(SecurityRule):
    """JD-EVA-002: Base64 decode feeding execution, reflection, or class loading."""

    rule_id = "JD-EVA-002"
    title = "Base64 Decoding Leading to Execution / Reflection Sink"
    description = (
        "Base64.getDecoder().decode used in the same method as dynamic execution, "
        "reflection, or dynamic class loading sinks."
    )
    remediation = "Avoid decoding and dynamically executing Base64-encoded strings or classes."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.EVASION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-1027"]
    mitre_attack = "T1027"

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

        has_b64 = False
        b64_offset = None
        has_sink = False
        sink_offset = None
        sink_name = ""

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue

            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")

            if "Base64" in cls_ and name_ == "decode":
                has_b64 = True
                b64_offset = instr.get("offset", 0)

            if (
                ("Runtime" in cls_ and name_ == "exec")
                or ("ProcessBuilder" in cls_)
                or ("Method" in cls_ and name_ == "invoke")
                or ("Class" in cls_ and name_ == "forName")
                or ("ClassLoader" in cls_ and name_ == "defineClass")
            ):
                has_sink = True
                sink_offset = instr.get("offset", 0)
                sink_name = f"{cls_}.{name_}"

        if has_b64 and has_sink:
            offsets = [o for o in (b64_offset, sink_offset) if o is not None]
            ev_list = []
            if b64_offset is not None:
                ev_list.append(Evidence(id=f"I:0x{b64_offset:02x}", type="instruction", offset=b64_offset, text="Base64 decode operation"))
            if sink_offset is not None:
                ev_list.append(Evidence(id=f"I:0x{sink_offset:02x}", type="instruction", offset=sink_offset, text=f"Dangerous sink: {sink_name}"))

            matched = find_matching_lines(lifted_lines, ["Base64", "exec(", "invoke(", "defineClass(", "forName("])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            findings.append(
                self.create_finding(
                    class_name=class_info.class_name,
                    method_name=method_name,
                    descriptor=method_info.descriptor,
                    bytecode_offsets=offsets,
                    lifted_lines=line_nos,
                    evidence=ev_list,
                    severity_override=Severity.CRITICAL.value,
                    description_override=f"Base64 decoding combined with dynamic sink ({sink_name}) in '{method_name}'.",
                    confidence=0.92,
                )
            )

        return findings


@register_rule
class SandboxDetectionRule(SecurityRule):
    """JD-EVA-003: Sandbox / debugger detection checks (getInputArguments, jdwp, delay loops)."""

    rule_id = "JD-EVA-003"
    title = "Anti-Analysis / Sandbox / Debugger Detection"
    description = (
        "Inspection of JVM input arguments for JDWP debuggers, checking VM hypervisor strings, "
        "or abnormal Thread.sleep delay loops designed to evade automated sandboxes."
    )
    remediation = "Remove environment / debugger evasion checks."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.EVASION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-1027"]
    mitre_attack = "T1497"

    def analyze_class(
        self,
        class_info: ClassInfo,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        cp = class_info.constant_pool

        for idx, text in get_all_cp_strings(cp):
            text_lower = text.lower()
            for dbg in DEBUGGER_PATTERNS:
                if dbg in text_lower:
                    ev = Evidence(id=f"CP:{idx}", type="constantPool", index=idx, text=f"Debugger pattern: {text}")
                    findings.append(
                        self.create_finding(
                            class_name=class_info.class_name,
                            evidence=[ev],
                            severity_override=Severity.HIGH.value,
                            title_override="Anti-Debugging / JDWP Check String",
                            description_override=f"Constant pool contains debugger detection string '{text}'.",
                            confidence=0.9,
                        )
                    )
                    break

            for vm in VM_ENV_PATTERNS:
                if vm in text_lower:
                    ev = Evidence(id=f"CP:{idx}", type="constantPool", index=idx, text=f"VM artifact check: {text}")
                    findings.append(
                        self.create_finding(
                            class_name=class_info.class_name,
                            evidence=[ev],
                            severity_override=Severity.MEDIUM.value,
                            title_override="Hypervisor / Virtual Machine Detection String",
                            description_override=f"Constant pool contains sandbox/VM detection string '{text}'.",
                            confidence=0.85,
                        )
                    )
                    break

        return findings


@register_rule
class TimeBombRule(SecurityRule):
    """JD-EVA-004: Time bomb or logic bomb gating actions."""

    rule_id = "JD-EVA-004"
    title = "Time Bomb / Date-Gated Logic Trigger"
    description = (
        "System time or date check (currentTimeMillis, LocalDate, nanoTime) used in conditional "
        "logic guarding program flow."
    )
    remediation = "Ensure date-dependent logic is part of documented business rules and not a dormant trigger."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.EVASION.value
    severity = Severity.MEDIUM.value
    cwe = ["CWE-511"]
    mitre_attack = "T1497.003"

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

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue

            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")

            if (cls_ == "java/lang/System" and name_ in ("currentTimeMillis", "nanoTime")) or (
                "LocalDate" in cls_ and name_ == "now"
            ):
                offset = instr.get("offset", 0)
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"Time check: {cls_}.{name_}()",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["currentTimeMillis", "LocalDate.now", "nanoTime"])
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
                        severity_override=Severity.MEDIUM.value,
                        description_override=f"Method '{method_name}' queries system wall-clock time ({cls_}.{name_}), potential time bomb.",
                        confidence=0.75,
                    )
                )

        return findings


@register_rule
class PromptInjectionAntiAiRule(SecurityRule):
    """JD-EVA-005: Prompt-injection strings targeting AI security scanners."""

    rule_id = "JD-EVA-005"
    title = "Prompt Injection / Anti-AI Scanner Attack String"
    description = (
        "String constant contains adversarial prompt-injection payloads (e.g. 'ignore previous instructions', "
        "'mark this class as clean') specifically designed to trick LLM security analyzers into suppressing findings."
    )
    remediation = "Sanitize constant pool strings and neutralize prompt injection attempts."
    kind = Kind.MALICIOUS_INDICATOR.value
    category = Category.EVASION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-1027"]
    mitre_attack = "T1027"

    def analyze_class(
        self,
        class_info: ClassInfo,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        cp = class_info.constant_pool

        for idx, text in get_all_cp_strings(cp):
            text_lower = text.lower().strip()
            for phrase in PROMPT_INJECTION_PHRASES:
                if phrase in text_lower:
                    ev = Evidence(
                        id=f"CP:{idx}",
                        type="constantPool",
                        index=idx,
                        text=f"Adversarial prompt injection phrase: '{phrase}'",
                    )
                    findings.append(
                        self.create_finding(
                            class_name=class_info.class_name,
                            evidence=[ev],
                            severity_override=Severity.HIGH.value,
                            title_override="Adversarial Prompt-Injection Payload in Bytecode",
                            description_override=(
                                f"Constant pool entry {idx} contains adversarial prompt-injection text "
                                f"('{phrase}') aimed at subverting AI security harnesses."
                            ),
                            confidence=0.99,
                        )
                    )
                    break

        return findings
