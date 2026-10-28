"""
dynamic.py — Dynamic code loading, reflection, JNDI, ScriptEngine, and Unsafe rules.
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
    get_call_info,
    get_ldc_string,
    get_new_class,
)


@register_rule
class DynamicBytecodeLoadingRule(SecurityRule):
    """JD-DYN-001: ClassLoader.defineClass, URLClassLoader, custom ClassLoader subclassing (CWE-470)."""

    rule_id = "JD-DYN-001"
    title = "Dynamic Bytecode / Class Loading (CWE-470)"
    description = (
        "Dynamic loading or definition of JVM bytecode via ClassLoader.defineClass, "
        "URLClassLoader, or custom ClassLoader subclassing."
    )
    remediation = "Avoid dynamic class definition from untrusted bytes or URLs. Enforce code signing."
    kind = Kind.MALICIOUS_INDICATOR.value
    category = Category.DYNAMIC_LOADING.value
    severity = Severity.HIGH.value
    cwe = ["CWE-470"]
    mitre_attack = "T1055"

    def analyze_class(
        self,
        class_info: ClassInfo,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        # Check custom ClassLoader subclassing
        super_cls = class_info.super_class.replace(".", "/")
        if super_cls in ("java/lang/ClassLoader", "java/security/SecureClassLoader", "java/net/URLClassLoader"):
            ev = Evidence(id="CLASS:SUPER", type="constantPool", text=f"Extends {super_cls}")
            findings.append(
                self.create_finding(
                    class_name=class_info.class_name,
                    evidence=[ev],
                    severity_override=Severity.MEDIUM.value,
                    title_override="Custom ClassLoader Subclass Defined",
                    description_override=f"Class extends '{super_cls}', enabling custom bytecode resolution.",
                    confidence=0.85,
                )
            )
        return findings

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
            offset = instr.get("offset", 0)
            new_cls = get_new_class(cp, instr)
            if new_cls and "URLClassLoader" in new_cls:
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text="Instantiation of URLClassLoader",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["URLClassLoader"])
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
                        title_override="URLClassLoader Remote Code Loading",
                        description_override="Instantiation of URLClassLoader enables loading remote bytecode.",
                        confidence=0.9,
                    )
                )

            call = get_call_info(cp, instr)
            if call:
                target_m = call.get("name", "")
                target_cls = call.get("class", "").replace(".", "/")
                if target_m == "defineClass" or (
                    "ClassLoader" in target_cls and target_m in ("defineClass", "loadClass")
                ):
                    ev_list = [
                        Evidence(
                            id=f"I:0x{offset:02x}",
                            type="instruction",
                            offset=offset,
                            text=f"Call to {target_cls}.{target_m}",
                        )
                    ]
                    matched = find_matching_lines(lifted_lines, ["defineClass(", "loadClass("])
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
                            description_override=f"Direct bytecode injection / class definition via {target_cls}.{target_m}.",
                            confidence=0.95,
                        )
                    )

        return findings


@register_rule
class DynamicReflectionRule(SecurityRule):
    """JD-DYN-002: Reflection with non-constant target or setAccessible(true) (CWE-470)."""

    rule_id = "JD-DYN-002"
    title = "Suspicious Reflection or Access Override (CWE-470)"
    description = (
        "Invocation of Class.forName / Method.invoke with non-constant arguments, "
        "or AccessibleObject.setAccessible(true) to bypass visibility controls."
    )
    remediation = "Avoid dynamic reflection on arbitrary class/method names. Restrict setAccessible usage."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.DYNAMIC_LOADING.value
    severity = Severity.MEDIUM.value
    cwe = ["CWE-470"]
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

        for idx, instr in enumerate(instructions):
            call = get_call_info(cp, instr)
            if not call:
                continue

            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")
            offset = instr.get("offset", 0)

            # Check setAccessible(true)
            if name_ == "setAccessible" and "AccessibleObject" in cls_:
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text="setAccessible(true) call",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["setAccessible("])
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
                        title_override="Encapsulation Bypass via setAccessible(true)",
                        description_override="AccessibleObject.setAccessible(true) called to bypass Java access modifiers.",
                        confidence=0.9,
                    )
                )

            # Check Class.forName or Method.invoke
            if (cls_ == "java/lang/Class" and name_ == "forName") or (
                cls_ == "java/lang/reflect/Method" and name_ == "invoke"
            ):
                prev_instr = instructions[idx - 1] if idx > 0 else None
                is_const = prev_instr and prev_instr.get("mnemonic") in ("ldc", "ldc_w")
                sev = Severity.LOW.value if is_const else Severity.HIGH.value

                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"Reflective {cls_}.{name_}",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["Class.forName", ".invoke("])
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
                        severity_override=sev,
                        description_override=(
                            f"Dynamic reflection call {cls_}.{name_} with "
                            f"{'constant string' if is_const else 'dynamic/variable argument'}."
                        ),
                        confidence=0.85,
                    )
                )

        return findings


@register_rule
class JndiAndScriptInjectionRule(SecurityRule):
    """JD-DYN-003: JNDI lookup, ScriptEngine.eval, or sun.misc.Unsafe (CWE-917 / CWE-74)."""

    rule_id = "JD-DYN-003"
    title = "Dangerous Injection Sink (JNDI, ScriptEngine, Unsafe)"
    description = (
        "Invocation of JNDI Context.lookup, ScriptEngine.eval, or direct sun.misc.Unsafe access, "
        "enabling arbitrary code execution or memory manipulation."
    )
    remediation = (
        "Disable remote JNDI resolution (trustURLCodebase=false). Avoid ScriptEngine eval on untrusted "
        "inputs. Disallow sun.misc.Unsafe."
    )
    kind = Kind.VULNERABILITY.value
    category = Category.DYNAMIC_LOADING.value
    severity = Severity.CRITICAL.value
    cwe = ["CWE-917", "CWE-74"]
    mitre_attack = "T1203"

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
            offset = instr.get("offset", 0)

            matched_sink = None
            if "naming" in cls_ and name_ == "lookup":
                matched_sink = "JNDI Context.lookup (Log4Shell pattern)"
            elif "ScriptEngine" in cls_ and name_ == "eval":
                matched_sink = "ScriptEngine.eval dynamic script execution"
            elif "sun/misc/Unsafe" in cls_:
                matched_sink = f"sun.misc.Unsafe.{name_} low-level memory operation"

            if matched_sink:
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"{cls_}.{name_}",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["lookup(", ".eval(", "Unsafe"])
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
                        title_override=f"Critical Injection Sink: {matched_sink}",
                        description_override=f"Dangerous API {cls_}.{name_} invoked ({matched_sink}).",
                        confidence=0.95,
                    )
                )

        return findings
