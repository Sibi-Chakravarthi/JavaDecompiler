"""
deserialization.py — Unsafe Java deserialization rules (ObjectInputStream, XMLDecoder, gadget patterns).
"""

from __future__ import annotations

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
    get_new_class,
)


@register_rule
class UnsafeObjectInputStreamRule(SecurityRule):
    """JD-DESER-001: ObjectInputStream.readObject/readUnshared without ObjectInputFilter (CWE-502)."""

    rule_id = "JD-DESER-001"
    title = "Unsafe Java Deserialization (CWE-502)"
    description = (
        "Invocation of ObjectInputStream.readObject or readUnshared without configuring "
        "an ObjectInputFilter, vulnerable to remote code execution via gadget chains."
    )
    remediation = (
        "Use safe serialization formats (JSON, Protocol Buffers) or enforce strict type filtering "
        "via java.io.ObjectInputFilter."
    )
    kind = Kind.VULNERABILITY.value
    category = Category.DESERIALIZATION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-502"]
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

        # Check if ObjectInputFilter is used in this method
        has_filter = False
        for instr in instructions:
            call = get_call_info(cp, instr)
            if call and ("ObjectInputFilter" in call.get("class", "") or "setObjectInputFilter" in call.get("name", "")):
                has_filter = True
                break

        if has_filter:
            return findings

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue

            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")
            if cls_ == "java/io/ObjectInputStream" and name_ in ("readObject", "readUnshared"):
                offset = instr.get("offset", 0)
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"Call to ObjectInputStream.{name_}()",
                    )
                ]
                matched = find_matching_lines(lifted_lines, [".readObject(", ".readUnshared("])
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
                        description_override=(
                            f"ObjectInputStream.{name_}() called without an ObjectInputFilter. "
                            "Untrusted stream deserialization can trigger arbitrary gadget chains."
                        ),
                        confidence=0.9,
                    )
                )

        return findings


@register_rule
class XmlDecoderAndGadgetRule(SecurityRule):
    """JD-DESER-002: XMLDecoder.readObject or custom readObject method invoking dangerous sinks (CWE-502)."""

    rule_id = "JD-DESER-002"
    title = "XMLDecoder or Deserialization Gadget Method (CWE-502)"
    description = (
        "Usage of XMLDecoder.readObject (inherently dangerous arbitrary bean instantiation) "
        "or a custom readObject(ObjectInputStream) containing reflection, process execution, or network sinks."
    )
    remediation = "Replace XMLDecoder with safe XML parsers. Avoid side effects inside custom readObject."
    kind = Kind.VULNERABILITY.value
    category = Category.DESERIALIZATION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-502"]
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

            if "XMLDecoder" in cls_ and name_ == "readObject":
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text="XMLDecoder.readObject() call",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["XMLDecoder", "readObject("])
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
                        title_override="Critical XMLDecoder Deserialization Sink",
                        description_override="XMLDecoder.readObject() allows arbitrary Java class instantiation and command execution.",
                        confidence=0.95,
                    )
                )

        # Check for custom readObject gadget: readObject(Ljava/io/ObjectInputStream;)V invoking dangerous sinks
        if method_name == "readObject" and "java/io/ObjectInputStream" in method_info.descriptor:
            for instr in instructions:
                call = get_call_info(cp, instr)
                if not call:
                    continue
                c = call.get("class", "")
                m = call.get("name", "")
                if ("Runtime" in c and m == "exec") or ("ProcessBuilder" in c) or ("invoke" in m) or ("Socket" in c):
                    offset = instr.get("offset", 0)
                    ev_list = [
                        Evidence(
                            id=f"I:0x{offset:02x}",
                            type="instruction",
                            offset=offset,
                            text=f"Dangerous sink {c}.{m} in custom readObject",
                        )
                    ]
                    matched = find_matching_lines(lifted_lines, ["exec(", "ProcessBuilder", "invoke(", "Socket("])
                    line_nos = [m[0] for m in matched]
                    for match in matched:
                        ev_list.append(Evidence(id=f"L:{match[0]}", type="liftedLine", line=match[0], text=match[1]))

                    findings.append(
                        self.create_finding(
                            class_name=class_info.class_name,
                            method_name=method_name,
                            descriptor=method_info.descriptor,
                            bytecode_offsets=[offset],
                            lifted_lines=line_nos,
                            evidence=ev_list,
                            severity_override=Severity.CRITICAL.value,
                            title_override="Deserialization Gadget Pattern in readObject",
                            description_override=f"Custom readObject deserialization hook invokes dangerous sink {c}.{m}.",
                            confidence=0.95,
                        )
                    )
                    break

        return findings
