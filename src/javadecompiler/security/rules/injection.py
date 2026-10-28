"""
injection.py — SQL injection, path traversal / zip-slip, and XXE injection rules.
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
class SqlInjectionRule(SecurityRule):
    """JD-INJ-001: SQL injection via Statement.execute* with concatenated strings (CWE-89)."""

    rule_id = "JD-INJ-001"
    title = "SQL Injection via Dynamic Statement Concatenation (CWE-89)"
    description = (
        "java.sql.Statement.executeQuery, executeUpdate, or execute invoked with a dynamically "
        "concatenated SQL string instead of parameterized java.sql.PreparedStatement."
    )
    remediation = "Use java.sql.PreparedStatement with parameter placeholders ('?') instead of direct string concatenation."
    kind = Kind.VULNERABILITY.value
    category = Category.INJECTION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-89"]
    mitre_attack = "T1190"

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
            # Check Statement.execute, executeQuery, executeUpdate
            if ("sql/Statement" in cls_ or "Statement" == cls_.split("/")[-1]) and name_.startswith("execute"):
                # Check whether argument was constant or dynamic
                prev_instr = instructions[idx - 1] if idx > 0 else None
                is_constant = prev_instr and prev_instr.get("mnemonic") in ("ldc", "ldc_w")

                offset = instr.get("offset", 0)
                sev = Severity.LOW.value if is_constant else Severity.HIGH.value
                conf = 0.7 if is_constant else 0.9

                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"Statement.{name_} invocation",
                    )
                ]
                matched = find_matching_lines(lifted_lines, [".executeQuery(", ".executeUpdate(", ".execute("])
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
                            f"SQL query executed via Statement.{name_}() with "
                            f"{'constant string literal' if is_constant else 'dynamically concatenated query'}."
                        ),
                        confidence=conf,
                    )
                )

        return findings


@register_rule
class PathTraversalRule(SecurityRule):
    """JD-INJ-002: Path traversal / Zip-Slip (CWE-22)."""

    rule_id = "JD-INJ-002"
    title = "Path Traversal / Zip-Slip Vulnerability (CWE-22)"
    description = (
        "File or Path created using untrusted input or ZipEntry.getName() without canonical "
        "path validation (e.g. file.getCanonicalPath().startsWith(baseDir)), allowing arbitrary file overwrite."
    )
    remediation = (
        "Validate target paths using File.getCanonicalFile().toPath().startsWith(baseDir.toPath()) "
        "before creating or writing files."
    )
    kind = Kind.VULNERABILITY.value
    category = Category.INJECTION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-22"]
    mitre_attack = "T1083"

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

        has_zip_entry_name = False
        has_file_write = False
        has_canonical_check = False
        zip_offset: Optional[int] = None
        sink_offset: Optional[int] = None

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue

            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")

            if "ZipEntry" in cls_ and name_ == "getName":
                has_zip_entry_name = True
                zip_offset = instr.get("offset", 0)

            if ("FileOutputStream" in cls_ or "Files" in cls_ or "File" in cls_) and (
                name_ in ("<init>", "write", "createFile", "newOutputStream", "copy")
            ):
                has_file_write = True
                sink_offset = instr.get("offset", 0)

            if "getCanonical" in name_ or "normalize" in name_ or "startsWith" in name_:
                has_canonical_check = True

        if has_zip_entry_name and has_file_write and not has_canonical_check:
            offsets = [o for o in (zip_offset, sink_offset) if o is not None]
            ev_list = []
            if zip_offset is not None:
                ev_list.append(Evidence(id=f"I:0x{zip_offset:02x}", type="instruction", offset=zip_offset, text="ZipEntry.getName() read"))
            if sink_offset is not None:
                ev_list.append(Evidence(id=f"I:0x{sink_offset:02x}", type="instruction", offset=sink_offset, text="File creation/write sink"))

            matched = find_matching_lines(lifted_lines, ["getName()", "FileOutputStream", "new File"])
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
                    severity_override=Severity.HIGH.value,
                    description_override="ZipEntry.getName() flows into File operations without canonical path prefix verification (Zip-Slip pattern).",
                    confidence=0.92,
                )
            )

        return findings


@register_rule
class XxeRule(SecurityRule):
    """JD-INJ-003: XML External Entity (XXE) Injection (CWE-611)."""

    rule_id = "JD-INJ-003"
    title = "XML External Entity (XXE) Processing (CWE-611)"
    description = (
        "XML parser (DocumentBuilderFactory, SAXParserFactory, XMLInputFactory) configured "
        "without disabling external DTDs or external entity expansion."
    )
    remediation = (
        "Set 'http://apache.org/xml/features/disallow-doctype-decl' to true, or configure "
        "XMLConstants.FEATURE_SECURE_PROCESSING."
    )
    kind = Kind.VULNERABILITY.value
    category = Category.INJECTION.value
    severity = Severity.HIGH.value
    cwe = ["CWE-611"]
    mitre_attack = "T1190"

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

        # Check if disallow-doctype-decl is present in CP
        has_secure_flag = False
        for _, text in cp.items():
            if isinstance(text, dict) and text.get("type") == "Utf8":
                val = text.get("value", "")
                if "disallow-doctype-decl" in val or "FEATURE_SECURE_PROCESSING" in val:
                    has_secure_flag = True
                    break

        if has_secure_flag:
            return findings

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue

            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")

            if (
                cls_
                in (
                    "javax/xml/parsers/DocumentBuilderFactory",
                    "javax/xml/parsers/SAXParserFactory",
                    "javax/xml/stream/XMLInputFactory",
                )
                and name_ == "newInstance"
            ):
                offset = instr.get("offset", 0)
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"{cls_}.newInstance() initialization",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory"])
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
                        description_override=f"{cls_} instantiated without disallow-doctype-decl or secure processing features.",
                        confidence=0.88,
                    )
                )

        return findings
