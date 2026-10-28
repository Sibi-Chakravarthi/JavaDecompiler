"""
system.py — System persistence, shutdown hooks, security manager tampering, and host reconnaissance.
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
)

SENSITIVE_FILES_OR_PROPS = [
    ".ssh",
    ".aws",
    "/etc/passwd",
    "/etc/shadow",
    "id_rsa",
    "known_hosts",
    "user.home",
    "user.dir",
]


@register_rule
class SystemPersistenceRule(SecurityRule):
    """JD-SYS-001: Runtime.addShutdownHook, System.setSecurityManager, native library loads."""

    rule_id = "JD-SYS-001"
    title = "System Persistence / SecurityManager Modification / Native Load"
    description = (
        "Invocations altering JVM shutdown hooks (Runtime.addShutdownHook), overriding or disabling "
        "System.setSecurityManager, or loading native shared libraries (System.load/loadLibrary)."
    )
    remediation = "Restrict shutdown hooks to essential cleanup. Do not disable SecurityManager. Audit native binaries."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.PERSISTENCE.value
    severity = Severity.MEDIUM.value
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
        cp = class_info.constant_pool

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue

            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")
            offset = instr.get("offset", 0)

            matched_reason = None
            sev = Severity.MEDIUM.value
            cat = Category.PERSISTENCE.value

            if name_ == "addShutdownHook" and "Runtime" in cls_:
                matched_reason = "Shutdown Hook Persistence (Runtime.addShutdownHook)"
                sev = Severity.HIGH.value
            elif name_ == "setSecurityManager" and "System" in cls_:
                matched_reason = "SecurityManager Modification (System.setSecurityManager)"
                sev = Severity.HIGH.value
            elif name_ in ("load", "loadLibrary") and "System" in cls_:
                matched_reason = f"Native Library Loading (System.{name_})"
                cat = Category.NATIVE.value

            if matched_reason:
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"{cls_}.{name_}() invocation",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["addShutdownHook", "setSecurityManager", "loadLibrary", "System.load"])
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
                        title_override=matched_reason,
                        description_override=f"Method '{method_name}' invokes {cls_}.{name_}() ({matched_reason}).",
                        confidence=0.9,
                    )
                )

        return findings


@register_rule
class SensitiveReconnaissanceRule(SecurityRule):
    """JD-SYS-002: Sensitive host reconnaissance (System.getenv, .ssh, .aws, /etc/passwd)."""

    rule_id = "JD-SYS-002"
    title = "Host Reconnaissance / Sensitive Path Read"
    description = (
        "Constant pool or method references sensitive local host paths (.ssh, .aws, /etc/passwd) "
        "or queries full environment variables (System.getenv)."
    )
    remediation = "Ensure environment variable and configuration reads do not access user credentials."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.INFO_GATHERING.value
    severity = Severity.MEDIUM.value
    cwe = ["CWE-200"]
    mitre_attack = "T1082"

    def analyze_class(
        self,
        class_info: ClassInfo,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        cp = class_info.constant_pool

        for idx, text in get_all_cp_strings(cp):
            text_lower = text.lower().strip()
            for path_pat in SENSITIVE_FILES_OR_PROPS:
                if path_pat in text_lower:
                    ev = Evidence(id=f"CP:{idx}", type="constantPool", index=idx, text=f"Sensitive target: {text}")
                    findings.append(
                        self.create_finding(
                            class_name=class_info.class_name,
                            evidence=[ev],
                            severity_override=Severity.HIGH.value if ".ssh" in text_lower or ".aws" in text_lower or "/etc/" in text_lower else Severity.MEDIUM.value,
                            title_override="Sensitive Host Target / Credential Path in Constant Pool",
                            description_override=f"Constant pool references sensitive host credential path: '{text}'.",
                            confidence=0.88,
                        )
                    )
                    break

        return findings
