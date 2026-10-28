"""
network.py — Network, exfiltration, socket, and C2 communication rules.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

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
    get_new_class,
)

RAW_SOCKET_CLASSES = {
    "java/net/Socket",
    "java/net/SSLSocket",
    "java/net/ServerSocket",
    "java/net/DatagramSocket",
    "javax/net/ssl/SSLSocket",
}

IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

SUSPICIOUS_DOMAINS = [
    ".onion",
    "pastebin.com",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "ngrok.io",
    "ngrok-free.app",
    "requestbin.net",
    "webhook.site",
    "transfer.sh",
    "temp.sh",
]


@register_rule
class RawSocketRule(SecurityRule):
    """JD-NET-001: Raw socket / datagram creation."""

    rule_id = "JD-NET-001"
    title = "Raw Network Socket Creation"
    description = (
        "Direct instantiation of raw Socket, ServerSocket, or DatagramSocket. "
        "Escalated if paired with hardcoded IP literal or triggered at class load time."
    )
    remediation = "Use standard application layer HTTP clients or framework abstractions."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.NETWORK.value
    severity = Severity.MEDIUM.value
    cwe = ["CWE-200", "CWE-319"]
    mitre_attack = "T1071"

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

        # Check for IP literal constants in CP
        has_ip = False
        ip_ev = None
        for idx, text in get_all_cp_strings(cp):
            if IPV4_PATTERN.search(text) and not text.startswith("127.0.0.1"):
                has_ip = True
                ip_ev = Evidence(id=f"CP:{idx}", type="constantPool", index=idx, text=f"IP literal: {text}")
                break

        for instr in instructions:
            is_socket = False
            sock_cls = get_new_class(cp, instr)
            if sock_cls and sock_cls in RAW_SOCKET_CLASSES:
                is_socket = True

            call = get_call_info(cp, instr)
            if call and call.get("class", "").replace(".", "/") in RAW_SOCKET_CLASSES and call.get("name") == "<init>":
                is_socket = True

            if is_socket:
                offset = instr.get("offset", 0)
                is_loadtime = method_name in ("<clinit>", "<init>")
                sev = Severity.HIGH.value if (has_ip or is_loadtime) else Severity.MEDIUM.value
                conf = 0.9 if has_ip else 0.8

                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"Direct socket allocation: {sock_cls or (call.get('class') if call else '')}",
                    )
                ]
                if ip_ev:
                    ev_list.append(ip_ev)

                matched = find_matching_lines(lifted_lines, ["Socket(", "ServerSocket(", "DatagramSocket("])
                line_nos = [m[0] for m in matched]
                for m in matched:
                    ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

                desc = f"Raw socket creation in '{method_name}'"
                if is_loadtime:
                    desc += " inside class initializer / constructor"
                if has_ip:
                    desc += " referencing hardcoded IP"

                findings.append(
                    self.create_finding(
                        class_name=class_info.class_name,
                        method_name=method_name,
                        descriptor=method_info.descriptor,
                        bytecode_offsets=[offset],
                        lifted_lines=line_nos,
                        evidence=ev_list,
                        severity_override=sev,
                        description_override=desc,
                        confidence=conf,
                    )
                )

        return findings


@register_rule
class SuspiciousHostRule(SecurityRule):
    """JD-NET-002: Suspicious URLs, raw external IPs, or exfiltration endpoints in constant pool."""

    rule_id = "JD-NET-002"
    title = "Suspicious Host, Endpoint or C2 URL in Constant Pool"
    description = (
        "Constant pool contains suspicious network targets such as raw public IPs, Tor .onion addresses, "
        "temporary pastebins, or webhooks commonly abused for command-and-control."
    )
    remediation = "Remove unvetted network endpoints and use parameterized, configured endpoints."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.NETWORK.value
    severity = Severity.MEDIUM.value
    cwe = ["CWE-200"]
    mitre_attack = "T1071.001"

    def analyze_class(
        self,
        class_info: ClassInfo,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        cp = class_info.constant_pool

        for idx, text in get_all_cp_strings(cp):
            text_lower = text.lower().strip()
            matched_reason = None
            sev = Severity.MEDIUM.value

            for domain in SUSPICIOUS_DOMAINS:
                if domain in text_lower:
                    matched_reason = f"Known C2/exfiltration domain '{domain}'"
                    sev = Severity.HIGH.value
                    break

            if not matched_reason and IPV4_PATTERN.search(text):
                # Filter out benign loopback or version strings
                ip_match = IPV4_PATTERN.search(text).group(0)
                if not (ip_match.startswith("127.") or ip_match.startswith("0.0.") or ip_match == "255.255.255.255"):
                    matched_reason = f"Hardcoded public IPv4 literal '{ip_match}'"

            if matched_reason:
                ev = Evidence(id=f"CP:{idx}", type="constantPool", index=idx, text=text)
                findings.append(
                    self.create_finding(
                        class_name=class_info.class_name,
                        bytecode_offsets=[],
                        lifted_lines=[],
                        evidence=[ev],
                        severity_override=sev,
                        description_override=f"Suspicious network target in constant pool: {matched_reason} (value: '{text}').",
                        confidence=0.85,
                    )
                )

        return findings


@register_rule
class DnsExfiltrationRule(SecurityRule):
    """JD-NET-003: Potential DNS exfiltration via InetAddress.getByName with dynamic string."""

    rule_id = "JD-NET-003"
    title = "Potential DNS Tunneling / Exfiltration"
    description = (
        "InetAddress.getByName or getAllByName invoked with dynamically constructed hostname, "
        "a classic pattern for DNS exfiltration and out-of-band data transfer."
    )
    remediation = "Validate and sanitize hostnames before invoking DNS resolution."
    kind = Kind.SUSPICIOUS_BEHAVIOR.value
    category = Category.NETWORK.value
    severity = Severity.MEDIUM.value
    cwe = ["CWE-200"]
    mitre_attack = "T1071.004"

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
            if cls_ == "java/net/InetAddress" and name_ in ("getByName", "getAllByName"):
                # Check if preceded by dynamic variable or string concatenation
                prev_instr = instructions[idx - 1] if idx > 0 else None
                is_constant = prev_instr and prev_instr.get("mnemonic") in ("ldc", "ldc_w")

                offset = instr.get("offset", 0)
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"InetAddress.{name_} invocation",
                    )
                ]

                matched = find_matching_lines(lifted_lines, ["InetAddress.getByName", "InetAddress.getAllByName"])
                line_nos = [m[0] for m in matched]
                for m in matched:
                    ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

                sev = Severity.LOW.value if is_constant else Severity.MEDIUM.value
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
                            f"InetAddress.{name_} called with "
                            f"{'static constant' if is_constant else 'dynamic/parameter string'}."
                        ),
                        confidence=0.8,
                    )
                )

        return findings
