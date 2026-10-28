"""
crypto.py — Cryptographic weakness rules (weak hashes, weak ciphers, static keys, Random vs SecureRandom, trust-all TLS).
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
    get_ldc_string,
    get_new_class,
)

WEAK_HASHES = {"MD5", "MD4", "MD2", "SHA-1", "SHA1", "SHA"}
WEAK_CIPHERS = {"DES", "DESEDE", "TRIPLEDES", "RC4", "ARCFOUR", "BLOWFISH", "AES/ECB/PKCS5PADDING", "AES/ECB/NOPADDING", "AES"}

SECURITY_SENSITIVE_NAMES = {
    "token",
    "key",
    "salt",
    "nonce",
    "password",
    "pass",
    "otp",
    "secret",
    "auth",
    "session",
    "credential",
}


@register_rule
class WeakDigestRule(SecurityRule):
    """JD-CRYP-001: Weak cryptographic hash algorithms (MD5, SHA-1) (CWE-328)."""

    rule_id = "JD-CRYP-001"
    title = "Broken Cryptographic Hash Algorithm (CWE-328)"
    description = "Usage of collision-vulnerable or broken hash algorithm (MD5 or SHA-1)."
    remediation = "Upgrade to SHA-256, SHA-384, SHA-512, or SHA-3."
    kind = Kind.VULNERABILITY.value
    category = Category.CRYPTO.value
    severity = Severity.MEDIUM.value
    cwe = ["CWE-328"]

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
            if cls_ == "java/security/MessageDigest" and name_ == "getInstance":
                prev_instr = instructions[idx - 1] if idx > 0 else None
                if prev_instr:
                    ldc = get_ldc_string(cp, prev_instr)
                    if ldc:
                        cp_idx, algo = ldc
                        if algo.upper().strip() in WEAK_HASHES:
                            offset = instr.get("offset", 0)
                            ev_list = [
                                Evidence(
                                    id=f"I:0x{offset:02x}",
                                    type="instruction",
                                    offset=offset,
                                    text=f"MessageDigest.getInstance(\"{algo}\")",
                                ),
                                Evidence(id=f"CP:{cp_idx}", type="constantPool", index=cp_idx, text=algo),
                            ]
                            matched = find_matching_lines(lifted_lines, ["MessageDigest.getInstance"])
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
                                    description_override=f"Insecure hash algorithm '{algo}' requested via MessageDigest.getInstance.",
                                    confidence=0.95,
                                )
                            )

        return findings


@register_rule
class WeakCipherRule(SecurityRule):
    """JD-CRYP-002: Insecure cipher or block mode (DES, RC4, ECB mode, bare AES) (CWE-327)."""

    rule_id = "JD-CRYP-002"
    title = "Insecure Cipher or Cipher Mode (CWE-327)"
    description = (
        "Cipher.getInstance requested with weak cipher (DES, RC4) or ECB mode / bare AES "
        "lacking authentication and initialization vectors."
    )
    remediation = "Use AES-GCM (e.g. 'AES/GCM/NoPadding') or ChaCha20-Poly1305 with unique IVs."
    kind = Kind.VULNERABILITY.value
    category = Category.CRYPTO.value
    severity = Severity.HIGH.value
    cwe = ["CWE-327"]

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
            if cls_ == "javax/crypto/Cipher" and name_ == "getInstance":
                prev_instr = instructions[idx - 1] if idx > 0 else None
                if prev_instr:
                    ldc = get_ldc_string(cp, prev_instr)
                    if ldc:
                        cp_idx, transform = ldc
                        trans_clean = transform.upper().strip()
                        is_weak = (
                            trans_clean in WEAK_CIPHERS
                            or "/ECB" in trans_clean
                            or trans_clean.startswith("DES")
                            or trans_clean == "AES"
                        )
                        if is_weak:
                            offset = instr.get("offset", 0)
                            ev_list = [
                                Evidence(
                                    id=f"I:0x{offset:02x}",
                                    type="instruction",
                                    offset=offset,
                                    text=f"Cipher.getInstance(\"{transform}\")",
                                ),
                                Evidence(id=f"CP:{cp_idx}", type="constantPool", index=cp_idx, text=transform),
                            ]
                            matched = find_matching_lines(lifted_lines, ["Cipher.getInstance"])
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
                                    description_override=f"Insecure cipher transformation '{transform}' requested in Cipher.getInstance.",
                                    confidence=0.95,
                                )
                            )

        return findings


@register_rule
class StaticSecretKeyRule(SecurityRule):
    """JD-CRYP-003: Hardcoded secret key or static IV parameter (CWE-321 / CWE-329)."""

    rule_id = "JD-CRYP-003"
    title = "Hardcoded Cryptographic Key or Static IV (CWE-321 / CWE-329)"
    description = (
        "Constant byte array or string literal passed into SecretKeySpec or IvParameterSpec, "
        "compromising confidential encryption or allowing replay attacks."
    )
    remediation = "Generate random cryptographic keys with KeyGenerator / SecureRandom and load from a secure vault."
    kind = Kind.VULNERABILITY.value
    category = Category.CRYPTO.value
    severity = Severity.HIGH.value
    cwe = ["CWE-321", "CWE-329"]

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
            if name_ == "<init>" and cls_ in ("javax/crypto/spec/SecretKeySpec", "javax/crypto/spec/IvParameterSpec"):
                offset = instr.get("offset", 0)
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"new {cls_}(...)",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["SecretKeySpec", "IvParameterSpec"])
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
                        description_override=f"Instantiation of {cls_} with local constant key/IV material.",
                        confidence=0.85,
                    )
                )

        return findings


@register_rule
class InsecureRandomRule(SecurityRule):
    """JD-CRYP-004: java.util.Random used in security-sensitive method (CWE-330)."""

    rule_id = "JD-CRYP-004"
    title = "Insecure PRNG in Security Context (CWE-330)"
    description = (
        "Pseudorandom number generator java.util.Random used in a security-sensitive context "
        "(method or class name matching token/key/salt/password/secret/otp)."
    )
    remediation = "Replace java.util.Random with java.security.SecureRandom."
    kind = Kind.VULNERABILITY.value
    category = Category.CRYPTO.value
    severity = Severity.MEDIUM.value
    cwe = ["CWE-330"]

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
        name_lower = (method_name + " " + class_info.class_name).lower()
        is_security_context = any(s in name_lower for s in SECURITY_SENSITIVE_NAMES)

        if not is_security_context:
            return findings

        cp = class_info.constant_pool
        for instr in instructions:
            new_cls = get_new_class(cp, instr)
            call = get_call_info(cp, instr)
            is_random = (new_cls == "java/util/Random") or (
                call and call.get("class", "").replace(".", "/") == "java/util/Random"
            )

            if is_random:
                offset = instr.get("offset", 0)
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text="java.util.Random usage in security-sensitive method",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["Random"])
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
                        description_override=(
                            f"java.util.Random used in security-sensitive method '{method_name}'. "
                            "PRNG values are predictable and non-cryptographic."
                        ),
                        confidence=0.85,
                    )
                )

        return findings


@register_rule
class PermissiveTlsRule(SecurityRule):
    """JD-CRYP-005: Trust-all X509TrustManager or HostnameVerifier returning constant true (CWE-295)."""

    rule_id = "JD-CRYP-005"
    title = "Disabled TLS Certificate or Hostname Validation (CWE-295)"
    description = (
        "X509TrustManager with empty checkServerTrusted / checkClientTrusted methods "
        "or HostnameVerifier returning constant true, disabling TLS protections against MITM attacks."
    )
    remediation = "Do not disable certificate or hostname verification. Configure trusted certificate authorities."
    kind = Kind.VULNERABILITY.value
    category = Category.CRYPTO.value
    severity = Severity.HIGH.value
    cwe = ["CWE-295"]

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

        # 1. Permissive HostnameVerifier: verify method returns true immediately (iconst_1 + ireturn)
        if method_name == "verify" and (
            method_info.return_type in ("boolean", "Z")
            or method_info.descriptor.endswith(")Z")
            or "boolean" in method_info.descriptor
        ):
            mnemonics = [i.get("mnemonic") for i in instructions]
            if "iconst_1" in mnemonics and "ireturn" in mnemonics and len(instructions) <= 5:
                offset = instructions[0].get("offset", 0) if instructions else 0
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text="HostnameVerifier.verify returns constant true (iconst_1 + ireturn)",
                    )
                ]
                matched = find_matching_lines(lifted_lines, ["return true", "verify("])
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
                        title_override="Permissive HostnameVerifier (Returns True)",
                        description_override="HostnameVerifier.verify() unconditionally returns true, allowing MITM attacks.",
                        confidence=0.98,
                    )
                )

        # 2. Trust-all X509TrustManager: checkServerTrusted / checkClientTrusted has empty body (only return)
        if method_name in ("checkServerTrusted", "checkClientTrusted"):
            mnemonics = [i.get("mnemonic") for i in instructions]
            # Empty void method has only [return] (0xb1)
            if mnemonics == ["return"]:
                offset = instructions[0].get("offset", 0) if instructions else 0
                ev_list = [
                    Evidence(
                        id=f"I:0x{offset:02x}",
                        type="instruction",
                        offset=offset,
                        text=f"Empty {method_name} (only return instruction)",
                    )
                ]
                matched = find_matching_lines(lifted_lines, [method_name])
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
                        title_override=f"Trust-All X509TrustManager ({method_name})",
                        description_override=f"{method_name} is empty and throws no CertificateException, trusting all certificates.",
                        confidence=0.98,
                    )
                )

        return findings
