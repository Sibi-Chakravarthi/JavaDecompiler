"""
secrets.py — Hardcoded credentials, API keys, tokens, and Shannon entropy analysis.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Tuple

from javadecompiler.class_parser import ClassInfo
from javadecompiler.security.models import (
    Category,
    Evidence,
    Finding,
    Kind,
    Location,
    Severity,
)
from javadecompiler.security.rules.base import SecurityRule, register_rule
from javadecompiler.security.rules.helpers import get_all_cp_strings

SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Personal Access Token", re.compile(r"\bghp_[0-9a-zA-Z]{36}\b")),
    ("GitHub Fine-Grained Token", re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b")),
    ("JSON Web Token (JWT)", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("PEM Private Key Header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Slack API Token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b")),
    ("Generic API Key Literal", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-+=/]{16,})['\"]")),
]


def shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def redact_secret(secret: str) -> str:
    """Masks secret preserving first 4 and last 4 characters for identification."""
    s = secret.strip()
    if len(s) <= 8:
        return "********"
    head = s[:4]
    tail = s[-4:]
    masked_count = max(4, len(s) - 8)
    return f"{head}{'*' * masked_count}{tail}"


@register_rule
class HardcodedSecretsRule(SecurityRule):
    """JD-SEC-001: Hardcoded credentials, private keys, API tokens, high entropy strings (CWE-798)."""

    rule_id = "JD-SEC-001"
    title = "Hardcoded Secret / Credential (CWE-798)"
    description = (
        "Hardcoded private key, API token, cloud credential, or high-entropy cryptographic "
        "secret embedded directly in the constant pool."
    )
    remediation = (
        "Store secrets in environment variables, secret vaults (AWS Secrets Manager, HashiCorp Vault), "
        "or encrypted configuration files. Never commit secrets to bytecode."
    )
    kind = Kind.VULNERABILITY.value
    category = Category.SECRETS.value
    severity = Severity.HIGH.value
    cwe = ["CWE-798"]
    mitre_attack = "T1552"

    def analyze_class(
        self,
        class_info: ClassInfo,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        cp = class_info.constant_pool

        for idx, text in get_all_cp_strings(cp):
            text_str = text.strip()
            if not text_str or len(text_str) < 16:
                continue

            # 1. Check known signature regexes
            matched_name = None
            matched_value = None
            for pattern_name, regex in SECRET_PATTERNS:
                m = regex.search(text_str)
                if m:
                    matched_name = pattern_name
                    matched_value = m.group(0)
                    break

            if matched_name and matched_value:
                redacted = redact_secret(matched_value)
                ev = Evidence(
                    id=f"CP:{idx}",
                    type="constantPool",
                    index=idx,
                    text=f"{matched_name}: {redacted}",
                )
                findings.append(
                    self.create_finding(
                        class_name=class_info.class_name,
                        evidence=[ev],
                        severity_override=Severity.CRITICAL.value if "Private Key" in matched_name or "AWS" in matched_name else Severity.HIGH.value,
                        title_override=f"Hardcoded {matched_name}",
                        description_override=f"Constant pool entry {idx} contains hardcoded {matched_name} ('{redacted}').",
                        confidence=0.98,
                    )
                )
                continue

            # 2. Check Shannon entropy on sufficiently long opaque strings
            # Skip class descriptors like (Ljava/lang/String;...) and standard paths/URLs
            if (
                len(text_str) >= 24
                and not text_str.startswith("http://")
                and not text_str.startswith("https://")
                and not text_str.startswith("Ljava/")
                and not text_str.startswith("Lorg/")
                and not text_str.startswith("Lcom/")
                and "/" not in text_str
                and "\\" not in text_str
                and " " not in text_str
            ):
                entropy = shannon_entropy(text_str)
                if entropy > 4.5:
                    redacted = redact_secret(text_str)
                    ev = Evidence(
                        id=f"CP:{idx}",
                        type="constantPool",
                        index=idx,
                        text=f"High entropy string (entropy: {entropy:.2f} bits/char): {redacted}",
                    )
                    findings.append(
                        self.create_finding(
                            class_name=class_info.class_name,
                            evidence=[ev],
                            severity_override=Severity.MEDIUM.value,
                            title_override="High-Entropy String Literal (Potential Key/Token)",
                            description_override=(
                                f"Constant pool entry {idx} has high Shannon entropy ({entropy:.2f} bits/char, "
                                f"length {len(text_str)}): '{redacted}'."
                            ),
                            confidence=0.8,
                        )
                    )

        return findings
