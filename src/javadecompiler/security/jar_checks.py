"""
jar_checks.py — Archive verification, manifest inspection & parser hardening.

Implements strict memory bounds against zip-bombs, flags path traversal in zip entries,
detects embedded native binaries, manifest agents, SPI providers, mismatched class paths,
and guards class parser against hostile/malformed bytecode.
"""

from __future__ import annotations

import io
import os
import re
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from javadecompiler.class_parser import ClassFileReader, ClassInfo, parseClassInfo
from javadecompiler.security.models import (
    Category,
    Evidence,
    Finding,
    Kind,
    Location,
    Origin,
    Severity,
)


@dataclass
class ArchiveBounds:
    """Strict limits to defend against resource exhaustion and zip bombs."""

    max_entries: int = 10_000
    max_single_size: int = 32 * 1024 * 1024  # 32 MB
    max_total_size: int = 256 * 1024 * 1024  # 256 MB
    max_compression_ratio: float = 100.0  # 100:1


NATIVE_EXTENSIONS = {".dll", ".so", ".dylib", ".jnilib", ".exe"}
NATIVE_MAGIC_HEADERS = [
    (b"MZ", "Windows PE executable/DLL"),
    (b"\x7fELF", "Linux ELF shared library/executable"),
    (b"\xfe\xed\xfa\xce", "macOS Mach-O 32-bit binary"),
    (b"\xfe\xed\xfa\xcf", "macOS Mach-O 64-bit binary"),
    (b"\xce\xfa\xed\xfe", "macOS Mach-O binary (reverse)"),
    (b"\xcf\xfa\xed\xfe", "macOS Mach-O binary (reverse)"),
    (b"\xca\xfe\xba\xbe", None),  # Note: 0xCAFEBABE is also Java class magic, checked separately
]


def check_embedded_native(entry_name: str, entry_header: bytes) -> Optional[str]:
    """Returns description if entry appears to be a native binary executable or shared library."""
    lower = entry_name.lower()
    for ext in NATIVE_EXTENSIONS:
        if lower.endswith(ext):
            return f"Native extension '{ext}' in entry name"

    if entry_header.startswith(b"MZ"):
        return "Windows PE executable magic (MZ)"
    if entry_header.startswith(b"\x7fELF"):
        return "Linux ELF binary magic (\\x7fELF)"
    if len(entry_header) >= 4:
        for magic, desc in NATIVE_MAGIC_HEADERS[2:6]:
            if entry_header.startswith(magic):
                return f"macOS Mach-O binary magic ({desc})"
    return None


def inspect_manifest(manifest_text: str, jar_path: str = "") -> List[Finding]:
    """Inspects META-INF/MANIFEST.MF for agent definitions and remote Class-Path entries."""
    findings: List[Finding] = []
    lines = manifest_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    # Unfold manifest lines (lines starting with space/tab continue previous line)
    unfolded_lines: List[str] = []
    for line in lines:
        if line.startswith(" ") or line.startswith("\t"):
            if unfolded_lines:
                unfolded_lines[-1] += line[1:]
            else:
                unfolded_lines.append(line.strip())
        else:
            unfolded_lines.append(line)

    agent_headers = {
        "Premain-Class": "JVM premain Java Agent loaded before application start",
        "Agent-Class": "JVM agent loaded dynamically into running JVM",
        "Launcher-Agent-Class": "JVM launcher agent loaded at launch time",
        "Can-Redefine-Classes": "Agent capability to redefine classes dynamically",
        "Can-Retransform-Classes": "Agent capability to retransform classes dynamically",
    }

    for line_idx, line in enumerate(unfolded_lines, 1):
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        # Check for agent headers
        for agent_key, desc in agent_headers.items():
            if key.lower() == agent_key.lower() and value:
                ev = Evidence(
                    id=f"JAR:MANIFEST:{line_idx}",
                    type="jarEntry",
                    text=f"{key}: {value}",
                    path="META-INF/MANIFEST.MF",
                    line=line_idx,
                )
                findings.append(
                    Finding(
                        ruleId="JD-ARCH-MANIFEST-AGENT",
                        title=f"Java Agent Declared in Manifest ({key})",
                        description=f"Manifest defines '{key}: {value}'. {desc}.",
                        remediation="Ensure this agent is authorized and review its premain/agentmain methods.",
                        kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                        category=Category.LOADTIME.value,
                        severity=Severity.HIGH.value,
                        location=Location(
                            className="META-INF/MANIFEST.MF",
                            jarEntryPath="META-INF/MANIFEST.MF",
                            liftedLineNumbers=[line_idx],
                        ),
                        evidence=[ev],
                        confidence=1.0,
                        cwe=["CWE-506"],
                    )
                )

        # Check for remote Class-Path
        if key.lower() == "class-path" and value:
            for token in value.split():
                token_lower = token.lower()
                if (
                    token_lower.startswith("http://")
                    or token_lower.startswith("https://")
                    or token_lower.startswith("ftp://")
                ):
                    ev = Evidence(
                        id=f"JAR:CLASSPATH:{line_idx}",
                        type="jarEntry",
                        text=f"Remote Class-Path: {token}",
                        path="META-INF/MANIFEST.MF",
                        line=line_idx,
                    )
                    findings.append(
                        Finding(
                            ruleId="JD-ARCH-CLASSPATH-REMOTE",
                            title="Remote Class-Path URL in Manifest",
                            description=f"Manifest Class-Path references remote external URL: {token}",
                            remediation="Remove remote Class-Path URLs and bundle dependencies locally.",
                            kind=Kind.MALICIOUS_INDICATOR.value,
                            category=Category.ARCHIVE.value,
                            severity=Severity.HIGH.value,
                            location=Location(
                                className="META-INF/MANIFEST.MF",
                                jarEntryPath="META-INF/MANIFEST.MF",
                                liftedLineNumbers=[line_idx],
                            ),
                            evidence=[ev],
                            confidence=1.0,
                            cwe=["CWE-829"],
                        )
                    )

    return findings


def safe_parse_class_bytes(
    class_bytes: bytes,
    file_name: str = "",
) -> Tuple[Optional[ClassInfo], List[Finding]]:
    """Safely parses raw class bytes into ClassInfo, emitting JD-ARCH-MALFORMED on any error."""
    findings: List[Finding] = []

    if len(class_bytes) < 4:
        ev = Evidence(id="RAW:0", type="instruction", text=f"Truncated file: size {len(class_bytes)} bytes", offset=0)
        findings.append(
            Finding(
                ruleId="JD-ARCH-MALFORMED",
                title="Malformed Class File: Truncated",
                description=f"Class file is too short ({len(class_bytes)} bytes) to contain valid header.",
                remediation="Ensure file is an intact, valid compiled .class file.",
                kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                category=Category.ARCHIVE.value,
                severity=Severity.MEDIUM.value,
                location=Location(className=file_name or "UnknownClass", jarEntryPath=file_name or None),
                evidence=[ev],
                analysisCoverage="partial",
                partialReason="Truncated class file header",
                confidence=1.0,
                cwe=["CWE-754"],
            )
        )
        return None, findings

    if not class_bytes.startswith(b"\xca\xfe\xba\xbe"):
        magic_hex = class_bytes[:4].hex()
        ev = Evidence(id="RAW:0", type="instruction", text=f"Invalid magic: 0x{magic_hex}", offset=0)
        findings.append(
            Finding(
                ruleId="JD-ARCH-MALFORMED",
                title="Malformed Class File: Invalid Magic Header",
                description=f"Class file header magic 0x{magic_hex} does not equal standard 0xCAFEBABE.",
                remediation="Verify whether the file is corrupted or disguised non-JVM binary.",
                kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                category=Category.ARCHIVE.value,
                severity=Severity.MEDIUM.value,
                location=Location(className=file_name or "UnknownClass", jarEntryPath=file_name or None),
                evidence=[ev],
                analysisCoverage="partial",
                partialReason="Invalid class magic number",
                confidence=1.0,
                cwe=["CWE-754"],
            )
        )
        return None, findings

    try:
        reader = ClassFileReader.__new__(ClassFileReader)
        reader.fileData = class_bytes
        reader.currentCursor = 0
        reader.fileLength = len(class_bytes)
        class_info = parseClassInfo(reader)
    except Exception as e:
        ev = Evidence(id="RAW:0", type="instruction", text=f"Parse failure: {type(e).__name__}: {e}", offset=0)
        findings.append(
            Finding(
                ruleId="JD-ARCH-MALFORMED",
                title="Malformed Class File: Parsing Exception",
                description=f"Failed to parse class bytecode or constant pool: {type(e).__name__} ({e})",
                remediation="Inspect class file with javap or binary hex viewer for corruption.",
                kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                category=Category.ARCHIVE.value,
                severity=Severity.MEDIUM.value,
                location=Location(className=file_name or "UnknownClass", jarEntryPath=file_name or None),
                evidence=[ev],
                analysisCoverage="partial",
                partialReason=f"Parser crash: {e}",
                confidence=1.0,
                cwe=["CWE-754"],
            )
        )
        return None, findings

    # Check for path vs class name mismatch
    if file_name and file_name.endswith(".class"):
        expected_suffix = class_info.class_name.replace(".", "/") + ".class"
        # Normalize slashes
        norm_file = file_name.replace("\\", "/")
        if "/" not in norm_file:
            mismatched = norm_file != os.path.basename(expected_suffix)
        else:
            mismatched = (
                not norm_file.endswith(expected_suffix)
                and not norm_file.startswith("BOOT-INF/")
                and not norm_file.startswith("WEB-INF/")
            )

        if mismatched:
            ev = Evidence(
                id="CP:NAME",
                type="constantPool",
                text=f"Declared class '{class_info.class_name}' located at archive path '{norm_file}'",
            )
            findings.append(
                Finding(
                    ruleId="JD-ARCH-MISMATCH",
                    title="Mismatched Class Name vs Archive Path",
                    description=(
                        f"Class '{class_info.class_name}' is stored at unexpected path '{norm_file}', "
                        "which may indicate obfuscation or evasion."
                    ),
                    remediation="Align package and directory structure according to JVM specifications.",
                    kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                    category=Category.EVASION.value,
                    severity=Severity.LOW.value,
                    location=Location(
                        className=class_info.class_name,
                        jarEntryPath=norm_file,
                    ),
                    evidence=[ev],
                    confidence=0.8,
                    cwe=["CWE-1027"],
                )
            )

    return class_info, findings


def inspect_jar_archive(
    jar_source: Any,
    bounds: Optional[ArchiveBounds] = None,
) -> Tuple[List[ClassInfo], List[Finding], Dict[str, bytes]]:
    """Opens and validates a JAR archive enforcing strict resource bounds and security checks."""
    bounds = bounds or ArchiveBounds()
    findings: List[Finding] = []
    classes: List[ClassInfo] = []
    raw_class_bytes: Dict[str, bytes] = {}

    jar_name = "archive.jar"
    if isinstance(jar_source, (str, os.PathLike)):
        jar_name = os.path.basename(str(jar_source))
        if not os.path.exists(jar_source):
            raise FileNotFoundError(f"JAR file not found: {jar_source}")
        try:
            zip_file = zipfile.ZipFile(jar_source, "r")
        except zipfile.BadZipFile as e:
            findings.append(
                Finding(
                    ruleId="JD-ARCH-MALFORMED",
                    title="Invalid or Corrupted JAR File",
                    description=f"ZipFile parser failed to open archive: {e}",
                    remediation="Ensure file is an intact ZIP/JAR archive.",
                    kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                    category=Category.ARCHIVE.value,
                    severity=Severity.HIGH.value,
                    location=Location(className=jar_name, jarEntryPath=jar_name),
                    evidence=[Evidence(id="JAR:0", type="jarEntry", text=str(e), path=jar_name)],
                    confidence=1.0,
                    cwe=["CWE-754"],
                )
            )
            return classes, findings, raw_class_bytes
    elif isinstance(jar_source, bytes):
        try:
            zip_file = zipfile.ZipFile(io.BytesIO(jar_source), "r")
        except zipfile.BadZipFile as e:
            findings.append(
                Finding(
                    ruleId="JD-ARCH-MALFORMED",
                    title="Invalid or Corrupted JAR File",
                    description=f"ZipFile parser failed: {e}",
                    remediation="Ensure payload is a valid ZIP/JAR archive.",
                    kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                    category=Category.ARCHIVE.value,
                    severity=Severity.HIGH.value,
                    location=Location(className=jar_name, jarEntryPath=jar_name),
                    evidence=[Evidence(id="JAR:0", type="jarEntry", text=str(e), path=jar_name)],
                    confidence=1.0,
                    cwe=["CWE-754"],
                )
            )
            return classes, findings, raw_class_bytes
    else:
        zip_file = zip_source

    with zip_file:
        infolist = zip_file.infolist()

        # Check total entry count
        if len(infolist) > bounds.max_entries:
            ev = Evidence(
                id="JAR:ENTRIES",
                type="jarEntry",
                text=f"Total entries {len(infolist)} exceeds limit {bounds.max_entries}",
                path=jar_name,
            )
            findings.append(
                Finding(
                    ruleId="JD-ARCH-ZIPBOMB",
                    title="Excessive Archive Entry Count (Zip Bomb Defense)",
                    description=f"Archive contains {len(infolist)} entries, exceeding safety limit of {bounds.max_entries}.",
                    remediation="Inspect archive for zip-bomb characteristics.",
                    kind=Kind.MALICIOUS_INDICATOR.value,
                    category=Category.ARCHIVE.value,
                    severity=Severity.HIGH.value,
                    location=Location(className=jar_name, jarEntryPath=jar_name),
                    evidence=[ev],
                    confidence=1.0,
                    cwe=["CWE-409"],
                )
            )
            return classes, findings, raw_class_bytes

        total_uncompressed = 0

        for info in infolist:
            entry_name = info.filename

            # 1. Zip-Slip / Path Traversal Check
            norm_name = entry_name.replace("\\", "/")
            if ".." in norm_name or norm_name.startswith("/") or (len(norm_name) > 1 and norm_name[1] == ":"):
                ev = Evidence(
                    id=f"JAR:SLIP:{entry_name}",
                    type="jarEntry",
                    text=f"Path traversal detected in entry name: {entry_name}",
                    path=entry_name,
                )
                findings.append(
                    Finding(
                        ruleId="JD-ARCH-TRAVERSAL",
                        title="Archive Path Traversal / Zip-Slip Entry",
                        description=f"Archive entry '{entry_name}' contains path traversal sequences ('..' or root/drive prefix).",
                        remediation="Do not extract this archive to disk. Sanitize archive entry paths.",
                        kind=Kind.MALICIOUS_INDICATOR.value,
                        category=Category.ARCHIVE.value,
                        severity=Severity.HIGH.value,
                        location=Location(className=entry_name, jarEntryPath=entry_name),
                        evidence=[ev],
                        confidence=1.0,
                        cwe=["CWE-22"],
                    )
                )

            # 2. Resource & Compression Ratio Limits (Zip Bomb Defense)
            if info.file_size > bounds.max_single_size:
                ev = Evidence(
                    id=f"JAR:SIZE:{entry_name}",
                    type="jarEntry",
                    text=f"Uncompressed size {info.file_size} exceeds {bounds.max_single_size}",
                    path=entry_name,
                )
                findings.append(
                    Finding(
                        ruleId="JD-ARCH-ZIPBOMB",
                        title="Single Archive Entry Exceeds Maximum Size",
                        description=f"Entry '{entry_name}' uncompressed size {info.file_size} bytes exceeds limit of {bounds.max_single_size} bytes.",
                        remediation="Verify whether the entry is an expansion attack.",
                        kind=Kind.MALICIOUS_INDICATOR.value,
                        category=Category.ARCHIVE.value,
                        severity=Severity.HIGH.value,
                        location=Location(className=entry_name, jarEntryPath=entry_name),
                        evidence=[ev],
                        confidence=1.0,
                        cwe=["CWE-409"],
                    )
                )

            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > bounds.max_compression_ratio and info.file_size > 65536:
                    ev = Evidence(
                        id=f"JAR:RATIO:{entry_name}",
                        type="jarEntry",
                        text=f"Compression ratio {ratio:.1f}:1 exceeds {bounds.max_compression_ratio}:1",
                        path=entry_name,
                    )
                    findings.append(
                        Finding(
                            ruleId="JD-ARCH-ZIPBOMB",
                            title="Abnormal Archive Compression Ratio (Zip Bomb Indicator)",
                            description=f"Entry '{entry_name}' has compression ratio {ratio:.1f}:1, exceeding safety threshold of {bounds.max_compression_ratio}:1.",
                            remediation="Do not extract archive using unconstrained tools.",
                            kind=Kind.MALICIOUS_INDICATOR.value,
                            category=Category.ARCHIVE.value,
                            severity=Severity.HIGH.value,
                            location=Location(className=entry_name, jarEntryPath=entry_name),
                            evidence=[ev],
                            confidence=1.0,
                            cwe=["CWE-409"],
                        )
                    )

            total_uncompressed += info.file_size
            if total_uncompressed > bounds.max_total_size:
                ev = Evidence(
                    id="JAR:TOTAL_SIZE",
                    type="jarEntry",
                    text=f"Total uncompressed size {total_uncompressed} exceeds {bounds.max_total_size}",
                    path=jar_name,
                )
                findings.append(
                    Finding(
                        ruleId="JD-ARCH-ZIPBOMB",
                        title="Total Archive Uncompressed Size Exceeded",
                        description=f"Cumulative uncompressed archive size {total_uncompressed} bytes exceeds safety limit of {bounds.max_total_size} bytes.",
                        remediation="Stop extraction and audit archive.",
                        kind=Kind.MALICIOUS_INDICATOR.value,
                        category=Category.ARCHIVE.value,
                        severity=Severity.HIGH.value,
                        location=Location(className=jar_name, jarEntryPath=jar_name),
                        evidence=[ev],
                        confidence=1.0,
                        cwe=["CWE-409"],
                    )
                )
                break

            # Read entry bytes in memory
            try:
                entry_bytes = zip_file.read(entry_name)
            except Exception as e:
                findings.append(
                    Finding(
                        ruleId="JD-ARCH-MALFORMED",
                        title="Corrupted Archive Entry Read Failure",
                        description=f"Failed to read archive entry '{entry_name}': {e}",
                        remediation="Verify archive integrity.",
                        kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                        category=Category.ARCHIVE.value,
                        severity=Severity.MEDIUM.value,
                        location=Location(className=entry_name, jarEntryPath=entry_name),
                        evidence=[Evidence(id="JAR:ENTRY", type="jarEntry", text=str(e), path=entry_name)],
                        confidence=0.9,
                        cwe=["CWE-754"],
                    )
                )
                continue

            # 3. Check for Embedded Native Binaries
            native_desc = check_embedded_native(entry_name, entry_bytes[:8])
            if native_desc:
                ev = Evidence(
                    id=f"JAR:NATIVE:{entry_name}",
                    type="jarEntry",
                    text=f"Native binary artifact: {native_desc}",
                    path=entry_name,
                )
                findings.append(
                    Finding(
                        ruleId="JD-ARCH-NATIVE",
                        title="Embedded Native Binary in JAR",
                        description=f"Archive contains embedded native executable/shared library: '{entry_name}' ({native_desc}).",
                        remediation="Audit native binaries with reverse engineering tools and verify signing.",
                        kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                        category=Category.NATIVE.value,
                        severity=Severity.MEDIUM.value,
                        location=Location(className=entry_name, jarEntryPath=entry_name),
                        evidence=[ev],
                        confidence=1.0,
                        cwe=["CWE-506"],
                    )
                )

            # 4. Check Manifest
            if entry_name.upper() == "META-INF/MANIFEST.MF":
                try:
                    manifest_text = entry_bytes.decode("utf-8", errors="replace")
                    manifest_findings = inspect_manifest(manifest_text, jar_name)
                    findings.extend(manifest_findings)
                except Exception:
                    pass

            # 5. Check SPI ServiceLoader definitions
            if entry_name.startswith("META-INF/services/") and len(entry_name) > len("META-INF/services/"):
                service_interface = entry_name[len("META-INF/services/") :]
                try:
                    service_impls = [
                        l.strip()
                        for l in entry_bytes.decode("utf-8", errors="replace").splitlines()
                        if l.strip() and not l.strip().startswith("#")
                    ]
                    impl_str = ", ".join(service_impls[:3])
                    ev = Evidence(
                        id=f"JAR:SPI:{service_interface}",
                        type="jarEntry",
                        text=f"Service provider for {service_interface}: {impl_str}",
                        path=entry_name,
                    )
                    findings.append(
                        Finding(
                            ruleId="JD-ARCH-SPI",
                            title=f"SPI ServiceLoader Provider Declared ({service_interface})",
                            description=(
                                f"Archive registers ServiceLoader provider for '{service_interface}' "
                                f"with implementation(s): {impl_str}. Loaded dynamically at runtime."
                            ),
                            remediation="Verify whether dynamic service loading is expected for this library.",
                            kind=Kind.HYGIENE.value,
                            category=Category.LOADTIME.value,
                            severity=Severity.LOW.value,
                            location=Location(className=entry_name, jarEntryPath=entry_name),
                            evidence=[ev],
                            confidence=0.8,
                            cwe=["CWE-506"],
                        )
                    )
                except Exception:
                    pass

            # 6. Parse .class files safely
            if entry_name.endswith(".class") and not entry_name.startswith("__MACOSX"):
                raw_class_bytes[entry_name] = entry_bytes
                c_info, parse_findings = safe_parse_class_bytes(entry_bytes, entry_name)
                findings.extend(parse_findings)
                if c_info:
                    classes.append(c_info)

    return classes, findings, raw_class_bytes
