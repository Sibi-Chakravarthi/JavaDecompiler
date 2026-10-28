"""
behavior.py — Layer B: Multi-step behavior-chain & intra-method taint-lite detectors.

Detects multi-instruction and 1-hop inter-procedural exploit chains:
  1. JD-CHAIN-REVSHELL: Socket streams connected to Process streams (reverse shell).
  2. JD-CHAIN-DROPPER: Network read -> file write / byte buffer -> exec / defineClass.
  3. JD-CHAIN-DECODE-EXEC: Encoded constant -> Base64/XOR decode -> exec/reflection sink.
  4. JD-CHAIN-EXFIL: Sensitive file/env read -> network output sink.
  5. JD-CHAIN-TAINT-SINK: Parameter -> string concat -> exec, SQL, path, or JNDI sink.
  6. JD-CHAIN-TIMEBOMB: Time/env check -> conditional branch gating a dangerous sink.
  7. JD-CHAIN-CLINIT: <clinit> -> helper method -> dangerous sink.

Each finding produces an ordered chain of evidence offsets and lines (source -> transform -> sink).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from javadecompiler.class_parser import ClassInfo, MethodInfo
from javadecompiler.security.callgraph import CallGraph
from javadecompiler.security.models import (
    Category,
    Evidence,
    Finding,
    Kind,
    Location,
    Origin,
    Severity,
)
from javadecompiler.security.rules.helpers import (
    find_matching_lines,
    get_all_cp_strings,
    get_call_info,
    get_ldc_string,
    get_new_class,
)


class BehaviorDetector:
    """Analyzes intra-method def-use sequences and 1-hop callee summaries for exploit chains."""

    def __init__(self, call_graph: Optional[CallGraph] = None) -> None:
        self.call_graph = call_graph

    def detect_chains(
        self,
        class_info: ClassInfo,
        raw_methods: Optional[Dict[str, str]] = None,
        instructions_by_method: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        raw_methods = raw_methods or {}

        # If instructions not supplied, disassemble methods on the fly
        if instructions_by_method is None:
            instructions_by_method = {}
            try:
                from javadecompiler.disassembler import disassembleMethod
            except ImportError:
                from disassembler import disassembleMethod

            for m_name, m_info in class_info.methods.items():
                if m_info.bytecode:
                    try:
                        instructions_by_method[m_name] = disassembleMethod(m_name, m_info.bytecode)
                    except Exception:
                        instructions_by_method[m_name] = []

        # 1. Intra-method chain analysis
        for m_name, m_info in class_info.methods.items():
            instructions = instructions_by_method.get(m_name, [])
            if not instructions:
                continue

            lifted_str = raw_methods.get(m_name, "")
            lifted_lines = lifted_str.splitlines() if lifted_str else []

            # Chain 1: REVSHELL
            f_rev = self._detect_revshell(class_info, m_name, m_info, instructions, lifted_lines)
            if f_rev:
                findings.append(f_rev)

            # Chain 2: DROPPER
            f_drop = self._detect_dropper(class_info, m_name, m_info, instructions, lifted_lines)
            if f_drop:
                findings.append(f_drop)

            # Chain 3: DECODE-EXEC
            f_dec = self._detect_decode_exec(class_info, m_name, m_info, instructions, lifted_lines)
            if f_dec:
                findings.append(f_dec)

            # Chain 4: EXFIL
            f_exfil = self._detect_exfil(class_info, m_name, m_info, instructions, lifted_lines)
            if f_exfil:
                findings.append(f_exfil)

            # Chain 5: TAINT-SINK
            f_taint = self._detect_taint_sink(class_info, m_name, m_info, instructions, lifted_lines)
            if f_taint:
                findings.append(f_taint)

            # Chain 6: TIMEBOMB
            f_bomb = self._detect_timebomb(class_info, m_name, m_info, instructions, lifted_lines)
            if f_bomb:
                findings.append(f_bomb)

        # Chain 7: CLINIT transitive chain
        f_clinit = self._detect_clinit_chain(class_info, instructions_by_method, raw_methods)
        if f_clinit:
            findings.extend(f_clinit)

        return findings

    def _detect_revshell(
        self,
        class_info: ClassInfo,
        method_name: str,
        method_info: MethodInfo,
        instructions: List[Dict[str, Any]],
        lifted_lines: List[str],
    ) -> Optional[Finding]:
        """Chain 1: Socket streams connected to Process streams (Reverse Shell)."""
        cp = class_info.constant_pool
        socket_stream_offsets: List[Tuple[int, str]] = []
        process_stream_offsets: List[Tuple[int, str]] = []

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue
            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")
            off = instr.get("offset", 0)

            if "Socket" in cls_ and name_ in ("getInputStream", "getOutputStream"):
                socket_stream_offsets.append((off, f"Socket.{name_}()"))
            elif "Process" in cls_ and name_ in ("getInputStream", "getOutputStream", "getErrorStream"):
                process_stream_offsets.append((off, f"Process.{name_}()"))
            elif cls_ == "java/lang/Runtime" and name_ == "exec":
                process_stream_offsets.append((off, "Runtime.exec()"))
            elif cls_ == "java/lang/ProcessBuilder" and name_ == "start":
                process_stream_offsets.append((off, "ProcessBuilder.start()"))

        if socket_stream_offsets and process_stream_offsets:
            offsets = [socket_stream_offsets[0][0], process_stream_offsets[0][0]]
            ev_list = [
                Evidence(
                    id=f"I:0x{socket_stream_offsets[0][0]:02x}",
                    type="instruction",
                    offset=socket_stream_offsets[0][0],
                    text=f"[SOURCE] {socket_stream_offsets[0][1]}",
                ),
                Evidence(
                    id=f"I:0x{process_stream_offsets[0][0]:02x}",
                    type="instruction",
                    offset=process_stream_offsets[0][0],
                    text=f"[SINK] {process_stream_offsets[0][1]}",
                ),
            ]
            matched = find_matching_lines(lifted_lines, ["Socket", "Process", "exec(", "getOutputStream", "getInputStream"])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            return Finding(
                ruleId="JD-CHAIN-REVSHELL",
                title="Reverse Shell Stream Pumping Chain (CWE-78 / CWE-506)",
                description=(
                    f"Method '{method_name}' establishes network Socket streams and connects them to OS Process streams, "
                    "a signature pattern for interactive reverse shell backdoors."
                ),
                remediation="Ensure program does not bridge remote network connections directly to an operating system shell.",
                kind=Kind.MALICIOUS_INDICATOR.value,
                category=Category.EXECUTION.value,
                severity=Severity.CRITICAL.value,
                confidence=0.98,
                confidenceSources={"behaviorChain": 0.98},
                cwe=["CWE-78", "CWE-506"],
                mitreAttack="T1059.004",
                location=Location(
                    className=class_info.class_name,
                    methodName=method_name,
                    descriptor=method_info.descriptor,
                    bytecodeOffsets=offsets,
                    liftedLineNumbers=line_nos,
                ),
                evidence=ev_list,
                origin=Origin.STATIC.value,
            )
        return None

    def _detect_dropper(
        self,
        class_info: ClassInfo,
        method_name: str,
        method_info: MethodInfo,
        instructions: List[Dict[str, Any]],
        lifted_lines: List[str],
    ) -> Optional[Finding]:
        """Chain 2: Network stream read -> file write -> exec or defineClass."""
        cp = class_info.constant_pool
        net_read: Optional[Tuple[int, str]] = None
        file_write: Optional[Tuple[int, str]] = None
        exec_sink: Optional[Tuple[int, str]] = None

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue
            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")
            off = instr.get("offset", 0)

            if ("Socket" in cls_ or "HttpURLConnection" in cls_ or "URL" in cls_) and (
                name_ in ("getInputStream", "openStream")
            ):
                if not net_read:
                    net_read = (off, f"{cls_}.{name_}()")

            if ("FileOutputStream" in cls_ or "Files" in cls_) and name_ in ("write", "<init>", "newOutputStream"):
                if not file_write:
                    file_write = (off, f"{cls_}.{name_}()")

            if ("Runtime" in cls_ and name_ == "exec") or (
                "ClassLoader" in cls_ and name_ in ("defineClass", "loadClass")
            ):
                if not exec_sink:
                    exec_sink = (off, f"{cls_}.{name_}()")

        if net_read and (file_write or exec_sink) and (exec_sink or (net_read and file_write and "drop" in method_name.lower())):
            ev_list = []
            offsets = []
            if net_read:
                offsets.append(net_read[0])
                ev_list.append(Evidence(id=f"I:0x{net_read[0]:02x}", type="instruction", offset=net_read[0], text=f"[SOURCE] Network download: {net_read[1]}"))
            if file_write:
                offsets.append(file_write[0])
                ev_list.append(Evidence(id=f"I:0x{file_write[0]:02x}", type="instruction", offset=file_write[0], text=f"[TRANSFORM] Local file write: {file_write[1]}"))
            if exec_sink:
                offsets.append(exec_sink[0])
                ev_list.append(Evidence(id=f"I:0x{exec_sink[0]:02x}", type="instruction", offset=exec_sink[0], text=f"[SINK] Dynamic execution: {exec_sink[1]}"))

            matched = find_matching_lines(lifted_lines, ["openStream", "getInputStream", "FileOutputStream", "exec(", "defineClass"])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            return Finding(
                ruleId="JD-CHAIN-DROPPER",
                title="Dropper / Payload Download-and-Execute Chain (CWE-506)",
                description=(
                    f"Method '{method_name}' downloads remote bytes from network, writes them to disk, and executes them, "
                    "constituting a multi-stage dropper/downloader chain."
                ),
                remediation="Remove arbitrary remote payload downloads. Enforce signature and hash validation.",
                kind=Kind.MALICIOUS_INDICATOR.value,
                category=Category.DYNAMIC_LOADING.value,
                severity=Severity.CRITICAL.value,
                confidence=0.95,
                confidenceSources={"behaviorChain": 0.95},
                cwe=["CWE-506", "CWE-470"],
                mitreAttack="T1105",
                location=Location(
                    className=class_info.class_name,
                    methodName=method_name,
                    descriptor=method_info.descriptor,
                    bytecodeOffsets=offsets,
                    liftedLineNumbers=line_nos,
                ),
                evidence=ev_list,
                origin=Origin.STATIC.value,
            )
        return None

    def _detect_decode_exec(
        self,
        class_info: ClassInfo,
        method_name: str,
        method_info: MethodInfo,
        instructions: List[Dict[str, Any]],
        lifted_lines: List[str],
    ) -> Optional[Finding]:
        """Chain 3: Encoded/encrypted constant -> Base64/XOR decode -> exec / forName / Method.invoke."""
        cp = class_info.constant_pool
        decode_op: Optional[Tuple[int, str]] = None
        sink_op: Optional[Tuple[int, str]] = None

        for instr in instructions:
            off = instr.get("offset", 0)
            mn = instr.get("mnemonic", "")
            if mn in ("ixor", "lxor") and not decode_op:
                decode_op = (off, "XOR decryption operation")

            call = get_call_info(cp, instr)
            if call:
                cls_ = call.get("class", "").replace(".", "/")
                name_ = call.get("name", "")
                if "Base64" in cls_ and name_ == "decode" and not decode_op:
                    decode_op = (off, "Base64.decode()")
                elif ("Runtime" in cls_ and name_ == "exec") or (
                    "ProcessBuilder" in cls_ and name_ in ("<init>", "start")
                ) or ("Method" in cls_ and name_ == "invoke") or ("ClassLoader" in cls_ and name_ == "defineClass") or (
                    "Class" in cls_ and name_ == "forName"
                ):
                    if not sink_op:
                        sink_op = (off, f"{cls_}.{name_}()")

        if decode_op and sink_op:
            offsets = [decode_op[0], sink_op[0]]
            ev_list = [
                Evidence(id=f"I:0x{decode_op[0]:02x}", type="instruction", offset=decode_op[0], text=f"[TRANSFORM] {decode_op[1]}"),
                Evidence(id=f"I:0x{sink_op[0]:02x}", type="instruction", offset=sink_op[0], text=f"[SINK] Dynamic execution: {sink_op[1]}"),
            ]
            matched = find_matching_lines(lifted_lines, ["Base64", " ^ ", "exec(", "invoke(", "forName(", "defineClass"])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            return Finding(
                ruleId="JD-CHAIN-DECODE-EXEC",
                title="Obfuscated Decode-and-Execute Chain (CWE-1027)",
                description=(
                    f"Method '{method_name}' decodes obfuscated bytes (via {decode_op[1]}) "
                    f"and passes the result into dynamic execution sink ({sink_op[1]})."
                ),
                remediation="Avoid dynamic execution of obfuscated or encrypted payloads.",
                kind=Kind.MALICIOUS_INDICATOR.value,
                category=Category.EVASION.value,
                severity=Severity.CRITICAL.value,
                confidence=0.94,
                confidenceSources={"behaviorChain": 0.94},
                cwe=["CWE-1027", "CWE-506"],
                mitreAttack="T1027",
                location=Location(
                    className=class_info.class_name,
                    methodName=method_name,
                    descriptor=method_info.descriptor,
                    bytecodeOffsets=offsets,
                    liftedLineNumbers=line_nos,
                ),
                evidence=ev_list,
                origin=Origin.STATIC.value,
            )
        return None

    def _detect_exfil(
        self,
        class_info: ClassInfo,
        method_name: str,
        method_info: MethodInfo,
        instructions: List[Dict[str, Any]],
        lifted_lines: List[str],
    ) -> Optional[Finding]:
        """Chain 4: Sensitive file/env read -> network output stream / HTTP."""
        cp = class_info.constant_pool
        sensitive_read: Optional[Tuple[int, str]] = None
        net_write: Optional[Tuple[int, str]] = None

        # Check CP for sensitive file markers
        has_sensitive_cp = any(
            any(k in s.lower() for k in (".ssh", ".aws", "/etc/passwd", "user.home"))
            for _, s in get_all_cp_strings(cp)
        )

        for instr in instructions:
            call = get_call_info(cp, instr)
            if not call:
                continue
            cls_ = call.get("class", "").replace(".", "/")
            name_ = call.get("name", "")
            off = instr.get("offset", 0)

            if (cls_ == "java/lang/System" and name_ in ("getenv", "getProperty")) or (
                "FileInputStream" in cls_ and name_ == "<init>" and has_sensitive_cp
            ):
                if not sensitive_read:
                    sensitive_read = (off, f"{cls_}.{name_}()")

            if ("Socket" in cls_ or "OutputStream" in cls_ or "HttpURLConnection" in cls_) and (
                name_ in ("getOutputStream", "write")
            ):
                if not net_write:
                    net_write = (off, f"{cls_}.{name_}()")

        if sensitive_read and net_write:
            offsets = [sensitive_read[0], net_write[0]]
            ev_list = [
                Evidence(id=f"I:0x{sensitive_read[0]:02x}", type="instruction", offset=sensitive_read[0], text=f"[SOURCE] Sensitive read: {sensitive_read[1]}"),
                Evidence(id=f"I:0x{net_write[0]:02x}", type="instruction", offset=net_write[0], text=f"[SINK] Network exfiltration: {net_write[1]}"),
            ]
            matched = find_matching_lines(lifted_lines, ["getenv", "getProperty", "getOutputStream", ".write(", "Socket"])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            return Finding(
                ruleId="JD-CHAIN-EXFIL",
                title="Sensitive Data Read and Network Exfiltration Chain (CWE-200)",
                description=(
                    f"Method '{method_name}' reads sensitive environment or host data ({sensitive_read[1]}) "
                    f"and connects to a network output sink ({net_write[1]})."
                ),
                remediation="Do not transmit host credentials or sensitive environment data over network sockets.",
                kind=Kind.MALICIOUS_INDICATOR.value,
                category=Category.NETWORK.value,
                severity=Severity.CRITICAL.value,
                confidence=0.92,
                confidenceSources={"behaviorChain": 0.92},
                cwe=["CWE-200", "CWE-506"],
                mitreAttack="T1048",
                location=Location(
                    className=class_info.class_name,
                    methodName=method_name,
                    descriptor=method_info.descriptor,
                    bytecodeOffsets=offsets,
                    liftedLineNumbers=line_nos,
                ),
                evidence=ev_list,
                origin=Origin.STATIC.value,
            )
        return None

    def _detect_taint_sink(
        self,
        class_info: ClassInfo,
        method_name: str,
        method_info: MethodInfo,
        instructions: List[Dict[str, Any]],
        lifted_lines: List[str],
    ) -> Optional[Finding]:
        """Chain 5: Method parameter flowing through string concatenation into critical sink."""
        if not method_info.param_types:
            return None

        cp = class_info.constant_pool
        # Parameter loads: aload_0 (if static), aload_1, aload_2, aload_3, aload
        param_load_mnemonics = {"aload_0", "aload_1", "aload_2", "aload_3", "aload"}
        has_param_load = False
        param_off = None
        has_concat = False
        concat_off = None
        sink_call: Optional[Tuple[int, str]] = None

        for instr in instructions:
            mn = instr.get("mnemonic", "")
            off = instr.get("offset", 0)

            if mn in param_load_mnemonics and not has_param_load:
                has_param_load = True
                param_off = off

            call = get_call_info(cp, instr)
            if call:
                cls_ = call.get("class", "").replace(".", "/")
                name_ = call.get("name", "")

                if "StringBuilder" in cls_ and name_ == "append":
                    has_concat = True
                    concat_off = off

                if ("Runtime" in cls_ and name_ == "exec") or (
                    "Statement" in cls_ and name_.startswith("execute")
                ) or ("InitialContext" in cls_ and name_ == "lookup") or (
                    "FileOutputStream" in cls_ and name_ == "<init>"
                ):
                    if not sink_call:
                        sink_call = (off, f"{cls_}.{name_}")

            if mn == "invokedynamic":
                # makeConcatWithConstants (Java 9+ string concat)
                has_concat = True
                concat_off = off

        if has_param_load and has_concat and sink_call:
            offsets = [o for o in (param_off, concat_off, sink_call[0]) if o is not None]
            ev_list = [
                Evidence(id=f"I:0x{param_off:02x}", type="instruction", offset=param_off, text="[SOURCE] Method parameter read"),
                Evidence(id=f"I:0x{concat_off:02x}", type="instruction", offset=concat_off, text="[TRANSFORM] Dynamic string concatenation"),
                Evidence(id=f"I:0x{sink_call[0]:02x}", type="instruction", offset=sink_call[0], text=f"[SINK] Untrusted sink: {sink_call[1]}"),
            ]
            matched = find_matching_lines(lifted_lines, ["exec(", "executeQuery(", "executeUpdate(", "lookup(", "new FileOutputStream"])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            return Finding(
                ruleId="JD-CHAIN-TAINT-SINK",
                title="Tainted Parameter Flowing into Injection Sink (CWE-78 / CWE-89)",
                description=(
                    f"Method parameter in '{method_name}' flows through dynamic string concatenation into "
                    f"unvalidated sink ({sink_call[1]})."
                ),
                remediation="Parameterize inputs or validate against a strict allowlist before passing to sinks.",
                kind=Kind.VULNERABILITY.value,
                category=Category.INJECTION.value,
                severity=Severity.HIGH.value,
                confidence=0.9,
                confidenceSources={"behaviorChain": 0.9},
                cwe=["CWE-78", "CWE-89", "CWE-22"],
                location=Location(
                    className=class_info.class_name,
                    methodName=method_name,
                    descriptor=method_info.descriptor,
                    bytecodeOffsets=offsets,
                    liftedLineNumbers=line_nos,
                ),
                evidence=ev_list,
                origin=Origin.STATIC.value,
            )
        return None

    def _detect_timebomb(
        self,
        class_info: ClassInfo,
        method_name: str,
        method_info: MethodInfo,
        instructions: List[Dict[str, Any]],
        lifted_lines: List[str],
    ) -> Optional[Finding]:
        """Chain 6: Conditional branch comparing time/date/env gating a dangerous sink."""
        cp = class_info.constant_pool
        has_time_call = False
        time_off = None
        has_branch = False
        branch_off = None
        sink_call: Optional[Tuple[int, str]] = None

        branch_mnemonics = {"ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge"}

        for instr in instructions:
            mn = instr.get("mnemonic", "")
            off = instr.get("offset", 0)

            call = get_call_info(cp, instr)
            if call:
                cls_ = call.get("class", "").replace(".", "/")
                name_ = call.get("name", "")

                if (cls_ == "java/lang/System" and name_ in ("currentTimeMillis", "nanoTime")) or (
                    "LocalDate" in cls_ and name_ == "now"
                ):
                    has_time_call = True
                    time_off = off

                if ("Runtime" in cls_ and name_ == "exec") or (
                    "Socket" in cls_ and name_ == "<init>"
                ) or ("ClassLoader" in cls_ and name_ == "defineClass"):
                    if not sink_call:
                        sink_call = (off, f"{cls_}.{name_}")

            if mn in branch_mnemonics and has_time_call and not has_branch:
                has_branch = True
                branch_off = off

        if has_time_call and has_branch and sink_call:
            offsets = [o for o in (time_off, branch_off, sink_call[0]) if o is not None]
            ev_list = [
                Evidence(id=f"I:0x{time_off:02x}", type="instruction", offset=time_off, text="[SOURCE] System time evaluation"),
                Evidence(id=f"I:0x{branch_off:02x}", type="instruction", offset=branch_off, text="[TRANSFORM] Conditional branch gating execution"),
                Evidence(id=f"I:0x{sink_call[0]:02x}", type="instruction", offset=sink_call[0], text=f"[SINK] Gated dangerous sink: {sink_call[1]}"),
            ]
            matched = find_matching_lines(lifted_lines, ["currentTimeMillis", "LocalDate.now", "exec(", "Socket("])
            line_nos = [m[0] for m in matched]
            for m in matched:
                ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

            return Finding(
                ruleId="JD-CHAIN-TIMEBOMB",
                title="Time-Bomb Gated Execution Chain (CWE-511)",
                description=(
                    f"Method '{method_name}' evaluates system wall-clock time and conditionally branches to execute "
                    f"a dangerous payload sink ({sink_call[1]})."
                ),
                remediation="Ensure date checks are documented business logic rather than unverified logic bombs.",
                kind=Kind.MALICIOUS_INDICATOR.value,
                category=Category.EVASION.value,
                severity=Severity.HIGH.value,
                confidence=0.88,
                confidenceSources={"behaviorChain": 0.88},
                cwe=["CWE-511", "CWE-506"],
                mitreAttack="T1497.003",
                location=Location(
                    className=class_info.class_name,
                    methodName=method_name,
                    descriptor=method_info.descriptor,
                    bytecodeOffsets=offsets,
                    liftedLineNumbers=line_nos,
                ),
                evidence=ev_list,
                origin=Origin.STATIC.value,
            )
        return None

    def _detect_clinit_chain(
        self,
        class_info: ClassInfo,
        instructions_by_method: Dict[str, List[Dict[str, Any]]],
        raw_methods: Dict[str, str],
    ) -> List[Finding]:
        """Chain 7: <clinit> -> helper method -> network/exec/reflection/file-write sink."""
        findings: List[Finding] = []
        if "<clinit>" not in class_info.methods:
            return findings

        clinit_m = class_info.methods["<clinit>"]
        clinit_instrs = instructions_by_method.get("<clinit>", [])
        cp = class_info.constant_pool

        # Identify callees called from <clinit>
        helpers_called: List[Tuple[int, str]] = []
        for instr in clinit_instrs:
            call = get_call_info(cp, instr)
            if call and call.get("class", "").replace(".", "/") == class_info.class_name.replace(".", "/"):
                callee_name = call.get("name", "")
                if callee_name != "<clinit>" and callee_name in class_info.methods:
                    helpers_called.append((instr.get("offset", 0), callee_name))

        for call_off, helper_name in helpers_called:
            helper_instrs = instructions_by_method.get(helper_name, [])
            for h_instr in helper_instrs:
                h_call = get_call_info(cp, h_instr)
                if not h_call:
                    continue
                cls_ = h_call.get("class", "").replace(".", "/")
                name_ = h_call.get("name", "")
                h_off = h_instr.get("offset", 0)

                is_sink = (
                    ("Runtime" in cls_ and name_ == "exec")
                    or ("Socket" in cls_)
                    or ("Method" in cls_ and name_ == "invoke")
                    or ("ClassLoader" in cls_ and name_ == "defineClass")
                    or ("FileOutputStream" in cls_ and name_ == "<init>")
                )

                if is_sink:
                    ev_list = [
                        Evidence(id=f"I:0x{call_off:02x}", type="instruction", offset=call_off, text=f"[SOURCE] <clinit> invokes helper: {helper_name}()"),
                        Evidence(id=f"I:0x{h_off:02x}", type="instruction", offset=h_off, text=f"[SINK] Callee sink: {cls_}.{name_}()"),
                    ]
                    matched = find_matching_lines(raw_methods.get(helper_name, "").splitlines(), ["exec(", "Socket(", "invoke(", "defineClass("])
                    line_nos = [m[0] for m in matched]
                    for m in matched:
                        ev_list.append(Evidence(id=f"L:{m[0]}", type="liftedLine", line=m[0], text=m[1]))

                    findings.append(
                        Finding(
                            ruleId="JD-CHAIN-CLINIT",
                            title="Load-Time Callee Exploit Chain (<clinit> -> helper -> sink)",
                            description=(
                                f"Static initializer <clinit> invokes helper method '{helper_name}()' which executes "
                                f"dangerous sink {cls_}.{name_}(). Executes automatically when class is loaded."
                            ),
                            remediation="Do not perform side effects or invoke dangerous sinks from class static initializers.",
                            kind=Kind.MALICIOUS_INDICATOR.value,
                            category=Category.LOADTIME.value,
                            severity=Severity.CRITICAL.value,
                            confidence=0.96,
                            confidenceSources={"behaviorChain": 0.96},
                            cwe=["CWE-506"],
                            mitreAttack="T1547",
                            location=Location(
                                className=class_info.class_name,
                                methodName="<clinit>",
                                descriptor=clinit_m.descriptor,
                                bytecodeOffsets=[call_off, h_off],
                                liftedLineNumbers=line_nos,
                            ),
                            evidence=ev_list,
                            origin=Origin.STATIC.value,
                        )
                    )
                    break

        return findings
