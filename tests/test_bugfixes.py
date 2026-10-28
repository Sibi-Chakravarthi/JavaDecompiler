"""
test_bugfixes.py — Regression Test Suite for JavaDecompiler Core Pipeline Bugfixes

Tests specific edge cases and bug vectors identified and fixed across:
1. class_parser.py (CP slot stepping, modern tags 15-20, modified UTF-8, attributes)
2. disassembler.py (tableswitch/lookupswitch padding, wide opcode 0xC4, 5-byte invokes)
3. cfg_builder.py (4-byte branch targets, exception table leaders, loop back-edges)
4. lifter.py (static vs instance slot mapping, Category-2 types, caughtEx, invokedynamic)
5. report.py (HTML escaping for <init>, <clinit>, XSS prevention, UTF-8 output)
6. semantic_restorer.py (code fence & preamble stripping, connection timeout resilience)
"""

import html
import json
import os
import struct
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from javadecompiler.class_parser import (
    ClassFileReader,
    ClassInfo,
    MethodInfo,
    decodeModifiedUtf8,
    parseClassInfo,
    parseConstantPool,
    parseDescriptor,
)
from javadecompiler.disassembler import disassembleMethod, jvmOpcodes
from javadecompiler.cfg_builder import (
    BasicBlock,
    buildControlFlowGraph,
    findLeaders,
    resolveBranchTarget,
)
from javadecompiler.lifter import (
    LifterContext,
    StackSimulator,
    liftMethod,
    map_parameter_slots,
)
from javadecompiler.report import generateHtmlReport
from javadecompiler.semantic_restorer import (
    OSContext,
    RestorationResult,
    SemanticRestorer,
    extractJsonPayload,
    stripMarkdownFences,
)


class TestCorePipelineBugfixes(unittest.TestCase):
    """Regression test suite verifying all 8 bug categories across the core pipeline."""

    # =========================================================================
    # 1. Constant Pool 8-Byte Slot Stepping, Modern Tags & Modified UTF-8
    # =========================================================================
    def test_constant_pool_long_double_and_modern_tags(self):
        """Verifies 8-byte CP slot stepping (None placeholder), JVM tags 15-20, and modified UTF-8."""
        # Construct synthetic constant pool with:
        # idx 1: Long (tag 5) -> takes slots 1 and 2 (slot 2 is None)
        # idx 3: Double (tag 6) -> takes slots 3 and 4 (slot 4 is None)
        # idx 5: MethodHandle (tag 15) -> 3 bytes
        # idx 6: MethodType (tag 16) -> 2 bytes
        # idx 7: Dynamic (tag 17) -> 4 bytes
        # idx 8: InvokeDynamic (tag 18) -> 4 bytes
        # idx 9: Module (tag 19) -> 2 bytes
        # idx 10: Package (tag 20) -> 2 bytes
        pool_bytes = bytearray()
        
        # 1. CONSTANT_Long: tag 5, 8 bytes (0x00000000_12345678)
        pool_bytes.append(5)
        pool_bytes.extend(struct.pack(">q", 0x12345678))

        # 3. CONSTANT_Double: tag 6, 8 bytes (3.14159)
        pool_bytes.append(6)
        pool_bytes.extend(struct.pack(">d", 3.14159))

        # 5. CONSTANT_MethodHandle: tag 15, 3 bytes (ref_kind=6 [REF_invokeStatic], ref_index=42)
        pool_bytes.append(15)
        pool_bytes.append(6)
        pool_bytes.extend(struct.pack(">H", 42))

        # 6. CONSTANT_MethodType: tag 16, 2 bytes (descriptor_index=10)
        pool_bytes.append(16)
        pool_bytes.extend(struct.pack(">H", 10))

        # 7. CONSTANT_Dynamic: tag 17, 4 bytes (bm_index=0, nat_index=12)
        pool_bytes.append(17)
        pool_bytes.extend(struct.pack(">H", 0))
        pool_bytes.extend(struct.pack(">H", 12))

        # 8. CONSTANT_InvokeDynamic: tag 18, 4 bytes (bm_index=1, nat_index=14)
        pool_bytes.append(18)
        pool_bytes.extend(struct.pack(">H", 1))
        pool_bytes.extend(struct.pack(">H", 14))

        # 9. CONSTANT_Module: tag 19, 2 bytes (name_index=20)
        pool_bytes.append(19)
        pool_bytes.extend(struct.pack(">H", 20))

        # 10. CONSTANT_Package: tag 20, 2 bytes (name_index=22)
        pool_bytes.append(20)
        pool_bytes.extend(struct.pack(">H", 22))

        reader = ClassFileReader.from_bytes(bytes(pool_bytes))
        # Total pool count is 11 (indices 1 through 10)
        cp = parseConstantPool(reader, 11)

        # 1. Verify 8-byte stepping and None placeholders
        self.assertEqual(cp[1]["type"], "Primitive64")
        self.assertEqual(cp[1]["kind"], "Long")
        self.assertIsNone(cp[2], "Slot 2 must be an explicit None placeholder per JVM Spec §4.4.5")

        self.assertEqual(cp[3]["type"], "Primitive64")
        self.assertEqual(cp[3]["kind"], "Double")
        self.assertIsNone(cp[4], "Slot 4 must be an explicit None placeholder per JVM Spec §4.4.5")

        # 2. Verify modern tags 15–20
        self.assertEqual(cp[5]["type"], "MethodHandle")
        self.assertEqual(cp[5]["referenceKind"], 6)
        self.assertEqual(cp[5]["referenceIndex"], 42)

        self.assertEqual(cp[6]["type"], "MethodType")
        self.assertEqual(cp[6]["descriptorIndex"], 10)

        self.assertEqual(cp[7]["type"], "Dynamic")
        self.assertEqual(cp[7]["bootstrapMethodAttrIndex"], 0)
        self.assertEqual(cp[7]["nameAndTypeIndex"], 12)

        self.assertEqual(cp[8]["type"], "InvokeDynamic")
        self.assertEqual(cp[8]["bootstrapMethodAttrIndex"], 1)
        self.assertEqual(cp[8]["nameAndTypeIndex"], 14)

        self.assertEqual(cp[9]["type"], "Module")
        self.assertEqual(cp[9]["nameIndex"], 20)

        self.assertEqual(cp[10]["type"], "Package")
        self.assertEqual(cp[10]["nameIndex"], 22)

        # 3. Modified UTF-8 decoding tests
        # Null character in Modified UTF-8 is 0xC0 0x80
        null_encoded = b"Hello\xc0\x80World"
        self.assertEqual(decodeModifiedUtf8(null_encoded), "Hello\x00World")

        # Standard ASCII
        self.assertEqual(decodeModifiedUtf8(b"SimpleText"), "SimpleText")

    # =========================================================================
    # 2. Switch 4-Byte Alignment & Variable-Length Decoding
    # =========================================================================
    def test_disassembler_tableswitch_lookupswitch_alignment(self):
        """Tests decoding tableswitch and lookupswitch across all 4 byte alignments (offsets 0, 1, 2, 3)."""
        # Test tableswitch at offsets 0, 1, 2, 3 followed by return (0xB1)
        for offset in (0, 1, 2, 3):
            code = bytearray(b"\x00" * offset)  # nop padding to reach exact start offset
            # Opcode 0xAA (tableswitch)
            code.append(0xaa)
            pad_len = (4 - ((offset + 1) % 4)) % 4
            code.extend(b"\x00" * pad_len)
            
            # default=20, low=1, high=2, jump1=10, jump2=15
            code.extend(struct.pack(">i", 20))  # default
            code.extend(struct.pack(">i", 1))   # low
            code.extend(struct.pack(">i", 2))   # high
            code.extend(struct.pack(">i", 10))  # target for case 1
            code.extend(struct.pack(">i", 15))  # target for case 2
            
            # Follow with return (0xB1)
            expected_return_offset = len(code)
            code.append(0xb1)  # return

            instructions = disassembleMethod("testTableSwitch", bytes(code))
            switch_instr = instructions[offset]
            self.assertEqual(switch_instr["mnemonic"], "tableswitch")
            self.assertEqual(switch_instr["offset"], offset)
            self.assertEqual(switch_instr["defaultTarget"], offset + 20)
            self.assertEqual(switch_instr["targets"], [offset + 10, offset + 15])
            
            # Ensure the subsequent return instruction decoded cleanly at the exact offset
            return_instr = instructions[-1]
            self.assertEqual(return_instr["mnemonic"], "return")
            self.assertEqual(return_instr["offset"], expected_return_offset)

        # Test lookupswitch at offsets 0, 1, 2, 3 followed by return (0xB1)
        for offset in (0, 1, 2, 3):
            code = bytearray(b"\x00" * offset)
            code.append(0xab)  # lookupswitch
            pad_len = (4 - ((offset + 1) % 4)) % 4
            code.extend(b"\x00" * pad_len)

            # default=25, npairs=2, (match=100, off=12), (match=200, off=18)
            code.extend(struct.pack(">i", 25))
            code.extend(struct.pack(">i", 2))
            code.extend(struct.pack(">i", 100))
            code.extend(struct.pack(">i", 12))
            code.extend(struct.pack(">i", 200))
            code.extend(struct.pack(">i", 18))

            expected_return_offset = len(code)
            code.append(0xb1)  # return

            instructions = disassembleMethod("testLookupSwitch", bytes(code))
            switch_instr = instructions[offset]
            self.assertEqual(switch_instr["mnemonic"], "lookupswitch")
            self.assertEqual(switch_instr["defaultTarget"], offset + 25)
            self.assertEqual(switch_instr["targets"], [offset + 12, offset + 18])

            return_instr = instructions[-1]
            self.assertEqual(return_instr["mnemonic"], "return")
            self.assertEqual(return_instr["offset"], expected_return_offset)

        # Test corrupted switch error guarding
        # Corrupted tableswitch: high < low
        bad_table = bytearray([0xaa, 0x00, 0x00, 0x00])  # pad=3
        bad_table.extend(struct.pack(">iii", 10, 5, 2))  # low=5, high=2
        with self.assertRaises(ValueError):
            disassembleMethod("corruptedTable", bytes(bad_table))

        # Corrupted lookupswitch: negative npairs
        bad_lookup = bytearray([0xab, 0x00, 0x00, 0x00])
        bad_lookup.extend(struct.pack(">ii", 10, -3))
        with self.assertRaises(ValueError):
            disassembleMethod("corruptedLookup", bytes(bad_lookup))

    # =========================================================================
    # 3. Wide (0xC4) and 5-Byte Invoke Instructions
    # =========================================================================
    def test_disassembler_wide_and_5byte_invokes(self):
        """Verifies wide instructions (6-byte wide iinc, 4-byte wide iload) and 5-byte invokes."""
        code = bytearray()
        
        # 1. wide iinc: 0xC4 0x84, index=300 (0x012C), const=-5 (0xFFFB) -> 6 bytes
        offset_wide_iinc = len(code)
        code.append(0xc4)
        code.append(0x84)
        code.extend(struct.pack(">H", 300))
        code.extend(struct.pack(">h", -5))

        # 2. wide iload: 0xC4 0x15, index=258 (0x0102) -> 4 bytes
        offset_wide_iload = len(code)
        code.append(0xc4)
        code.append(0x15)
        code.extend(struct.pack(">H", 258))

        # 3. invokeinterface: 0xB9, cp_idx=10, count=3, trailing=0 -> 5 bytes
        offset_invokeinterface = len(code)
        code.append(0xb9)
        code.extend(struct.pack(">H", 10))
        code.append(3)
        code.append(0)

        # 4. invokedynamic: 0xBA, cp_idx=15, trailing=0, 0 -> 5 bytes
        offset_invokedynamic = len(code)
        code.append(0xba)
        code.extend(struct.pack(">H", 15))
        code.append(0)
        code.append(0)

        # 5. return (0xB1) at the end
        offset_return = len(code)
        code.append(0xb1)

        instructions = disassembleMethod("testWideAndInvokes", bytes(code))
        self.assertEqual(len(instructions), 5)

        # Verify wide iinc
        instr0 = instructions[0]
        self.assertEqual(instr0["offset"], offset_wide_iinc)
        self.assertEqual(instr0["mnemonic"], "wide")
        self.assertEqual(instr0["index"], 300)
        self.assertEqual(instr0["const"], -5)

        # Verify wide iload
        instr1 = instructions[1]
        self.assertEqual(instr1["offset"], offset_wide_iload)
        self.assertEqual(instr1["mnemonic"], "wide")
        self.assertEqual(instr1["index"], 258)

        # Verify invokeinterface length (5 bytes: 10 + 5 = 15)
        instr2 = instructions[2]
        self.assertEqual(instr2["offset"], offset_invokeinterface)
        self.assertEqual(instr2["mnemonic"], "invokeinterface")
        self.assertEqual(len(instr2["operands"]), 4)

        # Verify invokedynamic length (5 bytes: 15 + 5 = 20)
        instr3 = instructions[3]
        self.assertEqual(instr3["offset"], offset_invokedynamic)
        self.assertEqual(instr3["mnemonic"], "invokedynamic")
        self.assertEqual(len(instr3["operands"]), 4)

        # Verify return offset matches exactly
        instr4 = instructions[4]
        self.assertEqual(instr4["offset"], offset_return)
        self.assertEqual(instr4["mnemonic"], "return")

    # =========================================================================
    # 4. Backward Loop Targets and Exception Table CFG Leaders
    # =========================================================================
    def test_cfg_backward_loop_and_exception_handlers(self):
        """Verifies CFG splits blocks at backward goto targets and exception handler entry points."""
        # Method with a backward goto loop and an exception handler:
        # offset 0: iconst_0 (1 byte)
        # offset 1: istore_1 (1 byte)
        # offset 2: iload_1 (1 byte) <- loop header
        # offset 3: bipush 10 (2 bytes)
        # offset 5: if_icmpge +8 -> offset 13 (3 bytes)
        # offset 8: iinc 1, 1 (3 bytes)
        # offset 11: goto -9 -> offset 2 (3 bytes) <- backward branch
        # offset 14: return (1 byte)
        # offset 15: astore_2 (1 byte) <- catch handler entry
        # offset 16: return (1 byte)
        code = bytearray()
        code.append(0x03)  # 0: iconst_0
        code.append(0x3c)  # 1: istore_1
        code.append(0x1b)  # 2: iload_1
        code.extend([0x10, 10])  # 3: bipush 10
        code.extend([0xa2, 0x00, 0x09])  # 5: if_icmpge +9 -> offset 14
        code.extend([0x84, 0x01, 0x01])  # 8: iinc 1, 1
        code.extend([0xa7, 0xff, 0xf7])  # 11: goto -9 -> offset 2
        code.append(0xb1)  # 14: return
        code.append(0x4d)  # 15: astore_2 (catch handler)
        code.append(0xb1)  # 16: return

        instructions = disassembleMethod("testLoopCfg", bytes(code))
        exception_handlers = [
            {"start_pc": 2, "end_pc": 14, "handler_pc": 15, "catch_type": 0}
        ]

        cfg = buildControlFlowGraph(instructions, exception_handlers)

        # Verify block splitting
        # Must have block at 0, block at 2 (loop header), block at 14 (exit), and block at 15 (catch handler)
        self.assertIn(0, cfg)
        self.assertIn(2, cfg, "Loop header target (offset 2) must be a basic block leader")
        self.assertIn(14, cfg)
        self.assertIn(15, cfg, "Exception handler_pc (offset 15) must be a basic block leader")

        # Verify edges: block at 8 (containing goto at 11) must branch to block 2
        block8 = None
        for b in cfg.values():
            if any(instr["offset"] == 11 for instr in b.instructions):
                block8 = b
                break
        self.assertIsNotNone(block8)
        self.assertIn(2, block8.successors, "Back-edge to loop header at offset 2 must be wired")

        # Verify exception edge: protected block 2 must wire to handler 15
        self.assertIn(15, cfg[2].successors, "Protected block must connect to exception handler block at offset 15")

    # =========================================================================
    # 5. Static vs. Instance Parameter Slots & Category-2 Stepping
    # =========================================================================
    def test_lifter_static_vs_instance_parameter_slots(self):
        """Verifies static methods do not emit 'this', Category-2 types step 2 slots, and binary op order."""
        # 1. Test parameter slot mapping helper
        # Static method: (int, long, double, String) -> (I, J, D, Ljava/lang/String;)
        desc = "(IJDLjava/lang/String;)V"
        static_flags = 0x0008  # ACC_STATIC
        names, types = map_parameter_slots(static_flags, desc)
        
        self.assertEqual(names[0], "param0")  # int: slot 0
        self.assertEqual(types[0], "int")
        self.assertEqual(names[1], "param1")  # long (Category-2): slot 1
        self.assertEqual(types[1], "long")
        self.assertEqual(names[3], "param2")  # double (Category-2): slot 3
        self.assertEqual(types[3], "double")
        self.assertEqual(names[5], "param3")  # String: slot 5
        self.assertEqual(types[5], "String")
        self.assertNotIn("this", names.values())

        # Instance method: slot 0 is 'this', param0 begins at slot 1
        instance_flags = 0x0001  # ACC_PUBLIC
        inames, itypes = map_parameter_slots(instance_flags, desc)
        self.assertEqual(inames[0], "this")
        self.assertEqual(inames[1], "param0")
        self.assertEqual(inames[2], "param1")
        self.assertEqual(inames[4], "param2")
        self.assertEqual(inames[6], "param3")

        # 2. Binary operation order preservation:
        # Bytecode: iload_0, iload_1, isub, ireturn -> param0 - param1
        # Not commutative: must be a - b, not b - a
        sub_code = bytes([0x1a, 0x1b, 0x64, 0xac])  # iload_0, iload_1, isub, ireturn
        m_info = MethodInfo(
            name="subTest",
            descriptor="(II)I",
            access_flags=0x0009,  # public static
            bytecode=sub_code,
            is_static=True,
            param_types=["int", "int"],
            return_type="int",
        )
        c_info = ClassInfo(
            class_name="MathOps",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=61,
            minor_version=0,
            constant_pool={},
            methods={"subTest": m_info},
        )
        lifted = liftMethod(c_info, "subTest", m_info)
        self.assertIn("param0 - param1", lifted, "Non-commutative subtraction order must be preserved")
        self.assertNotIn("this", lifted, "Static method must never reference 'this'")

        # Division order: iload_0, iload_1, idiv, ireturn -> param0 / param1
        div_code = bytes([0x1a, 0x1b, 0x6c, 0xac])
        m_div = MethodInfo(
            name="divTest",
            descriptor="(II)I",
            access_flags=0x0009,
            bytecode=div_code,
            is_static=True,
            param_types=["int", "int"],
            return_type="int",
        )
        c_info.methods["divTest"] = m_div
        lifted_div = liftMethod(c_info, "divTest", m_div)
        self.assertIn("param0 / param1", lifted_div)

    # =========================================================================
    # 6. Exception Handler Stack Pre-Population & Underflow Resilience
    # =========================================================================
    def test_lifter_exception_handler_and_underflow_resilience(self):
        """Verifies handler_pc block starts with caughtEx on stack and underflow falls back cleanly."""
        # 1. Exception handler block: starts with astore_1 (0x4C), return (0xB1)
        handler_code = bytes([0x4c, 0xb1])
        m_info = MethodInfo(
            name="catchTest",
            descriptor="()V",
            access_flags=0x0001,
            bytecode=handler_code,
            is_static=False,
            param_types=[],
            return_type="void",
            exception_handlers=[{"start_pc": 0, "end_pc": 0, "handler_pc": 0, "catch_type": 0}],
        )
        c_info = ClassInfo(
            class_name="TryCatchClass",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=61,
            minor_version=0,
            constant_pool={},
            methods={"catchTest": m_info},
        )
        lifted = liftMethod(c_info, "catchTest", m_info)
        self.assertIn("var1 = caughtEx;", lifted, "Catch block must store pre-populated caughtEx, not /* stack_underflow */")

        # 2. Underflow fallback resilience: popping from an empty simulator returns _stack_undef
        ctx = LifterContext.create(c_info, m_info)
        sim = StackSimulator(ctx)
        popped = sim._pop()
        self.assertEqual(popped, "_stack_undef", "Stack underflow must fall back to _stack_undef gracefully")

        # 3. Java 9+ invokedynamic makeConcatWithConstants lifting
        indy_cp = {
            1: {"type": "Utf8", "value": "makeConcatWithConstants"},
            2: {"type": "Utf8", "value": "(Ljava/lang/String;I)Ljava/lang/String;"},
            3: {"type": "NameAndType", "nameIndex": 1, "descriptorIndex": 2},
            4: {"type": "InvokeDynamic", "bootstrapMethodAttrIndex": 0, "nameAndTypeIndex": 3},
        }
        # Bytecode: aload_0 (0x2A), iconst_5 (0x08), invokedynamic 0x0004 (0xBA, 0x00, 0x04, 0x00, 0x00), areturn (0xB0)
        indy_bytes = bytes([0x2a, 0x08, 0xba, 0x00, 0x04, 0x00, 0x00, 0xb0])
        m_indy = MethodInfo(
            name="concatTest",
            descriptor="(Ljava/lang/String;)Ljava/lang/String;",
            access_flags=0x0009,
            bytecode=indy_bytes,
            is_static=True,
            param_types=["String"],
            return_type="String",
        )
        c_indy = ClassInfo(
            class_name="ConcatClass",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=61,
            minor_version=0,
            constant_pool=indy_cp,
            methods={"concatTest": m_indy},
        )
        lifted_indy = liftMethod(c_indy, "concatTest", m_indy)
        self.assertIn("param0 + 5", lifted_indy, "invokedynamic makeConcatWithConstants must lift to string concatenation")

    # =========================================================================
    # 7. HTML Escaping for <init>, <clinit>, XSS and Windows UTF-8 Output
    # =========================================================================
    def test_report_html_escapes_init_clinit_and_xss(self):
        """Verifies <init>, <clinit>, and XSS injections are safely escaped in HTML and written with utf-8."""
        m_init = MethodInfo(
            name="<init>",
            descriptor="()V",
            access_flags=0x0001,
            bytecode=bytes([0x2a, 0xb7, 0x00, 0x01, 0xb1]),
            is_static=False,
            param_types=[],
            return_type="void",
        )
        m_clinit = MethodInfo(
            name="<clinit>",
            descriptor="()V",
            access_flags=0x0008,
            bytecode=bytes([0xb1]),
            is_static=True,
            param_types=[],
            return_type="void",
        )
        c_info = ClassInfo(
            class_name="XssTestClass",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=61,
            minor_version=0,
            constant_pool={},
            methods={"<init>": m_init, "<clinit>": m_clinit},
        )

        restored_result = RestorationResult(
            method_name="<init>",
            renamed_variables={"<script>alert(1)</script>": "safeVar"},
            javadoc="/** Constructor */",
            reconstructed_code="public XssTestClass() { super(); }",
            mode="offline_heuristic",
        )

        html_out = generateHtmlReport(
            classes=[c_info],
            raw_methods={"XssTestClass": {"<init>": "super();", "<clinit>": ""}},
            restored_methods={"XssTestClass": {"<init>": restored_result}},
            target_name="<script>evil()</script>.jar",
            ai_engine="TestEngine",
        )

        # 1. Verify <init> and <clinit> are properly escaped
        self.assertIn("&lt;init&gt;", html_out, "Method name <init> must be HTML-escaped to &lt;init&gt;")
        self.assertIn("&lt;clinit&gt;", html_out, "Method name <clinit> must be HTML-escaped to &lt;clinit&gt;")

        # 2. Verify malicious XSS payload is escaped
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_out)
        self.assertNotIn("<script>evil()</script>", html_out)
        self.assertIn("&lt;script&gt;evil()&lt;/script&gt;", html_out)

        # 3. Verify writing to temporary file with UTF-8 succeeds without Windows cp1252 crash
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(html_out)
            self.assertGreater(os.path.getsize(tmp_path), 500)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # =========================================================================
    # 8. Semantic Restorer Fence Stripping & Offline Resilience
    # =========================================================================
    def test_semantic_restorer_strips_fences_and_handles_offline(self):
        """Verifies markdown fence stripping, JSON payload recovery, and offline network error resilience."""
        # 1. Fence stripping helper tests
        fenced_java = "```java\npublic void hello() {\n    System.out.println(1);\n}\n```"
        stripped = stripMarkdownFences(fenced_java)
        self.assertEqual(stripped, "public void hello() {\n    System.out.println(1);\n}")

        # Conversational text surrounding JSON
        noisy_json = """Here is the restored output:
```json
{
  "renamed_variables": {"var1": "totalSum"},
  "summary": "Computes sum.",
  "javadoc": "/** Computes sum */",
  "reconstructed_code": "```java\\npublic int sum() { return totalSum; }\\n```"
}
```
Hope this helps!"""
        payload = extractJsonPayload(noisy_json)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["renamed_variables"]["var1"], "totalSum")

        # 2. Mocked Ollama response with internal code fences stripped
        mock_response = {
            "response": json.dumps({
                "renamed_variables": {"param0": "limit"},
                "javadoc": "/** Loops up to limit */",
                "reconstructed_code": "```java\npublic static void loop(int limit) {\n}\n```",
            })
        }
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(mock_response).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            restorer = SemanticRestorer(model="test", no_llm=False)
            dummy_m = MethodInfo("sumUpTo", "(I)V", 0x0009, b"\xb1", True, ["int"], "void")
            dummy_c = ClassInfo("LoopClass", "java/lang/Object", [], 61, 0, {}, {"sumUpTo": dummy_m})
            res = restorer.restoreMethod(dummy_c, "sumUpTo", "public static void sumUpTo(int param0) {}")

            self.assertEqual(res.mode, "ollama")
            self.assertNotIn("```", res.reconstructed_code, "Markdown fences must be stripped from reconstructed Java code")
            self.assertIn("public static void sumUpTo(int limit)", res.reconstructed_code)

        # 3. Connection and Timeout Resilience: Ollama offline / URLError
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            restorer_offline = SemanticRestorer(model="test", no_llm=False)
            res_fallback = restorer_offline.restoreMethod(dummy_c, "sumUpTo", "public static void sumUpTo(int param0) {}")
            self.assertEqual(res_fallback.mode, "offline_heuristic")
            self.assertIn("limit", res_fallback.renamed_variables.values())

        # Socket Timeout resilience
        with patch("urllib.request.urlopen", side_effect=TimeoutError("Request timed out")):
            restorer_timeout = SemanticRestorer(model="test", no_llm=False)
            res_timeout = restorer_timeout.restoreMethod(dummy_c, "sumUpTo", "public static void sumUpTo(int param0) {}")
            self.assertEqual(res_timeout.mode, "offline_heuristic")


if __name__ == "__main__":
    unittest.main()
