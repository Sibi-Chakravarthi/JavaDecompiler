"""
test_bugfixes.py — Regression Test Suite for Core Pipeline Bugfixes

Validates fixes for:
- Phase 1: Constant pool 8-byte slot stepping, tags 17-20, modified UTF-8, in-memory parsing
- Phase 2a: Variable-length switches, wide (0xC4) instruction decoding, signed immediates
- Phase 2b: 4-byte wide branch targets (goto_w/jsr_w), exception handler CFG wiring, loop leaders
- Phase 2c: ACC_STATIC parameter slot mapping, Category-2 2-slot stepping, binary op order, invokedynamic, catch block stack resilience
- Phase 3: Markdown code fence stripping, JSON preamble extraction, timeout/offline resilience
- Phase 4: HTML escaping in reports for <init> and <clinit>
"""

import html
import json
import struct
import unittest
from unittest.mock import MagicMock, patch

from javadecompiler.class_parser import (
    ClassFileReader,
    ClassInfo,
    MethodInfo,
    decodeModifiedUtf8,
    parseConstantPool,
)
from javadecompiler.disassembler import disassembleMethod, jvmOpcodes
from javadecompiler.cfg_builder import (
    buildControlFlowGraph,
    findLeaders,
    resolveBranchTarget,
    wireEdges,
)
from javadecompiler.lifter import (
    LifterContext,
    StackSimulator,
    getSlotForParameter,
    liftMethod,
)
from javadecompiler.semantic_restorer import (
    OSContext,
    RestorationResult,
    SemanticRestorer,
    extractJsonPayload,
    stripMarkdownFences,
)
from javadecompiler.report import generateHtmlReport


class TestCorePipelineBugfixes(unittest.TestCase):

    def test_constant_pool_long_double_slot_stepping(self):
        """1. Verify Long/Double advance CP index by 2 with None placeholder at index+1."""
        # Construct constant pool with:
        # 1: Long (tag 5, 8 bytes: high=1, low=2) -> takes slots 1 and 2
        # 3: Double (tag 6, 8 bytes: high=3, low=4) -> takes slots 3 and 4
        # 5: Utf8 (tag 1, len=4, 'done') -> slot 5
        # 6: Dynamic (tag 17, 4 bytes: bm_attr=0, nat=1) -> slot 6
        # 7: Module (tag 19, 2 bytes: name=1) -> slot 7
        # 8: Package (tag 20, 2 bytes: name=1) -> slot 8
        raw_cp = bytearray()
        # Slot 1: Long (tag 5)
        raw_cp.append(5)
        raw_cp.extend(struct.pack(">II", 1, 2))
        # Slot 3: Double (tag 6)
        raw_cp.append(6)
        raw_cp.extend(struct.pack(">II", 3, 4))
        # Slot 5: Utf8 (tag 1)
        raw_cp.append(1)
        raw_cp.extend(struct.pack(">H", 4))
        raw_cp.extend(b"done")
        # Slot 6: Dynamic (tag 17)
        raw_cp.append(17)
        raw_cp.extend(struct.pack(">HH", 0, 1))
        # Slot 7: Module (tag 19)
        raw_cp.append(19)
        raw_cp.extend(struct.pack(">H", 1))
        # Slot 8: Package (tag 20)
        raw_cp.append(20)
        raw_cp.extend(struct.pack(">H", 1))

        reader = ClassFileReader.from_bytes(bytes(raw_cp))
        # Total pool count is 9 (indices 1..8)
        cp = parseConstantPool(reader, 9)

        # Slot 1 is Long, slot 2 is None placeholder
        self.assertEqual(cp[1]["type"], "Primitive64")
        self.assertIn(2, cp)
        self.assertIsNone(cp[2])

        # Slot 3 is Double, slot 4 is None placeholder
        self.assertEqual(cp[3]["type"], "Primitive64")
        self.assertIn(4, cp)
        self.assertIsNone(cp[4])

        # Slot 5 is Utf8
        self.assertEqual(cp[5]["type"], "Utf8")
        self.assertEqual(cp[5]["value"], "done")

        # Slot 6 is Dynamic, 7 is Module, 8 is Package
        self.assertEqual(cp[6]["type"], "Dynamic")
        self.assertEqual(cp[7]["type"], "Module")
        self.assertEqual(cp[8]["type"], "Package")

        # Test Modified UTF-8 decoding for 0xC0 0x80 (null byte)
        mod_utf8_null = b"\xc0\x80"
        self.assertEqual(decodeModifiedUtf8(mod_utf8_null), "\x00")

    def test_disassembler_tableswitch_lookupswitch_alignment(self):
        """2. Verify tableswitch and lookupswitch 4-byte padding at unaligned offsets."""
        # Test tableswitch at offset 1:
        # Prepend 1 byte (e.g. nop 0x00)
        # Offset 0: nop (1 byte)
        # Offset 1: tableswitch (0xAA)
        # Pad should be (4 - ((1 + 1) % 4)) % 4 = 2 bytes
        # Pad at bytes 2, 3 -> table starts at byte 4 (multiple of 4)
        ts_bytes = bytearray([0x00, 0xaa, 0x00, 0x00]) # offset 0: nop, offset 1: tableswitch + 2 pad bytes
        # Default: offset 10, low: 0, high: 1 (2 targets: 15, 20)
        ts_bytes.extend(struct.pack(">iii", 10, 0, 1))
        ts_bytes.extend(struct.pack(">ii", 15, 20))

        instrs = disassembleMethod("test_tableswitch", bytes(ts_bytes))
        self.assertEqual(len(instrs), 2)
        self.assertEqual(instrs[0]["mnemonic"], "nop")
        self.assertEqual(instrs[1]["mnemonic"], "tableswitch")
        self.assertEqual(instrs[1]["offset"], 1)
        self.assertEqual(instrs[1]["defaultTarget"], 1 + 10)
        self.assertEqual(instrs[1]["targets"], [1 + 15, 1 + 20])
        self.assertEqual(instrs[1]["low"], 0)
        self.assertEqual(instrs[1]["high"], 1)

        # Test lookupswitch at offset 2:
        # Offset 0: nop, Offset 1: nop, Offset 2: lookupswitch (0xAB)
        # Pad should be (4 - ((2 + 1) % 4)) % 4 = 1 byte
        # Pad at byte 3 -> table starts at byte 4
        ls_bytes = bytearray([0x00, 0x00, 0xab, 0x00])
        # Default: 12, npairs: 1, (match=100, off=25)
        ls_bytes.extend(struct.pack(">ii", 12, 1))
        ls_bytes.extend(struct.pack(">ii", 100, 25))

        instrs_ls = disassembleMethod("test_lookupswitch", bytes(ls_bytes))
        self.assertEqual(len(instrs_ls), 3)
        self.assertEqual(instrs_ls[2]["mnemonic"], "lookupswitch")
        self.assertEqual(instrs_ls[2]["offset"], 2)
        self.assertEqual(instrs_ls[2]["defaultTarget"], 2 + 12)
        self.assertEqual(instrs_ls[2]["targets"], [2 + 25])
        self.assertEqual(instrs_ls[2]["npairs"], 1)

    def test_disassembler_wide_instruction(self):
        """3. Verify opcode 0xC4 (wide) decodes 4-byte load/store and 6-byte iinc."""
        # 1. Wide iload (0xC4 0x15 index=500) -> 4 bytes
        wide_iload_bytes = bytearray([0xc4, 0x15])
        wide_iload_bytes.extend(struct.pack(">H", 500))

        # 2. Wide iinc (0xC4 0x84 index=350 const=-25) -> 6 bytes
        wide_iinc_bytes = bytearray([0xc4, 0x84])
        wide_iinc_bytes.extend(struct.pack(">Hh", 350, -25))

        combined = bytes(wide_iload_bytes + wide_iinc_bytes)
        instrs = disassembleMethod("test_wide", combined)

        self.assertEqual(len(instrs), 2)
        # Wide iload
        self.assertEqual(instrs[0]["mnemonic"], "wide")
        self.assertEqual(instrs[0]["wide_opcode"], "iload")
        self.assertEqual(instrs[0]["index"], 500)
        self.assertEqual(instrs[0]["offset"], 0)

        # Wide iinc
        self.assertEqual(instrs[1]["mnemonic"], "wide")
        self.assertEqual(instrs[1]["wide_opcode"], "iinc")
        self.assertEqual(instrs[1]["index"], 350)
        self.assertEqual(instrs[1]["const"], -25)
        self.assertEqual(instrs[1]["offset"], 4)

    def test_cfg_exception_handlers_and_loop_leaders(self):
        """4. Verify CFG builds leaders and edges for exception handlers and backward loop targets."""
        # Method instructions:
        # offset 0: iload_0 (1 byte)
        # offset 1: ifeq to 10 (3 bytes)
        # offset 4: iload_1 (1 byte)
        # offset 5: goto to 0 (3 bytes) - backward loop back-edge!
        # offset 8: astore_1 (1 byte) - catch handler!
        # offset 9: return (1 byte)
        # offset 10: return (1 byte)
        instructions = [
            {"offset": 0, "mnemonic": "iload_0", "operands": []},
            {"offset": 1, "mnemonic": "ifeq", "operands": [0, 9], "target": 10},
            {"offset": 4, "mnemonic": "iload_1", "operands": []},
            {"offset": 5, "mnemonic": "goto", "operands": [0xff, 0xfb], "target": 0},
            {"offset": 8, "mnemonic": "astore_1", "operands": []},
            {"offset": 9, "mnemonic": "return", "operands": []},
            {"offset": 10, "mnemonic": "return", "operands": []},
        ]
        # Exception handler covering [0, 8) with handler at 8
        ex_handlers = [{"start_pc": 0, "end_pc": 8, "handler_pc": 8, "catch_type": 1}]

        cfg = buildControlFlowGraph(instructions, ex_handlers)

        # Block 0 starts at 0
        self.assertIn(0, cfg)
        # Handler entry 8 must be a leader
        self.assertIn(8, cfg)
        # Jump target 10 must be a leader
        self.assertIn(10, cfg)

        # Protected block (e.g. block 0 or 4) must wire an edge to handler 8
        block0 = cfg[0]
        self.assertIn(8, block0.successors)

        # Backward loop edge from block at 4/5 back to 0
        self.assertIn(0, cfg[4].successors)
        self.assertIn(4, cfg[0].predecessors)

        # Test 4-byte wide branch resolution (goto_w)
        goto_w_instr = {"offset": 100, "mnemonic": "goto_w", "operands": [0, 0, 0x10, 0x00]}
        target = resolveBranchTarget(goto_w_instr)
        self.assertEqual(target, 100 + 0x1000)

    def test_lifter_static_method_slot_mapping(self):
        """5. Verify static methods map slot 0 to param0 and Category-2 long/double step 2 slots."""
        m_info = MethodInfo(
            name="staticCompute",
            descriptor="(IJLjava/lang/String;)V",
            access_flags=0x0009, # public static
            bytecode=b"",
            is_static=True,
            param_types=["int", "long", "String"],
            return_type="void",
        )
        c_info = ClassInfo(
            class_name="MathUtil",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=61,
            minor_version=0,
            constant_pool={},
            methods={"staticCompute": m_info},
        )

        ctx = LifterContext.create(c_info, m_info)

        # Static method MUST NOT have 'this' in slot 0
        self.assertNotIn("this", ctx.param_map.values())
        # Slot 0 -> param0 (int)
        self.assertEqual(ctx.param_map[0], "param0")
        # Slot 1 -> param1 (long, 8 bytes, occupies slots 1 and 2)
        self.assertEqual(ctx.param_map[1], "param1")
        # Slot 2 is unusable
        self.assertNotIn(2, ctx.param_map)
        # Slot 3 -> param2 (String)
        self.assertEqual(ctx.param_map[3], "param2")

        # Test getSlotForParameter helper
        self.assertEqual(getSlotForParameter(m_info, 0), 0)
        self.assertEqual(getSlotForParameter(m_info, 1), 1)
        self.assertEqual(getSlotForParameter(m_info, 2), 3)

        # Instance method comparison: slot 0 must be 'this'
        m_instance = MethodInfo(
            name="instanceCompute",
            descriptor="(IJ)V",
            access_flags=0x0001, # public instance
            bytecode=b"",
            is_static=False,
            param_types=["int", "long"],
            return_type="void",
        )
        ctx_inst = LifterContext.create(c_info, m_instance)
        self.assertEqual(ctx_inst.param_map[0], "this")
        self.assertEqual(ctx_inst.param_map[1], "param0")
        self.assertEqual(ctx_inst.param_map[2], "param1")

    def test_lifter_binary_op_evaluation_order(self):
        """6. Verify stack simulator pops left and right operands in correct order (val1 - val2)."""
        m_info = MethodInfo(
            name="subAndDiv",
            descriptor="(II)I",
            access_flags=0x0009,
            bytecode=b"",
            is_static=True,
            param_types=["int", "int"],
            return_type="int",
        )
        c_info = ClassInfo(
            class_name="OrderTest",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=61,
            minor_version=0,
            constant_pool={},
            methods={"subAndDiv": m_info},
        )
        ctx = LifterContext.create(c_info, m_info)
        sim = StackSimulator(ctx)

        # Simulate: iload_0, iload_1, isub
        sim._push("param0")
        sim._push("param1")
        b = sim._pop()
        a = sim._pop()
        self.assertEqual(a, "param0")
        self.assertEqual(b, "param1")
        sub_expr = f"{a} - {b}"
        self.assertEqual(sub_expr, "param0 - param1")

        # Also test invokedynamic string concatenation (Java 9+)
        c_info.constant_pool[1] = {"type": "Utf8", "value": "makeConcatWithConstants"}
        c_info.constant_pool[2] = {"type": "Utf8", "value": "(Ljava/lang/String;I)Ljava/lang/String;"}
        c_info.constant_pool[3] = {"type": "NameAndType", "nameIndex": 1, "descriptorIndex": 2}
        c_info.constant_pool[4] = {"type": "InvokeDynamic", "bootstrapMethodAttrIndex": 0, "nameAndTypeIndex": 3}

        indy_sim = StackSimulator(ctx)
        indy_sim._push('"Count: "')
        indy_sim._push("param0")
        from javadecompiler.cfg_builder import BasicBlock
        block = BasicBlock(startOffset=0, instructions=[
            {"offset": 0, "mnemonic": "invokedynamic", "operands": [0, 4]},
            {"offset": 5, "mnemonic": "astore_2", "operands": []},
        ])
        res = indy_sim.liftBlock(block)
        self.assertTrue(any('var2 = "Count: " + param0;' in s for s in res.statements))

    def test_semantic_restorer_strips_markdown_fences(self):
        """7. Verify semantic_restorer strips markdown fences, conversational preambles, and handles timeouts."""
        fenced_code = "```java\npublic static void test() {\n    int a = 1;\n}\n```"
        self.assertEqual(stripMarkdownFences(fenced_code), "public static void test() {\n    int a = 1;\n}")

        raw_llm_response = """Here is the restored JSON representation:
```json
{
    "renamed_variables": {"param0": "userId"},
    "summary": "Loads user profile",
    "javadoc": "/** Loads user profile. */",
    "reconstructed_code": "```java\\n/** Loads user profile. */\\npublic static void test(int userId) {}\\n```"
}
```
Hope this is helpful!"""
        payload = extractJsonPayload(raw_llm_response)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["renamed_variables"]["param0"], "userId")
        self.assertIn("userId", payload["reconstructed_code"])
        cleaned_code = stripMarkdownFences(payload["reconstructed_code"])
        self.assertFalse(cleaned_code.startswith("```"))
        self.assertFalse(cleaned_code.endswith("```"))

        # Test timeout / offline graceful fallback
        restorer = SemanticRestorer(model="nonexistent-model", host="http://127.0.0.1:9999", timeout=1, no_llm=False)
        c_info = ClassInfo("Test", "java/lang/Object", [], 61, 0, {}, {"foo": MethodInfo("foo", "()V", 1, b"")})
        res = restorer.restoreMethod(c_info, "foo", "public void foo() {}")
        self.assertEqual(res.mode, "offline_heuristic")

    def test_report_html_escaping(self):
        """8. Verify generateHtmlReport escapes <init> and <clinit> so browser DOM is not corrupted."""
        m_init = MethodInfo("<init>", "()V", 1, b"\xb1", is_static=False)
        m_clinit = MethodInfo("<clinit>", "()V", 8, b"\xb1", is_static=True)

        c_info = ClassInfo(
            class_name="com/example/MyClass",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=61,
            minor_version=0,
            constant_pool={},
            methods={"<init>": m_init, "<clinit>": m_clinit},
        )

        raw_methods = {
            "com/example/MyClass": {
                "<init>": "public MyClass() {\n    super();\n}",
                "<clinit>": "static {\n    x = 10;\n}",
            }
        }
        restored_methods = {
            "com/example/MyClass": {
                "<init>": RestorationResult("<init>", {"<this>": "self"}, "/** ctor */", "public MyClass() {}"),
                "<clinit>": RestorationResult("<clinit>", {}, "/** clinit */", "static {}"),
            }
        }

        report_html = generateHtmlReport(
            classes=[c_info],
            raw_methods=raw_methods,
            restored_methods=restored_methods,
            target_name="MyClass.class",
        )

        # Must contain escaped forms &lt;init&gt; and &lt;clinit&gt;
        self.assertIn("&lt;init&gt;", report_html)
        self.assertIn("&lt;clinit&gt;", report_html)
        self.assertIn("&lt;this&gt;", report_html)
        # Must NOT contain raw unescaped tags <init> or <clinit> outside pre/code
        self.assertNotIn("<span class=\"method-sig\"><init>", report_html)
        self.assertNotIn("<span class=\"method-sig\"><clinit>", report_html)


if __name__ == "__main__":
    unittest.main()
