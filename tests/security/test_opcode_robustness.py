"""
test_opcode_robustness.py — Unit tests for Milestone 12: tableswitch, lookupswitch,
invokedynamic string concat resolution, and scanner fallback.
"""

from __future__ import annotations

import struct
import unittest

from javadecompiler.cfg_builder import buildControlFlowGraph
from javadecompiler.class_parser import ClassInfo, MethodInfo
from javadecompiler.disassembler import disassembleMethod
from javadecompiler.security.behavior import BehaviorDetector
from javadecompiler.security.models import Verdict
from javadecompiler.security.rules.helpers import get_call_info
from javadecompiler.security.scanner import SecurityScanner


class TestOpcodeRobustness(unittest.TestCase):
    def test_disassemble_tableswitch(self):
        # Offset 0: tableswitch
        # Padding: (3 - (0 % 4)) = 3 bytes -> offsets 1, 2, 3
        # Offset 4: default = 20 (big-endian s4)
        # Offset 8: low = 0 (big-endian s4)
        # Offset 12: high = 2 (big-endian s4) -> count = 3
        # Offsets 16, 20, 24: target1=10, target2=14, target3=18
        # Offset 28: return (0xb1)
        bytecode = bytearray()
        bytecode.append(0xaa)  # tableswitch
        bytecode.extend([0x00, 0x00, 0x00])  # 3 padding bytes to offset 4
        bytecode.extend(struct.pack(">i", 20))  # default offset
        bytecode.extend(struct.pack(">i", 0))   # low
        bytecode.extend(struct.pack(">i", 2))   # high
        bytecode.extend(struct.pack(">i", 10))  # target 0
        bytecode.extend(struct.pack(">i", 14))  # target 1
        bytecode.extend(struct.pack(">i", 18))  # target 2
        # padding up to 28, then return
        bytecode.append(0xb1)  # return at offset 28

        instructions = disassembleMethod("testTableSwitch", bytes(bytecode))
        self.assertEqual(len(instructions), 2)
        switch_instr = instructions[0]
        self.assertEqual(switch_instr["mnemonic"], "tableswitch")
        self.assertEqual(switch_instr["offset"], 0)
        self.assertEqual(switch_instr["defaultTarget"], 20)
        self.assertEqual(switch_instr["low"], 0)
        self.assertEqual(switch_instr["high"], 2)
        self.assertEqual(switch_instr["targets"], [10, 14, 18])

    def test_disassemble_lookupswitch(self):
        # Offset 0: bipush 1 (2 bytes: 0x10, 0x01) -> offset 2
        # Offset 2: lookupswitch (0xab)
        # Padding: (3 - (2 % 4)) = 1 byte -> offset 3
        # Offset 4: default = 30
        # Offset 8: npairs = 2
        # Offset 12: match=1, offset=15
        # Offset 20: match=2, offset=25
        bytecode = bytearray([0x10, 0x01, 0xab, 0x00])
        bytecode.extend(struct.pack(">i", 30))  # default
        bytecode.extend(struct.pack(">i", 2))   # npairs
        bytecode.extend(struct.pack(">i", 1))   # match 1
        bytecode.extend(struct.pack(">i", 15))  # target 1
        bytecode.extend(struct.pack(">i", 2))   # match 2
        bytecode.extend(struct.pack(">i", 25))  # target 2

        instructions = disassembleMethod("testLookupSwitch", bytes(bytecode))
        self.assertEqual(len(instructions), 2)
        switch_instr = instructions[1]
        self.assertEqual(switch_instr["mnemonic"], "lookupswitch")
        self.assertEqual(switch_instr["offset"], 2)
        self.assertEqual(switch_instr["defaultTarget"], 32)
        self.assertEqual(switch_instr["npairs"], 2)
        self.assertEqual(switch_instr["targets"], [17, 27])

    def test_cfg_builder_with_tableswitch(self):
        # Construct synthetic instructions:
        # 0: iconst_1
        # 1: tableswitch (default: 10, targets: [8])
        # 8: iconst_2
        # 9: ireturn
        # 10: iconst_3
        # 11: ireturn
        instructions = [
            {"offset": 0, "mnemonic": "iconst_1", "operands": []},
            {
                "offset": 1,
                "mnemonic": "tableswitch",
                "operands": [],
                "defaultTarget": 10,
                "targets": [8],
            },
            {"offset": 8, "mnemonic": "iconst_2", "operands": []},
            {"offset": 9, "mnemonic": "ireturn", "operands": []},
            {"offset": 10, "mnemonic": "iconst_3", "operands": []},
            {"offset": 11, "mnemonic": "ireturn", "operands": []},
        ]
        cfg = buildControlFlowGraph(instructions)
        self.assertIn(0, cfg)
        self.assertIn(8, cfg)
        self.assertIn(10, cfg)
        block0 = cfg[0]
        self.assertIn(8, block0.successors)
        self.assertIn(10, block0.successors)

    def test_invokedynamic_string_concat_helpers(self):
        cp = {
            1: {
                "type": "InvokeDynamic",
                "bootstrapMethodAttrIndex": 0,
                "nameAndTypeIndex": 2,
            },
            2: {
                "type": "NameAndType",
                "nameIndex": 3,
                "descriptorIndex": 4,
            },
            3: {"type": "Utf8", "value": "makeConcatWithConstants"},
            4: {"type": "Utf8", "value": "(Ljava/lang/String;I)Ljava/lang/String;"},
        }
        instr = {"offset": 5, "mnemonic": "invokedynamic", "operands": [0, 1, 0, 0]}
        call = get_call_info(cp, instr)
        self.assertIsNotNone(call)
        self.assertEqual(call["kind"], "InvokeDynamic")
        self.assertEqual(call["class"], "java/lang/invoke/StringConcatFactory")
        self.assertEqual(call["name"], "makeConcatWithConstants")
        self.assertEqual(call["descriptor"], "(Ljava/lang/String;I)Ljava/lang/String;")

    def test_taint_sink_chain_with_invokedynamic(self):
        cp = {
            1: {
                "type": "InvokeDynamic",
                "nameAndTypeIndex": 2,
            },
            2: {
                "type": "NameAndType",
                "nameIndex": 3,
                "descriptorIndex": 4,
            },
            3: {"type": "Utf8", "value": "makeConcatWithConstants"},
            4: {"type": "Utf8", "value": "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"},
            5: {
                "type": "Class",
                "nameIndex": 6,
            },
            6: {"type": "Utf8", "value": "java/sql/Statement"},
            7: {
                "type": "NameAndType",
                "nameIndex": 8,
                "descriptorIndex": 9,
            },
            8: {"type": "Utf8", "value": "executeQuery"},
            9: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/sql/ResultSet;"},
            10: {
                "type": "Ref",
                "refKind": "InterfaceMethodRef",
                "classIndex": 5,
                "nameAndTypeIndex": 7,
            },
        }
        m_info = MethodInfo(
            access_flags=0x0009,
            name="queryUser",
            descriptor="(Ljava/lang/String;)V",
            param_types=["String"],
            bytecode=b"",
        )
        cinfo = ClassInfo(
            class_name="DynamicTaintDemo",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=61,
            minor_version=0,
            constant_pool=cp,
            methods={"queryUser": m_info},
        )
        instructions = [
            {"offset": 0, "mnemonic": "aload_0", "operands": []},
            {"offset": 1, "mnemonic": "invokedynamic", "operands": [0, 1, 0, 0]},
            {"offset": 5, "mnemonic": "invokeinterface", "operands": [0, 10, 2, 0]},
            {"offset": 10, "mnemonic": "return", "operands": []},
        ]
        detector = BehaviorDetector()
        findings = detector.detect_chains(
            class_info=cinfo,
            raw_methods={"queryUser": "stmt.executeQuery(cmd);"},
            instructions_by_method={"queryUser": instructions},
        )
        taint_findings = [f for f in findings if f.ruleId == "JD-CHAIN-TAINT-SINK"]
        self.assertEqual(len(taint_findings), 1)
        f = taint_findings[0]
        self.assertEqual(f.ruleId, "JD-CHAIN-TAINT-SINK")
        self.assertTrue(any("Dynamic string concatenation" in ev.text for ev in f.evidence))

    def test_scanner_fallback_on_unrecognized_opcode(self):
        bad_method_bytes = bytes([0xff, 0xff])  # 0xff is not in jvmOpcodes
        cinfo = ClassInfo(
            class_name="CorruptBytecodeSample",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=52,
            minor_version=0,
            constant_pool={},
            methods={
                "badMethod": MethodInfo(
                    access_flags=0x0001,
                    name="badMethod",
                    descriptor="()V",
                    bytecode=bad_method_bytes,
                )
            },
        )
        scanner = SecurityScanner()
        res = scanner.scan_class(cinfo)
        # Should NOT crash, analysis coverage for method should be partial
        self.assertIn("CorruptBytecodeSample", res.classes)
        c_analysis = res.classes["CorruptBytecodeSample"]
        self.assertIn("badMethod", c_analysis.methods)
        m_analysis = c_analysis.methods["badMethod"]
        self.assertEqual(m_analysis.analysisCoverage, "partial")
        self.assertIn("Disassembler failure", m_analysis.partialReason or "")
        self.assertGreater(res.coverageStats.partialCoverageMethods, 0)
        # Definition of done: never return CLEAN if partialCoverageMethods > 0
        self.assertEqual(res.overallVerdict, Verdict.REVIEW_RECOMMENDED.value)


if __name__ == "__main__":
    unittest.main()
