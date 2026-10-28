"""
Unit tests for Phase 2: disassembler.py
"""

import os
import unittest
from javadecompiler.class_parser import parseClassFile
from javadecompiler.disassembler import disassembleMethod, jvmOpcodes

TEST_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "javadecompiler", "Java_Test_Files")


class TestDisassembler(unittest.TestCase):
    def test_opcodes_table(self):
        self.assertIn(0x00, jvmOpcodes)
        self.assertEqual(jvmOpcodes[0x00], ("nop", 0))
        self.assertEqual(jvmOpcodes[0x10], ("bipush", 1))
        self.assertEqual(jvmOpcodes[0x60], ("iadd", 0))
        self.assertEqual(jvmOpcodes[0xb8], ("invokestatic", 2))

    def test_disassemble_method(self):
        class_path = os.path.join(TEST_DIR, "EngineMath.class")
        info = parseClassFile(class_path)
        m = info.methods["calculateHealth"]

        instructions = disassembleMethod("calculateHealth", m.bytecode)
        self.assertGreater(len(instructions), 5)

        mnemonics = [instr["mnemonic"] for instr in instructions]
        self.assertIn("iload_0", mnemonics)
        self.assertIn("iload_1", mnemonics)
        self.assertIn("isub", mnemonics)
        self.assertIn("ireturn", mnemonics)

    def test_unknown_opcode_error(self):
        bad_bytes = bytes([0xff])
        with self.assertRaises(ValueError):
            disassembleMethod("testBad", bad_bytes)


if __name__ == "__main__":
    unittest.main()
