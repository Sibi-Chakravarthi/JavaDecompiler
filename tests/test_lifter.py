"""
Unit tests for Phase 2: lifter.py
"""

import os
import time
import unittest
from javadecompiler.class_parser import parseClassFile
from javadecompiler.lifter import liftMethod, invertCondition
from javadecompiler.cfg_builder import BasicBlock
from javadecompiler.structurer import structureMethod, findMergePoint

TEST_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "javadecompiler", "Java_Test_Files")


class TestLifter(unittest.TestCase):
    def test_invert_condition(self):
        self.assertEqual(invertCondition("a == 0"), "a != 0")
        self.assertEqual(invertCondition("a != 0"), "a == 0")
        self.assertEqual(invertCondition("i >= limit"), "i < limit")
        self.assertEqual(invertCondition("i < limit"), "i >= limit")
        self.assertEqual(invertCondition("ref == null"), "ref != null")

    def test_lift_engine_math(self):
        class_path = os.path.join(TEST_DIR, "EngineMath.class")
        info = parseClassFile(class_path)
        code = liftMethod(info, "calculateHealth")

        self.assertIn("public static int calculateHealth(int param0, int param1)", code)
        self.assertIn("param0 - param1", code)
        self.assertIn("if (", code)
        self.assertIn("return ", code)

    def test_lift_loop_test(self):
        class_path = os.path.join(TEST_DIR, "LoopTest.class")
        info = parseClassFile(class_path)
        code = liftMethod(info, "sumUpTo")

        self.assertIn("public static int sumUpTo(int param0)", code)
        self.assertIn("while (var2 < param0)", code)
        self.assertIn("var1 = var1 + var2;", code)
        self.assertIn("return var1;", code)

    def test_lift_combined_test(self):
        class_path = os.path.join(TEST_DIR, "CombinedTest.class")
        info = parseClassFile(class_path)
        code = liftMethod(info, "sumEvens")

        self.assertIn("while (var2 < param0)", code)
        self.assertIn("if (var2 % 2 == 0)", code)

    def test_find_merge_point_excludes_backward_offsets(self):
        # Header 10 -> Block 20 -> Block 30 (branches: then 40, else 50)
        # Block 40 and 50 both jump back to Header 10.
        # findMergePoint for 40 and 50 must NOT pick 10!
        blocks = {
            10: BasicBlock(10, [{'offset': 10, 'mnemonic': 'iload_0', 'operands': []}], predecessors={40, 50}, successors={20}),
            20: BasicBlock(20, [{'offset': 20, 'mnemonic': 'nop', 'operands': []}], predecessors={10}, successors={30}),
            30: BasicBlock(30, [{'offset': 30, 'mnemonic': 'ifeq', 'operands': [0, 20]}], predecessors={20}, successors={40, 50}),
            40: BasicBlock(40, [{'offset': 40, 'mnemonic': 'goto', 'operands': [0, -30]}], predecessors={30}, successors={10}),
            50: BasicBlock(50, [{'offset': 50, 'mnemonic': 'goto', 'operands': [0, -40]}], predecessors={30}, successors={10}),
        }
        back_edges = {(40, 10), (50, 10)}
        m = findMergePoint(blocks, 40, 50, branchOffset=30, backEdges=back_edges)
        # 10 is <= branchOffset 30 and in back_edges, so it should be rejected
        self.assertIsNone(m)

    def test_complex_cfg_bounded_structuring(self):
        # Build a synthetic diamond chain with early return forks
        blocks = {}
        for i in range(0, 100, 10):
            # Block i branches to i+2 (early return) or i+10 (continuation)
            blocks[i] = BasicBlock(
                i,
                [{'offset': i, 'mnemonic': 'ifeq', 'operands': [0, 2]}],
                predecessors={i - 10} if i > 0 else set(),
                successors={i + 2, i + 10} if i < 90 else {i + 10},
            )
            if i < 90:
                # Early return block
                blocks[i + 2] = BasicBlock(
                    i + 2,
                    [{'offset': i + 2, 'mnemonic': 'return', 'operands': []}],
                    predecessors={i},
                    successors=set(),
                )
        # Final block 100
        blocks[100] = BasicBlock(100, [{'offset': 100, 'mnemonic': 'return', 'operands': []}], predecessors={90}, successors=set())

        t0 = time.time()
        tree = structureMethod(blocks)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 0.5, "CFG structuring took too long (possible exponential blowup)")
        self.assertIsNotNone(tree)


if __name__ == "__main__":
    unittest.main()
