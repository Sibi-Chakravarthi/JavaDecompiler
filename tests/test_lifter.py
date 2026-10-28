"""
Unit tests for Phase 2: lifter.py
"""

import os
import unittest
from javadecompiler.class_parser import parseClassFile
from javadecompiler.lifter import liftMethod, invertCondition

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


if __name__ == "__main__":
    unittest.main()
