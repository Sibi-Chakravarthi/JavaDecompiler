"""
Unit tests for Phase 1: class_parser.py
"""

import os
import unittest
from javadecompiler.class_parser import (
    ClassFileReader,
    parseClassHeader,
    parseConstantPool,
    parseClassFile,
    parseJarFile,
    parseDescriptor,
)

TEST_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "javadecompiler", "Java_Test_Files")


class TestClassParser(unittest.TestCase):
    def test_descriptor_parsing(self):
        params, ret = parseDescriptor("()V")
        self.assertEqual(params, [])
        self.assertEqual(ret, "void")

        params, ret = parseDescriptor("(II)I")
        self.assertEqual(params, ["int", "int"])
        self.assertEqual(ret, "int")

        params, ret = parseDescriptor("([Ljava/lang/String;)V")
        self.assertEqual(params, ["String[]"])
        self.assertEqual(ret, "void")

        params, ret = parseDescriptor("(Ljava/lang/String;I[B)V")
        self.assertEqual(params, ["String", "int", "byte[]"])
        self.assertEqual(ret, "void")

    def test_parse_class_header_and_pool(self):
        class_path = os.path.join(TEST_DIR, "EngineMath.class")
        self.assertTrue(os.path.exists(class_path))

        reader = ClassFileReader(class_path)
        pool_count = parseClassHeader(reader)
        self.assertGreater(pool_count, 10)

        cp = parseConstantPool(reader, pool_count)
        self.assertIn(1, cp)

    def test_parse_class_file(self):
        class_path = os.path.join(TEST_DIR, "EngineMath.class")
        info = parseClassFile(class_path)

        self.assertEqual(info.class_name, "EngineMath")
        self.assertIn("calculateHealth", info.methods)
        self.assertIn("main", info.methods)
        self.assertIn("<init>", info.methods)

        m = info.methods["calculateHealth"]
        self.assertTrue(m.is_static)
        self.assertEqual(m.param_types, ["int", "int"])
        self.assertEqual(m.return_type, "int")
        self.assertGreater(len(m.bytecode), 0)

    def test_parse_jar_file(self):
        jar_path = os.path.join(os.path.dirname(__file__), "..", "sample_library.jar")
        if os.path.exists(jar_path):
            classes = parseJarFile(jar_path)
            self.assertGreaterEqual(len(classes), 3)
            names = [c.class_name for c in classes]
            self.assertIn("EngineMath", names)
            self.assertIn("LoopTest", names)


if __name__ == "__main__":
    unittest.main()
