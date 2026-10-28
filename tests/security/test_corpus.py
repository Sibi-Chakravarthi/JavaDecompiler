"""
test_corpus.py — Unit tests verifying the synthetic security test corpus and manifest.
"""

import json
import unittest
from pathlib import Path

from javadecompiler.security.jar_checks import safe_parse_class_bytes
from javadecompiler.security.scanner import SecurityScanner

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CORPUS_DIR = BASE_DIR / "tests" / "security_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
COMPILED_DIR = CORPUS_DIR / "compiled"


class TestSecurityCorpus(unittest.TestCase):

    def test_manifest_structure(self):
        self.assertTrue(MANIFEST_PATH.exists(), "manifest.json should exist")
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        classes = manifest.get("classes", {})
        self.assertGreaterEqual(len(classes), 42, "Should contain at least 42 test classes")

        benign = [k for k in classes if k.startswith("benign/")]
        vuln = [k for k in classes if k.startswith("vulnerable/")]
        susp = [k for k in classes if k.startswith("suspicious/")]

        self.assertGreaterEqual(len(benign), 15)
        self.assertGreaterEqual(len(vuln), 15)
        self.assertGreaterEqual(len(susp), 12)

    def test_compiled_classes_loadable(self):
        self.assertTrue(COMPILED_DIR.exists(), "Compiled corpus directory should exist")
        class_files = list(COMPILED_DIR.rglob("*.class"))
        self.assertGreaterEqual(len(class_files), 42)

        for cf in class_files:
            data = cf.read_bytes()
            c_info, findings = safe_parse_class_bytes(data, cf.name)
            self.assertIsNotNone(c_info, f"Class {cf.name} should parse cleanly")
            self.assertGreaterEqual(c_info.major_version, 52)

    def test_static_scan_on_benign_corpus(self):
        scanner = SecurityScanner(enable_llm=False)
        benign_files = list((COMPILED_DIR / "benign").glob("*.class"))
        self.assertGreaterEqual(len(benign_files), 15)

        for bf in benign_files:
            res = scanner.scan_file(str(bf))
            # No critical or high findings should be present in benign classes (except intentional HarmlessProcess echo)
            if bf.stem != "HarmlessProcess":
                critical_or_high = [f for f in res.allFindings if f.severity in ("critical", "high")]
                self.assertEqual(
                    len(critical_or_high),
                    0,
                    f"Benign class {bf.name} produced unexpected high/critical findings: {critical_or_high}",
                )


if __name__ == "__main__":
    unittest.main()
