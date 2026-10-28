"""
End-to-End tests for CLI & Pipeline: cli.py
"""

import os
import tempfile
import unittest
from javadecompiler.cli import run_pipeline

TEST_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "javadecompiler", "Java_Test_Files")


class TestCLI(unittest.TestCase):
    def test_pipeline_single_class(self):
        class_path = os.path.join(TEST_DIR, "EngineMath.class")
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp_html:
            html_path = tmp_html.name

        try:
            ret = run_pipeline(
                input_path=class_path,
                no_llm=True,
                output_html=html_path,
            )
            self.assertEqual(ret, 0)
            self.assertTrue(os.path.exists(html_path))
            self.assertGreater(os.path.getsize(html_path), 1000)
        finally:
            if os.path.exists(html_path):
                os.remove(html_path)

    def test_pipeline_jar_archive(self):
        jar_path = os.path.join(os.path.dirname(__file__), "..", "sample_library.jar")
        if not os.path.exists(jar_path):
            self.skipTest("sample_library.jar not found")

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp_html:
            html_path = tmp_html.name
        tmp_dir = tempfile.mkdtemp(prefix="neurodecomp_test_")

        try:
            ret = run_pipeline(
                input_path=jar_path,
                no_llm=True,
                output_html=html_path,
                output_dir=tmp_dir,
            )
            self.assertEqual(ret, 0)
            self.assertTrue(os.path.exists(html_path))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "EngineMath.java")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "LoopTest.java")))
        finally:
            if os.path.exists(html_path):
                os.remove(html_path)
            import shutil
            if os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir)


if __name__ == "__main__":
    unittest.main()
