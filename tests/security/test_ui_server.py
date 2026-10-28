"""
test_ui_server.py — Unit and integration tests for the Interactive Web UI HTTP server.
"""

import base64
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

from javadecompiler.security.ui.server import UiServerHandler

BASE_DIR = Path(__file__).resolve().parent.parent.parent
COMPILED_DIR = BASE_DIR / "tests" / "security_corpus" / "compiled"


class TestUiServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Pick an arbitrary available port for testing
        cls.server = HTTPServer(("127.0.0.1", 0), UiServerHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_index(self):
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get_content_type(), "text/html")
            body = resp.read().decode("utf-8")
            self.assertIn("NeuroDecomp", body)
            self.assertIn("Drag &amp; Drop", body)

    def test_get_static_assets(self):
        # styles.css
        req_css = urllib.request.Request(f"{self.base_url}/styles.css")
        with urllib.request.urlopen(req_css) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get_content_type(), "text/css")
            self.assertIn(":root", resp.read().decode("utf-8"))

        # app.js
        req_js = urllib.request.Request(f"{self.base_url}/app.js")
        with urllib.request.urlopen(req_js) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get_content_type(), "application/javascript")
            self.assertIn("uploadFile", resp.read().decode("utf-8"))

    def test_get_health(self):
        req = urllib.request.Request(f"{self.base_url}/api/health")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertIn("toolVersion", data)
            self.assertIn("ollamaReachable", data)

    def test_post_scan_valid_class(self):
        # Use compiled MathUtils.class
        sample_path = COMPILED_DIR / "benign" / "MathUtils.class"
        if not sample_path.exists():
            self.skipTest(f"{sample_path} not found")

        file_bytes = sample_path.read_bytes()
        file_b64 = base64.b64encode(file_bytes).decode("ascii")

        payload = {
            "fileName": "MathUtils.class",
            "fileBase64": file_b64,
            "options": {"enableLlm": False},
        }

        req = urllib.request.Request(
            f"{self.base_url}/api/scan",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            result = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(result["success"])
            self.assertEqual(result["targetName"], "MathUtils.class")
            self.assertIn("scanResult", result)
            self.assertIn("decompiled", result)
            self.assertIn("htmlReport", result)
            self.assertIn("sarifReport", result)
            self.assertGreater(result["executionTimeMs"], 0)

            # Check decompiled structure and content
            self.assertIn("benign/MathUtils", result["decompiled"])
            math_utils = result["decompiled"]["benign/MathUtils"]
            self.assertIn("add", math_utils)
            self.assertIn("<init>", math_utils)

            add_data = math_utils["add"]
            self.assertNotIn("// Error lifting method", add_data["liftedSource"])
            self.assertNotIn("// Error disassembling method", add_data["bytecodeText"])
            self.assertIn("return", add_data["liftedSource"].lower())
            self.assertTrue(any(line.startswith("0x") for line in add_data["bytecodeText"].splitlines()))

            init_data = math_utils["<init>"]
            self.assertNotIn("// Error lifting method", init_data["liftedSource"])
            self.assertNotIn("// Error disassembling method", init_data["bytecodeText"])

    def test_post_scan_vulnerable_class(self):
        # Use compiled VulnCommandExec.class
        sample_path = COMPILED_DIR / "vulnerable" / "VulnCommandExec.class"
        if not sample_path.exists():
            self.skipTest(f"{sample_path} not found")

        file_bytes = sample_path.read_bytes()
        file_b64 = base64.b64encode(file_bytes).decode("ascii")

        payload = {
            "fileName": "VulnCommandExec.class",
            "fileBase64": file_b64,
            "options": {"enableLlm": False},
        }

        req = urllib.request.Request(
            f"{self.base_url}/api/scan",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            result = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(result["success"])
            self.assertEqual(result["targetName"], "VulnCommandExec.class")

            # Check decompiled methods
            self.assertIn("vulnerable/VulnCommandExec", result["decompiled"])
            c_decomp = result["decompiled"]["vulnerable/VulnCommandExec"]
            self.assertIn("executeCommand", c_decomp)

            exec_data = c_decomp["executeCommand"]
            self.assertNotIn("// Error lifting method", exec_data["liftedSource"])
            self.assertNotIn("// Error disassembling method", exec_data["bytecodeText"])
            self.assertIn("Runtime", exec_data["liftedSource"])

            # Verify finding line numbers match lines in lifted source
            c_analysis = result["scanResult"]["classes"]["vulnerable/VulnCommandExec"]
            m_analysis = c_analysis["methods"]["executeCommand"]
            self.assertGreater(len(m_analysis["findings"]), 0)
            lifted_line_count = len(exec_data["liftedSource"].splitlines())
            for finding in m_analysis["findings"]:
                line_nos = finding.get("location", {}).get("liftedLineNumbers", [])
                for l_no in line_nos:
                    self.assertGreaterEqual(l_no, 1)
                    self.assertLessEqual(l_no, lifted_line_count)

    def test_post_scan_invalid_empty(self):
        req = urllib.request.Request(
            f"{self.base_url}/api/scan",
            data=b"",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)

    def test_not_found(self):
        req = urllib.request.Request(f"{self.base_url}/nonexistent")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 404)

    def test_get_progress_idle(self):
        req = urllib.request.Request(f"{self.base_url}/api/scan/progress?id=nonexistent_scan")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "idle")
            self.assertEqual(data["current"], 0)
            self.assertEqual(data["total"], 0)

    def test_scan_with_progress(self):
        sample_path = COMPILED_DIR / "benign" / "MathUtils.class"
        if not sample_path.exists():
            self.skipTest(f"{sample_path} not found")

        file_bytes = sample_path.read_bytes()
        file_b64 = base64.b64encode(file_bytes).decode("ascii")

        payload = {
            "fileName": "MathUtils.class",
            "fileBase64": file_b64,
            "scanId": "test_active_scan_123",
            "options": {"enableLlm": False},
        }

        req = urllib.request.Request(
            f"{self.base_url}/api/scan",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            result = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(result["success"])

        # Progress should now reflect complete
        req_prog = urllib.request.Request(f"{self.base_url}/api/scan/progress?id=test_active_scan_123")
        with urllib.request.urlopen(req_prog) as resp:
            self.assertEqual(resp.status, 200)
            prog_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(prog_data["status"], "complete")
            self.assertGreater(prog_data["total"], 0)


if __name__ == "__main__":
    unittest.main()
