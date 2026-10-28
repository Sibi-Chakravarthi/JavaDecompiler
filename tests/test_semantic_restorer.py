"""
Unit tests for Phase 3: semantic_restorer.py
"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from javadecompiler.class_parser import parseClassFile
from javadecompiler.lifter import liftMethod
from javadecompiler.semantic_restorer import (
    SemanticRestorer,
    extractOsContext,
)

TEST_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "javadecompiler", "Java_Test_Files")


class TestSemanticRestorer(unittest.TestCase):
    def test_os_context_extraction_clean(self):
        class_path = os.path.join(TEST_DIR, "EngineMath.class")
        info = parseClassFile(class_path)
        ctx = extractOsContext(info, "calculateHealth")
        self.assertEqual(len(ctx.categories), 0)

    def test_os_context_extraction_network_crypto(self):
        class_path = os.path.join(TEST_DIR, "NetworkCryptoService.class")
        if os.path.exists(class_path):
            info = parseClassFile(class_path)
            ctx = extractOsContext(info, "sendHash")
            self.assertIn("Network / Sockets", ctx.categories)
            self.assertIn("Cryptography & Hashing", ctx.categories)
            self.assertIn("SHA-256", ctx.string_literals)

    def test_offline_heuristic_fallback(self):
        class_path = os.path.join(TEST_DIR, "EngineMath.class")
        info = parseClassFile(class_path)
        raw = liftMethod(info, "calculateHealth")

        restorer = SemanticRestorer(no_llm=True)
        res = restorer.restoreMethod(info, "calculateHealth", raw)

        self.assertEqual(res.mode, "offline_heuristic")
        self.assertIn("baseHealth", res.renamed_variables.values())
        self.assertIn("damage", res.renamed_variables.values())
        self.assertIn("currentHealth", res.renamed_variables.values())
        self.assertIn("/**", res.javadoc)
        self.assertIn("public static int calculateHealth(int baseHealth, int damage)", res.reconstructed_code)

    def test_ollama_mocked_query(self):
        class_path = os.path.join(TEST_DIR, "EngineMath.class")
        info = parseClassFile(class_path)
        raw = liftMethod(info, "calculateHealth")

        mock_llm_response = {
            "response": json.dumps({
                "renamed_variables": {
                    "param0": "initialHp",
                    "param1": "damageTaken",
                    "var2": "finalHp"
                },
                "summary": "Calculates health points after combat damage.",
                "javadoc": "/** Calculates health points. */",
                "reconstructed_code": "/** Calculates health points. */\npublic static int calculateHealth(int initialHp, int damageTaken) {\n    finalHp = initialHp - damageTaken;\n    return finalHp;\n}"
            })
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(mock_llm_response).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            restorer = SemanticRestorer(model="test-model", no_llm=False)
            res = restorer.restoreMethod(info, "calculateHealth", raw)

            self.assertEqual(res.mode, "ollama")
            self.assertEqual(res.renamed_variables["param0"], "initialHp")
            self.assertIn("initialHp", res.reconstructed_code)


if __name__ == "__main__":
    unittest.main()
