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



    def test_sql_query_restoration(self):
        class_path = os.path.join(os.path.dirname(__file__), "security_corpus", "compiled", "vulnerable", "VulnSqlInjection.class")
        if os.path.exists(class_path):
            info = parseClassFile(class_path)
            raw = liftMethod(info, "queryUser")
            restorer = SemanticRestorer(no_llm=True)
            res = restorer.restoreMethod(info, "queryUser", raw)

            self.assertEqual(res.mode, "offline_heuristic")
            self.assertIn("connection", res.renamed_variables.values())
            self.assertIn("userId", res.renamed_variables.values())
            self.assertIn("statement", res.renamed_variables.values())
            self.assertIn("sqlQuery", res.renamed_variables.values())
            self.assertIn("resultSet", res.renamed_variables.values())
            self.assertNotIn("var3", res.reconstructed_code)
            self.assertNotIn("var4", res.reconstructed_code)
            self.assertNotIn("var5", res.reconstructed_code)

    def test_path_traversal_restoration(self):
        class_path = os.path.join(os.path.dirname(__file__), "security_corpus", "compiled", "vulnerable", "VulnPathTraversal.class")
        if os.path.exists(class_path):
            info = parseClassFile(class_path)
            raw = liftMethod(info, "extractFile")
            restorer = SemanticRestorer(no_llm=True)
            res = restorer.restoreMethod(info, "extractFile", raw)

            self.assertEqual(res.mode, "offline_heuristic")
            self.assertIn("destDir", res.renamed_variables.values())
            self.assertIn("fileName", res.renamed_variables.values())
            self.assertIn("data", res.renamed_variables.values())
            self.assertIn("targetFile", res.renamed_variables.values())
            self.assertIn("fileOutStream", res.renamed_variables.values())
            self.assertNotIn("var4", res.reconstructed_code)
            self.assertNotIn("var5", res.reconstructed_code)

    def test_ollama_partial_renaming_cleanup(self):
        """Tests that when an AI model leaves generic placeholders (var3, var4) in reconstructed_code,
        the restorer automatically cleans them up with semantic names."""
        class_path = os.path.join(os.path.dirname(__file__), "security_corpus", "compiled", "vulnerable", "VulnSqlInjection.class")
        if not os.path.exists(class_path):
            return
        info = parseClassFile(class_path)
        raw = liftMethod(info, "queryUser")

        mock_llm_response = {
            "response": json.dumps({
                "renamed_variables": {
                    "param0": "dbConn",
                    "param1": "userAcc"
                },
                "summary": "Executes SQL query.",
                "javadoc": "/** Query user. */",
                "reconstructed_code": "/** Query user. */\npublic void queryUser(Connection dbConn, String userAcc) {\n    var3 = dbConn.createStatement();\n    var4 = new StringBuilder().append(\"SELECT * FROM accounts WHERE id = '\").append(userAcc).append(\"'\").toString();\n    var5 = var3.executeQuery(var4);\n}"
            })
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(mock_llm_response).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            restorer = SemanticRestorer(model="test-model", no_llm=False)
            res = restorer.restoreMethod(info, "queryUser", raw)

            self.assertEqual(res.mode, "ollama")
            # Model renamed these:
            self.assertEqual(res.renamed_variables["param0"], "dbConn")
            self.assertEqual(res.renamed_variables["param1"], "userAcc")
            # Restorer automatically cleaned up the AI's leftover generic variables!
            self.assertIn("statement", res.renamed_variables.values())
            self.assertIn("sqlQuery", res.renamed_variables.values())
            self.assertIn("resultSet", res.renamed_variables.values())
            self.assertNotIn("var3", res.reconstructed_code)
            self.assertNotIn("var4", res.reconstructed_code)
            self.assertNotIn("var5", res.reconstructed_code)


if __name__ == "__main__":
    unittest.main()
