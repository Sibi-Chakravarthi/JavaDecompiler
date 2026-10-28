"""
test_scoring_scanner.py — Unit tests for scoring, verdicts, scanner orchestration, JSON & SARIF reports.
"""

import json
import os
import tempfile
import unittest

from javadecompiler.cli import run_pipeline
from javadecompiler.security.models import (
    Category,
    Evidence,
    Finding,
    Kind,
    Location,
    ScanResult,
    Severity,
    Verdict,
)
from javadecompiler.security.reporting.json_out import to_json
from javadecompiler.security.reporting.sarif import to_sarif
from javadecompiler.security.scanner import SecurityScanner
from javadecompiler.security.scoring import calculate_risk_score, determine_verdict


class TestScoringAndScanner(unittest.TestCase):
    def test_risk_scoring_weights_and_diminishing_returns(self):
        f_crit = Finding(
            ruleId="JD-EXEC-001",
            title="Crit",
            description="",
            remediation="",
            kind=Kind.VULNERABILITY.value,
            category=Category.EXECUTION.value,
            severity=Severity.CRITICAL.value,
            location=Location(className="A"),
        )
        # Critical base weight is 40.0
        score1 = calculate_risk_score([f_crit])
        self.assertEqual(score1, 40.0)

        # Second critical in same category gets 60% weight (40 + 24 = 64)
        f_crit2 = Finding(
            ruleId="JD-EXEC-002",
            title="Crit2",
            description="",
            remediation="",
            kind=Kind.VULNERABILITY.value,
            category=Category.EXECUTION.value,
            severity=Severity.CRITICAL.value,
            location=Location(className="A"),
        )
        score2 = calculate_risk_score([f_crit, f_crit2])
        self.assertEqual(score2, 64.0)

    def test_verdict_clean_strict_coverage(self):
        # 0 findings, 0 partial coverage -> CLEAN
        v_clean, reasons = determine_verdict(0.0, [], partial_coverage_count=0)
        self.assertEqual(v_clean, Verdict.CLEAN.value)

        # 0 findings, BUT 1 partial coverage method -> REVIEW_RECOMMENDED (Never CLEAN!)
        v_partial, reasons_p = determine_verdict(0.0, [], partial_coverage_count=1)
        self.assertEqual(v_partial, Verdict.REVIEW_RECOMMENDED.value)
        self.assertTrue(any("partial" in r.lower() for r in reasons_p))

    def test_verdict_malicious_and_suspicious(self):
        f_chain = Finding(
            ruleId="JD-CHAIN-REVSHELL",
            title="Reverse Shell",
            description="",
            remediation="",
            kind=Kind.MALICIOUS_INDICATOR.value,
            category=Category.EXECUTION.value,
            severity=Severity.CRITICAL.value,
            location=Location(className="Backdoor"),
        )
        v, reasons = determine_verdict(75.0, [f_chain])
        self.assertEqual(v, Verdict.LIKELY_MALICIOUS.value)

    def test_json_and_sarif_export(self):
        loc = Location(className="Target", methodName="run", liftedLineNumbers=[10])
        f = Finding(
            ruleId="JD-INJ-001",
            title="SQLi",
            description="SQL injection in query",
            remediation="Use PreparedStatement",
            kind=Kind.VULNERABILITY.value,
            category=Category.INJECTION.value,
            severity=Severity.HIGH.value,
            cwe=["CWE-89"],
            location=loc,
            evidence=[Evidence(id="I:0x04", type="instruction", text="executeQuery", offset=4)],
        )

        scan_result = ScanResult(
            inputSha256="1234567890abcdef",
            inputName="Target.jar",
            timestamp="2026-10-28T12:00:00Z",
            overallVerdict=Verdict.VULNERABLE.value,
            overallRiskScore=25.0,
            jarFindings=[f],
        )

        # Test JSON
        json_str = to_json(scan_result)
        parsed_json = json.loads(json_str)
        self.assertEqual(parsed_json["overallVerdict"], "VULNERABLE")

        # Test SARIF 2.1.0
        sarif_str = to_sarif(scan_result)
        parsed_sarif = json.loads(sarif_str)
        self.assertEqual(parsed_sarif["version"], "2.1.0")
        runs = parsed_sarif.get("runs", [])
        self.assertEqual(len(runs), 1)
        results = runs[0].get("results", [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "JD-INJ-001")
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 10)

    def test_scanner_on_fixture_jar(self):
        jar_path = os.path.join(os.path.dirname(__file__), "..", "..", "sample_library.jar")
        if not os.path.exists(jar_path):
            self.skipTest("sample_library.jar not present")

        scanner = SecurityScanner()
        res = scanner.scan_file(jar_path)
        self.assertIsNotNone(res)
        self.assertIn("NetworkCryptoService", res.classes)
        # NetworkCryptoService connects to Socket, so findings should be present
        self.assertGreaterEqual(len(res.allFindings), 1)
        self.assertGreater(res.overallRiskScore, 0.0)

    def test_cli_fail_on_threshold(self):
        jar_path = os.path.join(os.path.dirname(__file__), "..", "..", "sample_library.jar")
        if not os.path.exists(jar_path):
            self.skipTest("sample_library.jar not present")

        # Fail on medium findings (sample_library.jar has raw Socket creation -> medium)
        ret = run_pipeline(
            input_path=jar_path,
            security_scan=True,
            no_llm=True,
            fail_on="medium",
        )
        self.assertEqual(ret, 2)

        # Fail on critical should NOT trigger on sample_library.jar (which only has medium socket)
        ret_crit = run_pipeline(
            input_path=jar_path,
            security_scan=True,
            no_llm=True,
            fail_on="critical",
        )
        self.assertEqual(ret_crit, 0)


if __name__ == "__main__":
    unittest.main()
