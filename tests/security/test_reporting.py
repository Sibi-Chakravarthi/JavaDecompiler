"""
test_reporting.py — Tests for Phase 4 security reporting components:
- HTML security banner, method cards, and report.py integration
- XSS escaping and sanitization
- JSON output and SARIF 2.1.0 validation
"""

import json
import unittest
from javadecompiler.class_parser import ClassInfo, MethodInfo
from javadecompiler.report import generateHtmlReport
from javadecompiler.security.models import (
    Category,
    ClassAnalysis,
    CoverageStats,
    Evidence,
    Finding,
    Kind,
    Location,
    MethodAnalysis,
    ScanResult,
    Severity,
    Verdict,
)
from javadecompiler.security.reporting.html_section import (
    get_severity_color,
    get_verdict_badge,
    render_method_findings_html,
    render_security_banner,
    render_security_styles,
)
from javadecompiler.security.reporting.json_out import to_json as scan_result_to_json
from javadecompiler.security.reporting.sarif import to_sarif


class TestSecurityReporting(unittest.TestCase):

    def setUp(self):
        self.evidence = Evidence(
            id="I:0x04",
            type="instruction",
            text='ldc "cmd.exe" <script>',
            offset=4,
            line=12,
        )
        self.finding = Finding(
            ruleId="JD-EXEC-001",
            title="Process Execution via <script>alert(1)</script>",
            description='Target calls ProcessBuilder with string "<script>"',
            remediation="Sanitize arguments with html/escape.",
            kind=Kind.VULNERABILITY.value,
            category=Category.EXECUTION.value,
            severity=Severity.HIGH.value,
            confidence=0.95,
            location=Location(
                className="com/example/MaliciousTarget",
                methodName="runPayload",
                descriptor="()V",
                bytecodeOffsets=[4, 10],
                liftedLineNumbers=[12, 14],
            ),
            evidence=[self.evidence],
            cwe=["CWE-78"],
        )

        self.method_analysis = MethodAnalysis(
            methodName="runPayload",
            descriptor="()V",
            findings=[self.finding],
            riskScore=85.0,
            analysisCoverage="full",
        )

        self.class_analysis = ClassAnalysis(
            className="com/example/MaliciousTarget",
            riskScore=85.0,
            methods={"runPayload": self.method_analysis},
        )

        self.scan_result = ScanResult(
            inputName="test_sample.jar",
            classes={"com/example/MaliciousTarget": self.class_analysis},
            overallVerdict=Verdict.SUSPICIOUS.value,
            overallRiskScore=85.0,
            topReasons=["Detected command execution with <script> alert", "Suspicious dropper pattern"],
            jarFindings=[
                Finding(
                    ruleId="JD-JAR-003",
                    title="Embedded Native Binary <evil>",
                    description="Found evil.dll in archive",
                    remediation="Remove embedded dynamic libraries.",
                    kind=Kind.SUSPICIOUS_BEHAVIOR.value,
                    category=Category.ARCHIVE.value,
                    severity=Severity.HIGH.value,
                    location=Location(className="", jarEntryPath="lib/evil.dll"),
                )
            ],
            coverageStats=CoverageStats(totalMethods=1, fullCoverageMethods=1, partialCoverageMethods=0),
        )

    def test_render_security_styles(self):
        css = render_security_styles()
        self.assertIn(".sec-banner", css)
        self.assertIn(".sec-finding-card", css)
        self.assertIn(".sec-score", css)

    def test_verdict_badge(self):
        badge = get_verdict_badge(Verdict.VULNERABLE.value)
        self.assertIn("VULNERABLE", badge)
        self.assertIn("span", badge)

    def test_render_security_banner_xss_safe(self):
        html_out = render_security_banner(self.scan_result)
        # Verify hostile XSS injection in topReasons and jarFindings is escaped
        self.assertNotIn("<script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)
        self.assertNotIn("<evil>", html_out)
        self.assertIn("&lt;evil&gt;", html_out)
        self.assertIn("85.0", html_out)
        self.assertIn("JD-JAR-003", html_out)

    def test_render_method_findings_html_xss_safe(self):
        html_out = render_method_findings_html([self.finding])
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_out)
        self.assertIn("JD-EXEC-001", html_out)
        self.assertIn("CWE-78", html_out)
        self.assertIn("0x04", html_out)

    def test_generate_html_report_without_security(self):
        c_info = ClassInfo(
            class_name="com/example/Dummy",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=52,
            minor_version=0,
            constant_pool={},
            methods={
                "dummy": MethodInfo(
                    name="dummy",
                    descriptor="()V",
                    access_flags=1,
                    bytecode=b"\xb1",  # return
                )
            },
        )
        report_html = generateHtmlReport(
            classes=[c_info],
            raw_methods={"com/example/Dummy": {"dummy": "void dummy() { return; }"}},
            restored_methods={},
            target_name="Dummy.class",
        )
        self.assertIn("NeuroDecomp Report: Dummy.class", report_html)
        self.assertIn("com/example/Dummy", report_html)
        # Should not have sec-banner when scan_result is None
        self.assertNotIn('<section class="sec-banner">', report_html)

    def test_generate_html_report_with_security(self):
        c_info = ClassInfo(
            class_name="com/example/MaliciousTarget",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=52,
            minor_version=0,
            constant_pool={},
            methods={
                "runPayload": MethodInfo(
                    name="runPayload",
                    descriptor="()V",
                    access_flags=1,
                    bytecode=b"\xb1",
                )
            },
        )
        report_html = generateHtmlReport(
            classes=[c_info],
            raw_methods={"com/example/MaliciousTarget": {"runPayload": "void runPayload() { }"}},
            restored_methods={},
            target_name="test_sample.jar",
            scan_result=self.scan_result,
        )
        self.assertIn("Security Auditing & Behavioral Analysis", report_html)
        self.assertIn(".sec-banner", report_html)
        self.assertIn("JD-EXEC-001", report_html)
        self.assertIn("SUSPICIOUS", report_html)
        # Hostile tags must not appear unescaped
        self.assertNotIn("<script>alert(1)</script>", report_html)

    def test_json_and_sarif_export(self):
        data = self.scan_result.to_dict()
        self.assertEqual(data["overallVerdict"], "SUSPICIOUS")
        self.assertEqual(data["overallRiskScore"], 85.0)

        json_str = scan_result_to_json(self.scan_result)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["inputName"], "test_sample.jar")

        sarif_str = to_sarif(self.scan_result)
        self.assertIn("2.1.0", sarif_str)
        sarif_obj = json.loads(sarif_str)
        self.assertEqual(sarif_obj["version"], "2.1.0")
        self.assertEqual(len(sarif_obj["runs"]), 1)
        driver = sarif_obj["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "NeuroDecomp Security Auditor")
        rules = driver["rules"]
        rule_ids = [r["id"] for r in rules]
        self.assertIn("JD-EXEC-001", rule_ids)
        self.assertIn("JD-JAR-003", rule_ids)

        results = sarif_obj["runs"][0]["results"]
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
