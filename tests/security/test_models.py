"""
test_models.py — Unit tests for Phase 4 models, serialization, rule base, and FakeLlmClient.
"""

import json
import os
import tempfile
import unittest

from javadecompiler.cli import run_pipeline
from javadecompiler.security.llm.client import FakeLlmClient
from javadecompiler.security.models import (
    Category,
    ClassAnalysis,
    CoverageStats,
    Evidence,
    Finding,
    Kind,
    LlmStats,
    Location,
    MethodAnalysis,
    Origin,
    ScanResult,
    Severity,
    Verdict,
    generate_finding_id,
)
from javadecompiler.security.rules.base import (
    RULE_REGISTRY,
    SecurityRule,
    get_all_rules,
    get_rule,
    register_rule,
)


class TestSecurityModels(unittest.TestCase):
    def test_evidence_serialization(self):
        ev = Evidence(id="I:0x12", type="instruction", text="invokevirtual Runtime.exec", offset=18)
        d = ev.to_dict()
        self.assertEqual(d["id"], "I:0x12")
        self.assertEqual(d["offset"], 18)
        restored = Evidence.from_dict(d)
        self.assertEqual(restored.id, ev.id)
        self.assertEqual(restored.offset, 18)

    def test_location_serialization(self):
        loc = Location(
            className="com/example/Exploit",
            methodName="run",
            descriptor="()V",
            bytecodeOffsets=[12, 18],
            liftedLineNumbers=[5, 6],
            jarEntryPath="BOOT-INF/classes/com/example/Exploit.class",
        )
        d = loc.to_dict()
        self.assertEqual(d["className"], "com/example/Exploit")
        self.assertEqual(d["bytecodeOffsets"], [12, 18])
        restored = Location.from_dict(d)
        self.assertEqual(restored.bytecodeOffsets, [12, 18])
        self.assertEqual(restored.liftedLineNumbers, [5, 6])

    def test_finding_id_stability(self):
        fid1 = generate_finding_id("JD-EXEC-001", "C", "m", "()V", "I:0x12")
        fid2 = generate_finding_id("JD-EXEC-001", "C", "m", "()V", "I:0x12")
        self.assertEqual(fid1, fid2)
        self.assertEqual(len(fid1), 16)

        loc = Location(className="TestClass", methodName="foo", descriptor="(I)V")
        f = Finding(
            ruleId="JD-EXEC-001",
            title="Command Execution",
            description="Process execution detected",
            remediation="Sanitize arguments",
            kind=Kind.VULNERABILITY.value,
            category=Category.EXECUTION.value,
            severity=Severity.HIGH.value,
            location=loc,
            evidence=[Evidence(id="I:0x04", type="instruction", text="invokestatic exec")],
        )
        self.assertTrue(bool(f.findingId))
        self.assertEqual(len(f.findingId), 16)

    def test_scan_result_full_roundtrip(self):
        loc = Location(className="A", methodName="m", descriptor="()V", bytecodeOffsets=[0], liftedLineNumbers=[1])
        ev = Evidence(id="I:0x00", type="instruction", text="nop", offset=0)
        finding = Finding(
            ruleId="JD-TEST-001",
            title="Test Finding",
            description="Desc",
            remediation="Fix it",
            kind=Kind.VULNERABILITY.value,
            category=Category.CRYPTO.value,
            severity=Severity.MEDIUM.value,
            location=loc,
            evidence=[ev],
        )

        method_analysis = MethodAnalysis(
            methodName="m",
            descriptor="()V",
            isStatic=True,
            analysisCoverage="full",
            liftedCode="void m() {}",
            riskScore=12.0,
            findings=[finding],
        )

        class_analysis = ClassAnalysis(
            className="A",
            superClass="java/lang/Object",
            riskScore=12.0,
            methods={"m": method_analysis},
        )

        result = ScanResult(
            schemaVersion="1.0.0",
            inputSha256="abc123sha",
            inputName="Test.jar",
            timestamp="2026-10-28T12:00:00Z",
            toolVersion="0.1.0",
            overallVerdict=Verdict.VULNERABLE.value,
            overallRiskScore=12.0,
            topReasons=["Detected crypto weakness"],
            classes={"A": class_analysis},
            jarFindings=[],
            coverageStats=CoverageStats(totalMethods=1, fullCoverageMethods=1),
            llmStats=LlmStats(enabled=False, model="qwen2.5-coder:14b"),
        )

        # Check allFindings aggregation
        self.assertEqual(len(result.allFindings), 1)
        self.assertEqual(result.allFindings[0].ruleId, "JD-TEST-001")

        # JSON Roundtrip
        json_str = result.to_json()
        restored = ScanResult.from_json(json_str)
        self.assertEqual(restored.inputSha256, "abc123sha")
        self.assertEqual(restored.overallVerdict, Verdict.VULNERABLE.value)
        self.assertEqual(len(restored.classes), 1)
        self.assertIn("A", restored.classes)
        self.assertEqual(len(restored.allFindings), 1)
        self.assertEqual(restored.allFindings[0].title, "Test Finding")

    def test_rule_registry(self):
        @register_rule
        class DummyRule(SecurityRule):
            rule_id = "JD-DUMMY-001"
            title = "Dummy Test Rule"
            description = "Rule for testing registry"
            remediation = "None"
            severity = Severity.LOW.value
            category = Category.INFO_GATHERING.value

        self.assertIn("JD-DUMMY-001", RULE_REGISTRY)
        rule = get_rule("JD-DUMMY-001")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.title, "Dummy Test Rule")

        # Test enable/disable filter
        filtered = get_all_rules(disabled_rules=["JD-DUMMY-001"])
        self.assertNotIn("JD-DUMMY-001", [r.rule_id for r in filtered])

        # Clean up registry
        del RULE_REGISTRY["JD-DUMMY-001"]

    def test_fake_llm_client(self):
        client = FakeLlmClient(model_name="test-model")
        self.assertTrue(client.is_available())
        response = client.generate("test prompt", format_json=True)
        data = json.loads(response)
        self.assertIn("intentClassification", data)
        self.assertEqual(len(client.call_history), 1)

        # Canned response
        client.enqueue_response('{"custom": true}')
        self.assertEqual(client.generate("another"), '{"custom": true}')

    def test_cli_security_scan_flag(self):
        class_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "javadecompiler", "Java_Test_Files", "EngineMath.class"
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_json:
            json_path = tmp_json.name

        try:
            ret = run_pipeline(
                input_path=class_path,
                security_scan=True,
                no_llm=True,
                security_json=json_path,
            )
            self.assertEqual(ret, 0)
            self.assertTrue(os.path.exists(json_path))
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data.get("schemaVersion"), "1.0.0")
            self.assertEqual(data.get("overallVerdict"), "CLEAN")
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)


if __name__ == "__main__":
    unittest.main()
