"""
test_llm_verifier_investigator.py — Tests for Phase 4 Milestone 9:
- Adversarial Verifier pass (Devil's Advocate refutation)
- Self-consistency majority voting (--llm-votes N)
- Bounded Agentic Investigator (max 8 steps, read-only tools, traces)
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from javadecompiler.class_parser import ClassInfo, MethodInfo
from javadecompiler.security.callgraph import CallGraph
from javadecompiler.security.llm.cache import LlmDiskCache
from javadecompiler.security.llm.client import FakeLlmClient
from javadecompiler.security.llm.harness import LlmAuditorHarness
from javadecompiler.security.llm.investigator import BoundedInvestigator
from javadecompiler.security.models import (
    Category,
    ClassAnalysis,
    Evidence,
    Finding,
    Kind,
    Location,
    MethodAnalysis,
    ScanResult,
    Severity,
)


class TestLlmVerifierAndInvestigator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "test_cache"
        self.cache = LlmDiskCache(cache_dir=self.cache_dir)
        self.c_info = ClassInfo(
            class_name="com/example/CryptoService",
            super_class="java/lang/Object",
            interfaces=[],
            major_version=52,
            minor_version=0,
            constant_pool={
                1: {"tag": "String", "value": "AES"},
                2: {"tag": "String", "value": "secret_key_123"},
            },
            methods={
                "encrypt": MethodInfo(
                    name="encrypt",
                    descriptor="([B)[B",
                    access_flags=1,
                    bytecode=b"\xb1",
                )
            },
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_adversarial_verifier_confirmed(self):
        # 1st call: deep dive findings (severity: medium)
        deep_dive_reply = json.dumps({
            "intentSummary": "Encrypts payload with hardcoded key",
            "intentClassification": "vulnerable",
            "findings": [
                {
                    "title": "Hardcoded Key",
                    "kind": "vulnerability",
                    "category": "crypto",
                    "severity": "medium",
                    "confidence": 0.9,
                    "evidenceIds": ["I:0x00", "CP:1"],
                    "rationale": "Static AES encryption key",
                    "remediation": "Load from KMS",
                }
            ],
        })
        # 2nd call: verifier returns confirmed
        verifier_reply = json.dumps({
            "verdict": "confirmed",
            "rationale": "Hardcoded key is unequivocally present.",
            "confidence": 0.95,
        })

        client = FakeLlmClient(canned_responses=[deep_dive_reply, verifier_reply])
        harness = LlmAuditorHarness(client=client, scope="all", votes=1, enable_cache=False)

        c_analysis = ClassAnalysis(
            className="com/example/CryptoService",
            methods={"encrypt": MethodAnalysis("encrypt", "([B)[B")},
        )
        scan_result = ScanResult(classes={"com/example/CryptoService": c_analysis})

        res = harness.run_audit(
            scan_result=scan_result,
            classes=[self.c_info],
            raw_methods={"com/example/CryptoService": {"encrypt": "byte[] encrypt(byte[] data) { return data; }"}},
        )

        findings = res.classes["com/example/CryptoService"].methods["encrypt"].findings
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].verifierVerdict, "confirmed")
        self.assertEqual(res.llmStats.verifierRefuted, 0)

    def test_adversarial_verifier_refuted(self):
        deep_dive_reply = json.dumps({
            "intentSummary": "Benign crypto usage",
            "intentClassification": "suspicious",
            "findings": [
                {
                    "title": "Potential Weak Crypto",
                    "kind": "vulnerability",
                    "category": "crypto",
                    "severity": "medium",
                    "confidence": 0.7,
                    "evidenceIds": ["I:0x00"],
                    "rationale": "Appears to use weak settings",
                    "remediation": "Review cipher suite",
                }
            ],
        })
        # Verifier refutes the finding
        verifier_reply = json.dumps({
            "verdict": "refuted",
            "rationale": "This is standard Java AES encryption with proper padding.",
            "confidence": 0.9,
        })

        client = FakeLlmClient(canned_responses=[deep_dive_reply, verifier_reply])
        harness = LlmAuditorHarness(client=client, scope="all", votes=1, enable_cache=False)

        c_analysis = ClassAnalysis(
            className="com/example/CryptoService",
            methods={"encrypt": MethodAnalysis("encrypt", "([B)[B")},
        )
        scan_result = ScanResult(classes={"com/example/CryptoService": c_analysis})

        res = harness.run_audit(
            scan_result=scan_result,
            classes=[self.c_info],
            raw_methods={"com/example/CryptoService": {"encrypt": "byte[] encrypt(byte[] data) { return data; }"}},
        )

        # Refuted finding must be dropped
        findings = res.classes["com/example/CryptoService"].methods["encrypt"].findings
        self.assertEqual(len(findings), 0)
        self.assertEqual(res.llmStats.verifierRefuted, 1)

    def test_self_consistency_majority_voting(self):
        deep_dive_reply = json.dumps({
            "intentSummary": "Check voting",
            "intentClassification": "vulnerable",
            "findings": [
                {
                    "title": "Crypto issue",
                    "kind": "vulnerability",
                    "category": "crypto",
                    "severity": "medium",
                    "confidence": 0.8,
                    "evidenceIds": ["I:0x00"],
                    "rationale": "Test voting",
                    "remediation": "Fix",
                }
            ],
        })

        # 3 votes: 2 refute, 1 confirms -> Majority is REFUTED
        v1 = json.dumps({"verdict": "refuted", "rationale": "Safe", "confidence": 0.8})
        v2 = json.dumps({"verdict": "confirmed", "rationale": "Unsafe", "confidence": 0.8})
        v3 = json.dumps({"verdict": "refuted", "rationale": "Safe again", "confidence": 0.8})

        client = FakeLlmClient(canned_responses=[deep_dive_reply, v1, v2, v3])
        harness = LlmAuditorHarness(client=client, scope="all", votes=3, enable_cache=False)

        c_analysis = ClassAnalysis(
            className="com/example/CryptoService",
            methods={"encrypt": MethodAnalysis("encrypt", "([B)[B")},
        )
        scan_result = ScanResult(classes={"com/example/CryptoService": c_analysis})

        res = harness.run_audit(
            scan_result=scan_result,
            classes=[self.c_info],
            raw_methods={"com/example/CryptoService": {"encrypt": "byte[] encrypt(byte[] data) { return data; }"}},
        )

        # Majority refuted -> dropped
        findings = res.classes["com/example/CryptoService"].methods["encrypt"].findings
        self.assertEqual(len(findings), 0)
        self.assertEqual(res.llmStats.verifierRefuted, 1)

    def test_bounded_investigator_tool_actions(self):
        cg = CallGraph()
        cg.add_edge(("com/example/CryptoService", "callerMethod"), ("com/example/CryptoService", "encrypt"))

        static_f = Finding(
            ruleId="JD-CRYP-002",
            title="Weak cipher",
            description="Static DES detected",
            remediation="Use AES",
            kind=Kind.VULNERABILITY.value,
            category=Category.CRYPTO.value,
            severity=Severity.HIGH.value,
            location=Location(className="com/example/CryptoService", methodName="encrypt"),
        )

        # Sequence of 3 actions: getConstants -> getStaticFindings -> finish
        step1 = json.dumps({
            "thought": "I will inspect constant pool strings.",
            "action": "getConstants",
            "arguments": {"filterStr": "secret"},
        })
        step2 = json.dumps({
            "thought": "I will check existing static findings.",
            "action": "getStaticFindings",
            "arguments": {"className": "com/example/CryptoService", "methodName": "encrypt"},
        })
        step3 = json.dumps({
            "thought": "Conclude investigation with verified findings.",
            "action": "finish",
            "arguments": {
                "findings": [
                    {
                        "title": "Verified Secret Key Hardcoded",
                        "kind": "vulnerability",
                        "category": "secrets",
                        "severity": "medium",
                        "confidence": 0.95,
                        "evidenceIds": ["CP:2"],
                        "rationale": "Hardcoded secret string found in constant pool",
                        "remediation": "Do not hardcode secrets",
                    }
                ]
            },
        })

        client = FakeLlmClient(canned_responses=[step1, step2, step3])
        investigator = BoundedInvestigator(
            client=client,
            classes=[self.c_info],
            raw_methods={"com/example/CryptoService": {"encrypt": "byte[] encrypt(byte[] data) { return data; }"}},
            call_graph=cg,
            static_findings=[static_f],
            max_steps=5,
        )

        inv_result = investigator.investigate("com/example/CryptoService", "encrypt")
        self.assertTrue(inv_result.concluded)
        self.assertEqual(inv_result.steps_taken, 3)
        self.assertEqual(len(inv_result.traces), 3)
        self.assertIn("secret_key_123", inv_result.traces[0]["result_summary"])
        self.assertIn("JD-CRYP-002", inv_result.traces[1]["result_summary"])
        self.assertEqual(len(inv_result.findings), 1)
        self.assertEqual(inv_result.findings[0].title, "Verified Secret Key Hardcoded")

    def test_bounded_investigator_max_8_steps_limit(self):
        # Feed 10 looping actions, verify investigator stops strictly at 8
        loop_step = json.dumps({
            "thought": "Keep looping...",
            "action": "getConstants",
            "arguments": {},
        })
        canned = [loop_step] * 12
        client = FakeLlmClient(canned_responses=canned)

        investigator = BoundedInvestigator(
            client=client,
            classes=[self.c_info],
            raw_methods={"com/example/CryptoService": {"encrypt": "byte[] encrypt(byte[] data) {}"}},
            max_steps=8,
        )

        inv_result = investigator.investigate("com/example/CryptoService", "encrypt")
        self.assertEqual(inv_result.steps_taken, 8)
        self.assertFalse(inv_result.concluded)


if __name__ == "__main__":
    unittest.main()
