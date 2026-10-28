"""
models.py — Security data models for NeuroDecomp Phase 4.

Defines JSON-serializable dataclasses for Findings, Evidence, Locations,
Coverage, and ScanResults.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Kind(str, Enum):
    VULNERABILITY = "vulnerability"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    MALICIOUS_INDICATOR = "malicious_indicator"
    HYGIENE = "hygiene"


class Category(str, Enum):
    EXECUTION = "execution"
    NETWORK = "network"
    DYNAMIC_LOADING = "dynamic_loading"
    DESERIALIZATION = "deserialization"
    INJECTION = "injection"
    CRYPTO = "crypto"
    SECRETS = "secrets"
    EVASION = "evasion"
    PERSISTENCE = "persistence"
    NATIVE = "native"
    LOADTIME = "loadtime"
    ARCHIVE = "archive"
    INFO_GATHERING = "info_gathering"


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    REVIEW_RECOMMENDED = "REVIEW_RECOMMENDED"
    VULNERABLE = "VULNERABLE"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_MALICIOUS = "LIKELY_MALICIOUS"


class Origin(str, Enum):
    STATIC = "static"
    LLM = "llm"
    HYBRID = "hybrid"


@dataclass
class Evidence:
    id: str  # e.g., "I:0x2A", "CP:17", "L:12", "JAR:0"
    type: str  # "instruction" | "constantPool" | "liftedLine" | "jarEntry"
    text: str
    offset: Optional[int] = None
    index: Optional[int] = None
    line: Optional[int] = None
    path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "text": self.text,
        }
        if self.offset is not None:
            d["offset"] = self.offset
        if self.index is not None:
            d["index"] = self.index
        if self.line is not None:
            d["line"] = self.line
        if self.path is not None:
            d["path"] = self.path
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        return cls(
            id=data.get("id", ""),
            type=data.get("type", "instruction"),
            text=data.get("text", ""),
            offset=data.get("offset"),
            index=data.get("index"),
            line=data.get("line"),
            path=data.get("path"),
        )


@dataclass
class Location:
    className: str
    methodName: str = ""
    descriptor: str = ""
    bytecodeOffsets: List[int] = field(default_factory=list)
    liftedLineNumbers: List[int] = field(default_factory=list)
    jarEntryPath: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "className": self.className,
            "methodName": self.methodName,
            "descriptor": self.descriptor,
            "bytecodeOffsets": list(self.bytecodeOffsets),
            "liftedLineNumbers": list(self.liftedLineNumbers),
            "jarEntryPath": self.jarEntryPath,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Location":
        return cls(
            className=data.get("className", ""),
            methodName=data.get("methodName", ""),
            descriptor=data.get("descriptor", ""),
            bytecodeOffsets=list(data.get("bytecodeOffsets", [])),
            liftedLineNumbers=list(data.get("liftedLineNumbers", [])),
            jarEntryPath=data.get("jarEntryPath"),
        )


def generate_finding_id(
    rule_id: str,
    class_name: str,
    method_name: str,
    descriptor: str,
    primary_evidence_key: str,
) -> str:
    """Computes a stable 16-character hex hash finding ID."""
    raw = f"{rule_id}:{class_name}:{method_name}:{descriptor}:{primary_evidence_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class Finding:
    ruleId: str
    title: str
    description: str
    remediation: str
    kind: str  # Kind enum value
    category: str  # Category enum value
    severity: str  # Severity enum value
    location: Location
    findingId: str = ""
    confidence: float = 1.0
    confidenceSources: Dict[str, float] = field(default_factory=dict)
    cwe: List[str] = field(default_factory=list)
    mitreAttack: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    origin: str = Origin.STATIC.value
    ruleVersion: str = "1.0.0"
    promptVersion: Optional[str] = None
    modelName: Optional[str] = None
    modelDigest: Optional[str] = None
    analysisCoverage: str = "full"
    partialReason: Optional[str] = None
    llmRationale: Optional[str] = None
    verifierVerdict: Optional[str] = None  # "confirmed" | "refuted" | "inconclusive"

    def __post_init__(self) -> None:
        if not self.findingId:
            primary_key = ""
            if self.evidence:
                primary_key = self.evidence[0].id
            elif self.location.bytecodeOffsets:
                primary_key = str(self.location.bytecodeOffsets[0])
            elif self.location.liftedLineNumbers:
                primary_key = str(self.location.liftedLineNumbers[0])
            self.findingId = generate_finding_id(
                self.ruleId,
                self.location.className,
                self.location.methodName,
                self.location.descriptor,
                primary_key,
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findingId": self.findingId,
            "ruleId": self.ruleId,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "kind": self.kind,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "confidenceSources": self.confidenceSources,
            "cwe": self.cwe,
            "mitreAttack": self.mitreAttack,
            "location": self.location.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "origin": self.origin,
            "ruleVersion": self.ruleVersion,
            "promptVersion": self.promptVersion,
            "modelName": self.modelName,
            "modelDigest": self.modelDigest,
            "analysisCoverage": self.analysisCoverage,
            "partialReason": self.partialReason,
            "llmRationale": self.llmRationale,
            "verifierVerdict": self.verifierVerdict,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        loc = Location.from_dict(data.get("location", {}))
        ev_list = [Evidence.from_dict(e) for e in data.get("evidence", [])]
        return cls(
            findingId=data.get("findingId", ""),
            ruleId=data.get("ruleId", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            kind=data.get("kind", Kind.VULNERABILITY.value),
            category=data.get("category", Category.EXECUTION.value),
            severity=data.get("severity", Severity.MEDIUM.value),
            confidence=float(data.get("confidence", 1.0)),
            confidenceSources=data.get("confidenceSources", {}),
            cwe=list(data.get("cwe", [])),
            mitreAttack=data.get("mitreAttack"),
            location=loc,
            evidence=ev_list,
            origin=data.get("origin", Origin.STATIC.value),
            ruleVersion=data.get("ruleVersion", "1.0.0"),
            promptVersion=data.get("promptVersion"),
            modelName=data.get("modelName"),
            modelDigest=data.get("modelDigest"),
            analysisCoverage=data.get("analysisCoverage", "full"),
            partialReason=data.get("partialReason"),
            llmRationale=data.get("llmRationale"),
            verifierVerdict=data.get("verifierVerdict"),
        )


@dataclass
class MethodAnalysis:
    methodName: str
    descriptor: str
    isStatic: bool = False
    analysisCoverage: str = "full"
    partialReason: Optional[str] = None
    liftedCode: str = ""
    bytecodeInstructions: List[Dict[str, Any]] = field(default_factory=list)
    riskScore: float = 0.0
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "methodName": self.methodName,
            "descriptor": self.descriptor,
            "isStatic": self.isStatic,
            "analysisCoverage": self.analysisCoverage,
            "partialReason": self.partialReason,
            "liftedCode": self.liftedCode,
            "bytecodeInstructions": self.bytecodeInstructions,
            "riskScore": round(self.riskScore, 2),
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MethodAnalysis":
        return cls(
            methodName=data.get("methodName", ""),
            descriptor=data.get("descriptor", ""),
            isStatic=bool(data.get("isStatic", False)),
            analysisCoverage=data.get("analysisCoverage", "full"),
            partialReason=data.get("partialReason"),
            liftedCode=data.get("liftedCode", ""),
            bytecodeInstructions=list(data.get("bytecodeInstructions", [])),
            riskScore=float(data.get("riskScore", 0.0)),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
        )


@dataclass
class ClassAnalysis:
    className: str
    superClass: str = "java/lang/Object"
    interfaces: List[str] = field(default_factory=list)
    majorVersion: int = 0
    minorVersion: int = 0
    analysisCoverage: str = "full"
    partialReason: Optional[str] = None
    riskScore: float = 0.0
    methods: Dict[str, MethodAnalysis] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)  # Class-level findings

    def to_dict(self) -> Dict[str, Any]:
        return {
            "className": self.className,
            "superClass": self.superClass,
            "interfaces": self.interfaces,
            "majorVersion": self.majorVersion,
            "minorVersion": self.minorVersion,
            "analysisCoverage": self.analysisCoverage,
            "partialReason": self.partialReason,
            "riskScore": round(self.riskScore, 2),
            "methods": {k: v.to_dict() for k, v in self.methods.items()},
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClassAnalysis":
        return cls(
            className=data.get("className", ""),
            superClass=data.get("superClass", "java/lang/Object"),
            interfaces=list(data.get("interfaces", [])),
            majorVersion=int(data.get("majorVersion", 0)),
            minorVersion=int(data.get("minorVersion", 0)),
            analysisCoverage=data.get("analysisCoverage", "full"),
            partialReason=data.get("partialReason"),
            riskScore=float(data.get("riskScore", 0.0)),
            methods={k: MethodAnalysis.from_dict(v) for k, v in data.get("methods", {}).items()},
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
        )


@dataclass
class CoverageStats:
    totalMethods: int = 0
    fullCoverageMethods: int = 0
    partialCoverageMethods: int = 0
    failedMethods: int = 0
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "totalMethods": self.totalMethods,
            "fullCoverageMethods": self.fullCoverageMethods,
            "partialCoverageMethods": self.partialCoverageMethods,
            "failedMethods": self.failedMethods,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CoverageStats":
        return cls(
            totalMethods=int(data.get("totalMethods", 0)),
            fullCoverageMethods=int(data.get("fullCoverageMethods", 0)),
            partialCoverageMethods=int(data.get("partialCoverageMethods", 0)),
            failedMethods=int(data.get("failedMethods", 0)),
            limitations=list(data.get("limitations", [])),
        )


@dataclass
class LlmStats:
    enabled: bool = False
    model: str = "qwen2.5-coder:14b"
    calls: int = 0
    cacheHits: int = 0
    failures: int = 0
    ungroundedDropped: int = 0
    verifierRefuted: int = 0
    totalLatencyMs: float = 0.0
    investigationTraces: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "model": self.model,
            "calls": self.calls,
            "cacheHits": self.cacheHits,
            "failures": self.failures,
            "ungroundedDropped": self.ungroundedDropped,
            "verifierRefuted": self.verifierRefuted,
            "totalLatencyMs": round(self.totalLatencyMs, 2),
            "investigationTraces": self.investigationTraces,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LlmStats":
        return cls(
            enabled=bool(data.get("enabled", False)),
            model=data.get("model", "qwen2.5-coder:14b"),
            calls=int(data.get("calls", 0)),
            cacheHits=int(data.get("cacheHits", 0)),
            failures=int(data.get("failures", 0)),
            ungroundedDropped=int(data.get("ungroundedDropped", 0)),
            verifierRefuted=int(data.get("verifierRefuted", 0)),
            totalLatencyMs=float(data.get("totalLatencyMs", 0.0)),
            investigationTraces=list(data.get("investigationTraces", [])),
        )


@dataclass
class ScanResult:
    schemaVersion: str = "1.0.0"
    inputSha256: str = ""
    inputName: str = ""
    timestamp: str = ""
    toolVersion: str = "0.1.0"
    config: Dict[str, Any] = field(default_factory=dict)
    overallVerdict: str = Verdict.CLEAN.value
    overallRiskScore: float = 0.0
    topReasons: List[str] = field(default_factory=list)
    classes: Dict[str, ClassAnalysis] = field(default_factory=dict)
    jarFindings: List[Finding] = field(default_factory=list)
    coverageStats: CoverageStats = field(default_factory=CoverageStats)
    llmStats: LlmStats = field(default_factory=LlmStats)

    @property
    def allFindings(self) -> List[Finding]:
        """Flattens all findings from JAR-level, class-level, and method-level."""
        res: List[Finding] = list(self.jarFindings)
        for c in self.classes.values():
            res.extend(c.findings)
            for m in c.methods.values():
                res.extend(m.findings)
        return res

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schemaVersion": self.schemaVersion,
            "inputSha256": self.inputSha256,
            "inputName": self.inputName,
            "timestamp": self.timestamp,
            "toolVersion": self.toolVersion,
            "config": self.config,
            "overallVerdict": self.overallVerdict,
            "overallRiskScore": round(self.overallRiskScore, 2),
            "topReasons": list(self.topReasons),
            "classes": {k: v.to_dict() for k, v in self.classes.items()},
            "jarFindings": [f.to_dict() for f in self.jarFindings],
            "coverageStats": self.coverageStats.to_dict(),
            "llmStats": self.llmStats.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        return cls(
            schemaVersion=data.get("schemaVersion", "1.0.0"),
            inputSha256=data.get("inputSha256", ""),
            inputName=data.get("inputName", ""),
            timestamp=data.get("timestamp", ""),
            toolVersion=data.get("toolVersion", "0.1.0"),
            config=data.get("config", {}),
            overallVerdict=data.get("overallVerdict", Verdict.CLEAN.value),
            overallRiskScore=float(data.get("overallRiskScore", 0.0)),
            topReasons=list(data.get("topReasons", [])),
            classes={k: ClassAnalysis.from_dict(v) for k, v in data.get("classes", {}).items()},
            jarFindings=[Finding.from_dict(f) for f in data.get("jarFindings", [])],
            coverageStats=CoverageStats.from_dict(data.get("coverageStats", {})),
            llmStats=LlmStats.from_dict(data.get("llmStats", {})),
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> "ScanResult":
        return cls.from_dict(json.loads(json_str))
