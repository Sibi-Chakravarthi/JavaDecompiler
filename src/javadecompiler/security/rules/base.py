"""
base.py — Security rule base class and registry for NeuroDecomp Phase 4.
"""

from __future__ import annotations

from abc import ABC
from typing import Any, Dict, List, Optional, Type

from javadecompiler.class_parser import ClassInfo, MethodInfo
from javadecompiler.security.models import (
    Category,
    Evidence,
    Finding,
    Kind,
    Location,
    Origin,
    Severity,
)

RULE_REGISTRY: Dict[str, Type["SecurityRule"]] = {}


def register_rule(cls: Type["SecurityRule"]) -> Type["SecurityRule"]:
    """Decorator to register a rule class in the global RULE_REGISTRY."""
    if not hasattr(cls, "rule_id") or not cls.rule_id:
        raise ValueError(f"Rule class {cls.__name__} must define a non-empty rule_id")
    RULE_REGISTRY[cls.rule_id] = cls
    return cls


class SecurityRule(ABC):
    """Base class for all static security rules in NeuroDecomp."""

    rule_id: str = ""
    title: str = ""
    description: str = ""
    remediation: str = ""
    kind: str = Kind.VULNERABILITY.value
    category: str = Category.EXECUTION.value
    severity: str = Severity.MEDIUM.value
    cwe: List[str] = []
    mitre_attack: Optional[str] = None
    rule_version: str = "1.0.0"
    enabled: bool = True

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def analyze_class(
        self,
        class_info: ClassInfo,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        """Class-level analysis hook. Override for rules checking class structure or CP."""
        return []

    def analyze_method(
        self,
        class_info: ClassInfo,
        method_name: str,
        method_info: MethodInfo,
        lifted_lines: List[str],
        instructions: List[Dict[str, Any]],
        cfg: Optional[Dict[int, Any]] = None,
        call_graph: Optional[Any] = None,
    ) -> List[Finding]:
        """Method-level analysis hook. Override for rules checking instructions, lines, or CFG."""
        return []

    def create_finding(
        self,
        class_name: str,
        method_name: str = "",
        descriptor: str = "",
        bytecode_offsets: Optional[List[int]] = None,
        lifted_lines: Optional[List[int]] = None,
        jar_entry_path: Optional[str] = None,
        evidence: Optional[List[Evidence]] = None,
        severity_override: Optional[str] = None,
        title_override: Optional[str] = None,
        description_override: Optional[str] = None,
        confidence: float = 1.0,
        confidence_sources: Optional[Dict[str, float]] = None,
        analysis_coverage: str = "full",
        partial_reason: Optional[str] = None,
    ) -> Finding:
        """Helper to construct a typed Finding object with standard rule metadata."""
        loc = Location(
            className=class_name,
            methodName=method_name,
            descriptor=descriptor,
            bytecodeOffsets=bytecode_offsets or [],
            liftedLineNumbers=lifted_lines or [],
            jarEntryPath=jar_entry_path,
        )
        conf_sources = confidence_sources or {"staticWeight": confidence}
        return Finding(
            ruleId=self.rule_id,
            title=title_override or self.title,
            description=description_override or self.description,
            remediation=self.remediation,
            kind=self.kind,
            category=self.category,
            severity=severity_override or self.severity,
            location=loc,
            confidence=confidence,
            confidenceSources=conf_sources,
            cwe=list(self.cwe),
            mitreAttack=self.mitre_attack,
            evidence=evidence or [],
            origin=Origin.STATIC.value,
            ruleVersion=self.rule_version,
            analysisCoverage=analysis_coverage,
            partialReason=partial_reason,
        )


def get_all_rules(
    enabled_rules: Optional[List[str]] = None,
    disabled_rules: Optional[List[str]] = None,
) -> List[SecurityRule]:
    """Instantiates registered rules respecting enable/disable filters."""
    rules: List[SecurityRule] = []
    for rule_id, rule_cls in RULE_REGISTRY.items():
        if disabled_rules and rule_id in disabled_rules:
            continue
        if enabled_rules and rule_id not in enabled_rules:
            continue
        rules.append(rule_cls())
    return rules


def get_rule(rule_id: str) -> Optional[SecurityRule]:
    """Fetches and instantiates a specific rule by ID."""
    rule_cls = RULE_REGISTRY.get(rule_id)
    return rule_cls() if rule_cls else None
