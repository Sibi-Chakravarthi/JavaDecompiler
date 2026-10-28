"""
schema.py — JSON schemas, stdlib schema validation, and automatic repair generator.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from javadecompiler.security.models import Category, Kind, Severity


TRIAGE_SCHEMA = {
    "type": "object",
    "required": ["triageNotes", "recommendedMethods", "overallClassRiskAssessment"],
    "properties": {
        "triageNotes": {"type": "string"},
        "recommendedMethods": {"type": "array", "items": {"type": "string"}},
        "overallClassRiskAssessment": {
            "type": "string",
            "enum": ["benign", "vulnerable", "suspicious", "malicious"],
        },
    },
}

DEEP_DIVE_SCHEMA = {
    "type": "object",
    "required": ["intentSummary", "intentClassification", "findings"],
    "properties": {
        "intentSummary": {"type": "string"},
        "intentClassification": {
            "type": "string",
            "enum": ["benign", "vulnerable", "suspicious", "malicious"],
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "title",
                    "kind",
                    "category",
                    "severity",
                    "confidence",
                    "evidenceIds",
                    "rationale",
                    "remediation",
                ],
                "properties": {
                    "title": {"type": "string"},
                    "kind": {
                        "type": "string",
                        "enum": [k.value for k in Kind],
                    },
                    "category": {
                        "type": "string",
                        "enum": [c.value for c in Category],
                    },
                    "severity": {
                        "type": "string",
                        "enum": [s.value for s in Severity],
                    },
                    "confidence": {"type": "number"},
                    "cwe": {"type": "array", "items": {"type": "string"}},
                    "evidenceIds": {"type": "array", "items": {"type": "string"}},
                    "rationale": {"type": "string"},
                    "remediation": {"type": "string"},
                },
            },
        },
    },
}

SYNTHESIS_SCHEMA = {
    "type": "object",
    "required": ["synthesisSummary", "chainsDetected"],
    "properties": {
        "synthesisSummary": {"type": "string"},
        "chainsDetected": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["title", "kind", "category", "severity", "confidence", "methodChain", "rationale", "remediation"],
                "properties": {
                    "title": {"type": "string"},
                    "kind": {"type": "string"},
                    "category": {"type": "string"},
                    "severity": {"type": "string"},
                    "confidence": {"type": "number"},
                    "methodChain": {"type": "array", "items": {"type": "string"}},
                    "rationale": {"type": "string"},
                    "remediation": {"type": "string"},
                },
            },
        },
    },
}

VERIFY_SCHEMA = {
    "type": "object",
    "required": ["verdict", "rationale", "confidence"],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "refuted", "inconclusive"],
        },
        "rationale": {"type": "string"},
        "confidence": {"type": "number"},
    },
}

SCHEMAS = {
    "triage": TRIAGE_SCHEMA,
    "deep_dive": DEEP_DIVE_SCHEMA,
    "synthesis": SYNTHESIS_SCHEMA,
    "verify": VERIFY_SCHEMA,
}


def _validate_node(data: Any, schema: Dict[str, Any], path: str = "root") -> Tuple[bool, Optional[str]]:
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(data, dict):
            return False, f"{path}: expected object (dict), got {type(data).__name__}"
        required_keys = schema.get("required", [])
        for k in required_keys:
            if k not in data:
                return False, f"{path}: missing required field '{k}'"
        properties = schema.get("properties", {})
        for k, sub_schema in properties.items():
            if k in data:
                valid, err = _validate_node(data[k], sub_schema, path=f"{path}.{k}")
                if not valid:
                    return False, err
        return True, None

    elif expected_type == "array":
        if not isinstance(data, list):
            return False, f"{path}: expected array (list), got {type(data).__name__}"
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(data):
                valid, err = _validate_node(item, item_schema, path=f"{path}[{i}]")
                if not valid:
                    return False, err
        return True, None

    elif expected_type == "string":
        if not isinstance(data, str):
            return False, f"{path}: expected string, got {type(data).__name__}"
        allowed_enum = schema.get("enum")
        if allowed_enum and data.lower() not in [e.lower() for e in allowed_enum]:
            return False, f"{path}: '{data}' not in allowed enum {allowed_enum}"
        return True, None

    elif expected_type == "number":
        if not isinstance(data, (int, float)):
            return False, f"{path}: expected number (float/int), got {type(data).__name__}"
        return True, None

    elif expected_type == "boolean":
        if not isinstance(data, bool):
            return False, f"{path}: expected boolean, got {type(data).__name__}"
        return True, None

    return True, None


def validate_schema(data: Any, schema_name: str) -> Tuple[bool, Optional[str]]:
    """Validates data against one of the registered schemas ('triage', 'deep_dive', 'synthesis', 'verify')."""
    schema = SCHEMAS.get(schema_name)
    if not schema:
        return False, f"Unknown schema name: '{schema_name}'"
    return _validate_node(data, schema)


def make_repair_prompt(broken_text: str, error_message: str, schema_name: str) -> str:
    """Constructs a repair prompt to ask the model to reformat its response."""
    schema = SCHEMAS.get(schema_name, {})
    schema_dump = json.dumps(schema, indent=2)
    return f"""The previous response could not be validated against the required JSON schema.
Error:
{error_message}

Required JSON Schema:
{schema_dump}

Previous Response:
{broken_text[:2000]}

Please correct the format and output ONLY valid, well-formed JSON matching the required schema above without extra conversational preamble or markdown code fences."""
