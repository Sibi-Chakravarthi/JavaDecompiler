"""
helpers.py — Common bytecode and constant pool inspection utilities for rules.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from javadecompiler.class_parser import (
    ClassInfo,
    resolveClass,
    resolveNameAndType,
    resolveRef,
    resolveString,
    resolveUtf8,
)


def get_call_info(
    constant_pool: Dict[int, Any],
    instruction: Dict[str, Any],
) -> Optional[Dict[str, str]]:
    """Resolves target class, method name, and descriptor for invoke instructions."""
    mnemonic = instruction.get("mnemonic", "")
    if not (
        mnemonic.startswith("invoke")
        and mnemonic != "invokedynamic"
    ):
        return None

    operands = instruction.get("operands", [])
    if len(operands) < 2:
        return None

    idx = (operands[0] << 8) | operands[1]
    ref = resolveRef(constant_pool, idx)
    if ref and ref.get("class") and ref.get("name"):
        return ref

    # Fallback to handle mock dictionaries in unit tests
    entry = constant_pool.get(idx)
    if entry:
        cls_idx = entry.get("classIndex", entry.get("class_index", 0))
        nt_idx = entry.get("nameAndTypeIndex", entry.get("name_and_type_index", 0))
        cls_name = resolveClass(constant_pool, cls_idx)
        if not cls_name:
            c_entry = constant_pool.get(cls_idx, {})
            c_name_idx = c_entry.get("nameIndex", c_entry.get("name_index", 0))
            cls_name = resolveUtf8(constant_pool, c_name_idx)

        m_name, desc = resolveNameAndType(constant_pool, nt_idx)
        if not m_name:
            nt_entry = constant_pool.get(nt_idx, {})
            n_idx = nt_entry.get("nameIndex", nt_entry.get("name_index", 0))
            d_idx = nt_entry.get("descriptorIndex", nt_entry.get("descriptor_index", 0))
            m_name = resolveUtf8(constant_pool, n_idx)
            desc = resolveUtf8(constant_pool, d_idx)

        if cls_name and m_name:
            return {"kind": "MethodRef", "class": cls_name, "name": m_name, "descriptor": desc}
    return None


def get_ldc_string(
    constant_pool: Dict[int, Any],
    instruction: Dict[str, Any],
) -> Optional[Tuple[int, str]]:
    """Resolves string constant loaded by ldc or ldc_w. Returns (cp_index, string_value)."""
    mnemonic = instruction.get("mnemonic", "")
    operands = instruction.get("operands", [])

    idx: Optional[int] = None
    if mnemonic == "ldc" and len(operands) >= 1:
        idx = operands[0]
    elif mnemonic == "ldc_w" and len(operands) >= 2:
        idx = (operands[0] << 8) | operands[1]

    if idx is not None:
        s = resolveString(constant_pool, idx)
        if s:
            return idx, s
        val = constant_pool.get(idx, {})
        if val.get("type") == "Utf8":
            return idx, val.get("value", "")
        if val.get("type") == "String":
            str_idx = val.get("stringIndex", val.get("string_index", 0))
            return idx, resolveUtf8(constant_pool, str_idx)
    return None


def get_new_class(
    constant_pool: Dict[int, Any],
    instruction: Dict[str, Any],
) -> Optional[str]:
    """Resolves class name for 'new' instruction."""
    mnemonic = instruction.get("mnemonic", "")
    operands = instruction.get("operands", [])
    if mnemonic == "new" and len(operands) >= 2:
        idx = (operands[0] << 8) | operands[1]
        cls_name = resolveClass(constant_pool, idx)
        if cls_name:
            return cls_name
        entry = constant_pool.get(idx, {})
        if entry.get("type") == "Class":
            name_idx = entry.get("nameIndex", entry.get("name_index", 0))
            return resolveUtf8(constant_pool, name_idx)
    return None


def get_all_cp_strings(constant_pool: Dict[int, Any]) -> List[Tuple[int, str]]:
    """Extracts string constants from constant pool without duplicate Utf8 references."""
    results: List[Tuple[int, str]] = []
    utf8_referenced = set()
    for idx, entry in constant_pool.items():
        if entry.get("type") == "String":
            s_idx = entry.get("stringIndex", entry.get("string_index", 0))
            if s_idx:
                utf8_referenced.add(s_idx)
            val = resolveString(constant_pool, idx)
            if val:
                results.append((idx, val))

    for idx, entry in constant_pool.items():
        if entry.get("type") == "Utf8" and idx not in utf8_referenced:
            val = entry.get("value", "")
            if val:
                results.append((idx, val))

    return results


def find_matching_lines(
    lifted_lines: List[str],
    patterns: List[str],
) -> List[Tuple[int, str]]:
    """Returns 1-based line numbers and line text matching any of the given regex/substring patterns."""
    matched: List[Tuple[int, str]] = []
    for line_idx, line in enumerate(lifted_lines, 1):
        for pat in patterns:
            if pat in line or re.search(pat, line):
                matched.append((line_idx, line.strip()))
                break
    return matched
