"""
context.py — Token budgeting, prompt-injection defense, and artifact formatting for LLM auditing.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Tuple


SUSPICIOUS_PHRASES = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"mark\s+this\s+class\s+as\s+clean",
    r"system\s+prompt",
    r"no\s+vulnerabilities\s+found",
    r"output\s+zero\s+findings",
    r"you\s+are\s+now\s+in\s+developer\s+mode",
]


def generate_boundary() -> str:
    """Generates a random unique boundary tag for enclosing untrusted data."""
    return f"UNTRUSTED_TARGET_DATA_{uuid.uuid4().hex[:8]}"


def sanitize_untrusted_text(text: str, boundary: Optional[str] = None, max_len: int = 16000) -> str:
    """
    Sanitizes untrusted target text:
    - Neutralizes closing XML/HTML boundary tags
    - Flags potential prompt-injection payloads
    - Truncates excessive text length to preserve token budget
    """
    if not text:
        return ""

    sanitized = text

    # Neutralize closing tags
    if boundary:
        sanitized = re.sub(rf"</?{re.escape(boundary)}>", "[TAG_DEFUSED]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"</?UNTRUSTED[^>]*>", "[TAG_DEFUSED]", sanitized, flags=re.IGNORECASE)

    # Flag and remove prompt-injection attempts inside code comments or strings
    for pattern in SUSPICIOUS_PHRASES:
        sanitized = re.sub(pattern, "[PROMPT_INJECTION_DEFUSED]", sanitized, flags=re.IGNORECASE)

    # Truncate if exceeding maximum length budget
    if len(sanitized) > max_len:
        head = sanitized[: max_len // 2]
        tail = sanitized[-max_len // 4 :]
        sanitized = f"{head}\n\n... [TRUNCATED {len(sanitized) - max_len} CHARACTERS FOR TOKEN BUDGET] ...\n\n{tail}"

    return sanitized


def format_lifted_code_with_lines(lifted_code: str, max_lines: int = 500) -> Tuple[str, Dict[int, str]]:
    """
    Annotates lifted code with line numbers: 'L:1:  public void test() ...'
    Returns formatted string and mapping of line_num -> code_line.
    """
    lines = lifted_code.splitlines()
    line_map: Dict[int, str] = {}
    formatted_lines: List[str] = []

    for idx, line in enumerate(lines[:max_lines], start=1):
        line_map[idx] = line
        formatted_lines.append(f"L:{idx:02d}:  {line}")

    if len(lines) > max_lines:
        formatted_lines.append(f"... [{len(lines) - max_lines} lines truncated] ...")

    return "\n".join(formatted_lines), line_map


def format_bytecode_with_offsets(instructions: List[Any], max_ins: int = 400) -> Tuple[str, Dict[int, str]]:
    """
    Formats disassembled instructions with offset markers: 'I:0x04:  invokevirtual #12'
    Returns formatted string and mapping of offset -> instruction_str.
    """
    offset_map: Dict[int, str] = {}
    formatted_ins: List[str] = []

    for ins in instructions[:max_ins]:
        # Support dict representation or object with offset and mnemonic
        offset = getattr(ins, "offset", None) if hasattr(ins, "offset") else (ins.get("offset") if isinstance(ins, dict) else None)
        if offset is None:
            continue

        text = getattr(ins, "text", None) if hasattr(ins, "text") else None
        if not text:
            mnemonic = getattr(ins, "mnemonic", "") if hasattr(ins, "mnemonic") else ins.get("mnemonic", "")
            operands = getattr(ins, "operands", "") if hasattr(ins, "operands") else ins.get("operands", "")
            text = f"{mnemonic} {operands}".strip()

        offset_map[int(offset)] = text
        formatted_ins.append(f"I:0x{int(offset):02x}:  {text}")

    if len(instructions) > max_ins:
        formatted_ins.append(f"... [{len(instructions) - max_ins} instructions truncated] ...")

    return "\n".join(formatted_ins), offset_map


def format_constant_pool_strings(constant_pool: Dict[int, Any], max_entries: int = 100) -> Tuple[str, Dict[int, str]]:
    """
    Extracts String and Utf8 constant pool entries formatted as 'CP:index: "string"'.
    Returns formatted string and mapping of index -> string_value.
    """
    cp_map: Dict[int, str] = {}
    lines: List[str] = []

    count = 0
    for idx, entry in sorted(constant_pool.items(), key=lambda x: int(x[0])):
        val = None
        if isinstance(entry, dict):
            tag = entry.get("tag") or entry.get("type")
            if tag in ("String", "Utf8", 8, 1):
                val = entry.get("value") or entry.get("string") or entry.get("bytes")
        elif hasattr(entry, "value"):
            val = entry.value

        if val and isinstance(val, str) and val.strip():
            # Truncate very long string literals
            display_val = val if len(val) <= 120 else f"{val[:100]}...[truncated]"
            cp_map[int(idx)] = val
            lines.append(f'CP:{idx}: "{display_val}"')
            count += 1
            if count >= max_entries:
                lines.append(f"... [remaining CP entries omitted] ...")
                break

    return "\n".join(lines), cp_map
