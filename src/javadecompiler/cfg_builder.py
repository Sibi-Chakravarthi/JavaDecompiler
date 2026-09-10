from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

unconditionalJumpMnemonics: Set[str] = {"goto", "goto_w"}

conditionalJumpMnemonics: Set[str] = {
    "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle",
    "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple",
    "if_acmpeq", "if_acmpne", "ifnull", "ifnonnull",
}

returnMnemonics: Set[str] = {"ireturn", "lreturn", "freturn", "dreturn", "areturn", "return"}
throwMnemonics: Set[str] = {"athrow"}

switchMnemonics: Set[str] = {"tableswitch", "lookupswitch"}
 
branchMnemonics: Set[str] = conditionalJumpMnemonics | unconditionalJumpMnemonics
terminatorMnemonics: Set[str] = branchMnemonics | returnMnemonics | throwMnemonics | switchMnemonics
 

def resolveBranchTarget(instruction: Dict[str, Any]) -> Optional[int]:
    mnemonic: str = instruction["mnemonic"]
    if mnemonic not in conditionalJumpMnemonics and mnemonic not in unconditionalJumpMnemonics:
        return None
 
    operands: List[int] = instruction["operands"]
    if len(operands) != 2:
        return None
 
    highByte, lowByte = operands
    rawOffset: int = (highByte << 8) | lowByte
    if rawOffset >= 0x8000:
        rawOffset -= 0x10000
 
    return instruction["offset"] + rawOffset
 
 
