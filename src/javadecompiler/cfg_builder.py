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
 

