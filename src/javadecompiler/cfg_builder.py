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
 
 
def fallsThrough(mnemonic: str) -> bool:
    if mnemonic in unconditionalJumpMnemonics:
        return False
    if mnemonic in returnMnemonics:
        return False
    if mnemonic in throwMnemonics:
        return False
    if mnemonic in switchMnemonics:
        return False
    return True

@dataclass
class BasicBlock:
    startOffset: int
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    successors: Set[int] = field(default_factory=set)
    predecessors: Set[int] = field(default_factory=set)
 
    @property
    def endOffset(self) -> int:
        return self.instructions[-1]["offset"] if self.instructions else self.startOffset
 
    @property
    def isExitBlock(self) -> bool:
        return len(self.successors) == 0
 
    def __repr__(self) -> str:
        mnemonics = ", ".join(instr["mnemonic"] for instr in self.instructions)
        return f"BasicBlock(start={self.startOffset}, [{mnemonics}], -> {sorted(self.successors)})"

def findLeaders(instructions: List[Dict[str, Any]]) -> Set[int]:
    if not instructions:
        return set()
 
    leaders: Set[int] = {instructions[0]["offset"]}
 
    for index, instruction in enumerate(instructions):
        mnemonic: str = instruction["mnemonic"]
 
        if mnemonic in branchMnemonics:
            target = resolveBranchTarget(instruction)
            if target is not None:
                leaders.add(target)
 
        if mnemonic in terminatorMnemonics and index + 1 < len(instructions):
            leaders.add(instructions[index + 1]["offset"])
 
    return leaders
 
 
def splitIntoBlocks(instructions: List[Dict[str, Any]], leaders: Set[int]) -> Dict[int, BasicBlock]:
    blocks: Dict[int, BasicBlock] = {}
    if not instructions:
        return blocks
 
    sortedLeaders: List[int] = sorted(leaders)
    currentBlock: Optional[BasicBlock] = None
 
    for instruction in instructions:
        if instruction["offset"] in leaders:
            currentBlock = BasicBlock(startOffset=instruction["offset"])
            blocks[currentBlock.startOffset] = currentBlock
        currentBlock.instructions.append(instruction)
 
    return blocks
 
def wireEdges(blocks: Dict[int, BasicBlock]) -> None:
    """Mutates each block's successors/predecessors in place."""
    sortedStarts: List[int] = sorted(blocks.keys())
 
    for position, startOffset in enumerate(sortedStarts):
        block = blocks[startOffset]
        lastInstruction = block.instructions[-1]
        mnemonic: str = lastInstruction["mnemonic"]
 
        if mnemonic in branchMnemonics:
            target = resolveBranchTarget(lastInstruction)
            if target is not None and target in blocks:
                block.successors.add(target)
            elif target is not None:
                raise ValueError(
                    f"Block at {startOffset} branches to unresolved offset {target}; "
                    f"no BasicBlock starts there."
                )

        if mnemonic in switchMnemonics:
            pass
 
        if fallsThrough(mnemonic) and position + 1 < len(sortedStarts):
            block.successors.add(sortedStarts[position + 1])
 
    for block in blocks.values():
        for successorOffset in block.successors:
            blocks[successorOffset].predecessors.add(block.startOffset)
 
 
def buildControlFlowGraph(instructions: List[Dict[str, Any]]) -> Dict[int, BasicBlock]:
    leaders = findLeaders(instructions)
    blocks = splitIntoBlocks(instructions, leaders)
    wireEdges(blocks)
    return blocks
 
 
def printControlFlowGraph(blocks: Dict[int, BasicBlock], methodName: str = "") -> None:
    header = f"CFG for {methodName}" if methodName else "CFG"
    print(f"\n{header}  ({len(blocks)} blocks)")
    for startOffset in sorted(blocks.keys()):
        block = blocks[startOffset]
        print(f"  Block[{block.startOffset}] (ends {block.endOffset}):")
        for instruction in block.instructions:
            operandStr = " ".join(str(operand) for operand in instruction["operands"])
            print(f"      {instruction['offset']:4}: {instruction['mnemonic']} {operandStr}".rstrip())
        if block.isExitBlock:
            print(f"      -> [exit]")
        else:
            print(f"      -> {sorted(block.successors)}")
 
 
if __name__ == "__main__":
    from class_parser import parseClassDirectly
    from disassembler import disassembleMethod
 
    methodBytecodes = parseClassDirectly("EngineMath.class")
    for methodName, methodBytes in methodBytecodes.items():
        parsedInstructions = disassembleMethod(methodName, methodBytes)
        cfg = buildControlFlowGraph(parsedInstructions)
        printControlFlowGraph(cfg, methodName)
