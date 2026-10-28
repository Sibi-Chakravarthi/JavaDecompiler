import struct
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
    """Resolves branch target offset from decoded instruction or raw operands."""
    if "target" in instruction and instruction["target"] is not None:
        return instruction["target"]

    mnemonic: str = instruction["mnemonic"]
    if mnemonic not in conditionalJumpMnemonics and mnemonic not in unconditionalJumpMnemonics:
        return None

    operands: List[int] = instruction["operands"]
    if len(operands) == 4:
        rawOffset = struct.unpack(">i", bytes(operands))[0]
        return instruction["offset"] + rawOffset
    elif len(operands) == 2:
        rawOffset = struct.unpack(">h", bytes(operands))[0]
        return instruction["offset"] + rawOffset

    return None


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


def findLeaders(
    instructions: List[Dict[str, Any]],
    exception_handlers: Optional[List[Dict[str, int]]] = None,
) -> Set[int]:
    if not instructions:
        return set()

    instruction_offsets: Set[int] = {instr["offset"] for instr in instructions}
    leaders: Set[int] = {instructions[0]["offset"]}

    for index, instruction in enumerate(instructions):
        mnemonic: str = instruction["mnemonic"]

        if mnemonic in branchMnemonics:
            target = resolveBranchTarget(instruction)
            if target is not None and target in instruction_offsets:
                leaders.add(target)

        if mnemonic in switchMnemonics:
            default_target = instruction.get("defaultTarget")
            if default_target is not None and default_target in instruction_offsets:
                leaders.add(default_target)
            for t in instruction.get("targets", []):
                if t in instruction_offsets:
                    leaders.add(t)

        if mnemonic in terminatorMnemonics and index + 1 < len(instructions):
            leaders.add(instructions[index + 1]["offset"])

    # Include exception handler entry points and protected ranges as leaders
    if exception_handlers:
        for handler in exception_handlers:
            start_pc = handler.get("start_pc")
            end_pc = handler.get("end_pc")
            handler_pc = handler.get("handler_pc")

            if start_pc is not None and start_pc in instruction_offsets:
                leaders.add(start_pc)
            if end_pc is not None and end_pc in instruction_offsets:
                leaders.add(end_pc)
            if handler_pc is not None and handler_pc in instruction_offsets:
                leaders.add(handler_pc)

    return leaders


def splitIntoBlocks(instructions: List[Dict[str, Any]], leaders: Set[int]) -> Dict[int, BasicBlock]:
    blocks: Dict[int, BasicBlock] = {}
    if not instructions:
        return blocks

    currentBlock: Optional[BasicBlock] = None

    for instruction in instructions:
        if instruction["offset"] in leaders:
            currentBlock = BasicBlock(startOffset=instruction["offset"])
            blocks[currentBlock.startOffset] = currentBlock
        if currentBlock is not None:
            currentBlock.instructions.append(instruction)

    return blocks


def wireEdges(
    blocks: Dict[int, BasicBlock],
    exception_handlers: Optional[List[Dict[str, int]]] = None,
) -> None:
    sortedStarts: List[int] = sorted(blocks.keys())

    for position, startOffset in enumerate(sortedStarts):
        block = blocks[startOffset]
        if not block.instructions:
            continue
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
            default_target = lastInstruction.get("defaultTarget")
            if default_target is not None and default_target in blocks:
                block.successors.add(default_target)
            for target in lastInstruction.get("targets", []):
                if target in blocks:
                    block.successors.add(target)

        if fallsThrough(mnemonic) and position + 1 < len(sortedStarts):
            block.successors.add(sortedStarts[position + 1])

    # Wire exception handler edges from protected blocks to catch handler entry blocks
    if exception_handlers:
        for handler in exception_handlers:
            start_pc = handler.get("start_pc", 0)
            end_pc = handler.get("end_pc", 0)
            handler_pc = handler.get("handler_pc")

            if handler_pc is not None and handler_pc in blocks:
                for startOffset, block in blocks.items():
                    if start_pc <= startOffset < end_pc:
                        block.successors.add(handler_pc)

    for block in blocks.values():
        for successorOffset in block.successors:
            if successorOffset in blocks:
                blocks[successorOffset].predecessors.add(block.startOffset)


def buildControlFlowGraph(
    instructions: List[Dict[str, Any]],
    exception_handlers: Optional[List[Dict[str, int]]] = None,
) -> Dict[int, BasicBlock]:
    leaders = findLeaders(instructions, exception_handlers)
    blocks = splitIntoBlocks(instructions, leaders)
    wireEdges(blocks, exception_handlers)
    return blocks


def printControlFlowGraphToString(blocks: Dict[int, BasicBlock], methodName: str = "") -> str:
    header = f"CFG for {methodName}" if methodName else "CFG"
    lines = [f"\n{header}  ({len(blocks)} blocks)"]
    for startOffset in sorted(blocks.keys()):
        block = blocks[startOffset]
        lines.append(f"  Block[{block.startOffset}] (ends {block.endOffset}):")
        for instruction in block.instructions:
            operandStr = " ".join(str(operand) for operand in instruction["operands"])
            lines.append(f"      {instruction['offset']:4}: {instruction['mnemonic']} {operandStr}".rstrip())
        if block.isExitBlock:
            lines.append(f"      -> [exit]")
        else:
            lines.append(f"      -> {sorted(block.successors)}")
    return "\n".join(lines)


def printControlFlowGraph(blocks: Dict[int, BasicBlock], methodName: str = "") -> None:
    print(printControlFlowGraphToString(blocks, methodName))


if __name__ == "__main__":
    from class_parser import parseClassDirectly
    from disassembler import disassembleMethod

    methodBytecodes = parseClassDirectly("EngineMath.class")
    for methodName, methodBytes in methodBytecodes.items():
        parsedInstructions = disassembleMethod(methodName, methodBytes)
        cfg = buildControlFlowGraph(parsedInstructions)
        printControlFlowGraph(cfg, methodName)
