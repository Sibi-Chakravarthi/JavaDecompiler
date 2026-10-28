from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from javadecompiler.cfg_builder import BasicBlock, resolveBranchTarget, switchMnemonics
except ImportError:
    from cfg_builder import BasicBlock, resolveBranchTarget, switchMnemonics

def computeDominators(blocks: Dict[int, BasicBlock], entryOffset: int) -> Dict[int, Set[int]]:
    allOffsets: List[int] = list(blocks.keys())
    dominators: Dict[int, Set[int]] = {offset: set(allOffsets) for offset in allOffsets}
    dominators[entryOffset] = {entryOffset}

    changed = True
    while changed:
        changed = False
        for offset in allOffsets:
            if offset == entryOffset:
                continue
            predecessors = blocks[offset].predecessors
            if not predecessors:
                continue

            newDominatorSet: Optional[Set[int]] = None
            for predecessorOffset in predecessors:
                if newDominatorSet is None:
                    newDominatorSet = set(dominators[predecessorOffset])
                else:
                    newDominatorSet &= dominators[predecessorOffset]

            newDominatorSet = newDominatorSet if newDominatorSet is not None else set()
            newDominatorSet.add(offset)

            if newDominatorSet != dominators[offset]:
                dominators[offset] = newDominatorSet
                changed = True

    return dominators

def naturalLoopBody(blocks: Dict[int, BasicBlock], backEdgeSource: int, header: int) -> Set[int]:
    loopBody: Set[int] = {header, backEdgeSource}
    worklist: List[int] = [backEdgeSource]

    while worklist:
        current = worklist.pop()
        for predecessorOffset in blocks[current].predecessors:
            if predecessorOffset not in loopBody:
                loopBody.add(predecessorOffset)
                worklist.append(predecessorOffset)

    return loopBody


def identifyLoops(blocks: Dict[int, BasicBlock], dominators: Dict[int, Set[int]]) -> Dict[int, Dict[str, Any]]:
    loops: Dict[int, Dict[str, Any]] = {}

    for offset, block in blocks.items():
        for successorOffset in block.successors:
            if successorOffset in dominators[offset]:
                header = successorOffset
                body = naturalLoopBody(blocks, offset, header)

                bodyEntry: Optional[int] = None
                exitTarget: Optional[int] = None
                for headerSuccessor in blocks[header].successors:
                    if headerSuccessor in body and headerSuccessor != header:
                        bodyEntry = headerSuccessor
                    elif headerSuccessor not in body:
                        exitTarget = headerSuccessor

                loops[header] = {
                    "body": body,
                    "bodyEntry": bodyEntry,
                    "exitTarget": exitTarget,
                    "backEdgeSource": offset,
                }

    return loops

def findMergePoint(
    blocks: Dict[int, BasicBlock],
    offsetA: int,
    offsetB: int,
    branchOffset: int = 0,
    backEdges: Optional[Set[Tuple[int, int]]] = None,
) -> Optional[int]:
    if offsetA == offsetB:
        return offsetA

    visitedA: Set[int] = {offsetA}
    visitedB: Set[int] = {offsetB}
    frontierA: Set[int] = {offsetA}
    frontierB: Set[int] = {offsetB}
    backEdges = backEdges or set()

    common = (visitedA & visitedB)
    valid_common = [c for c in common if c > branchOffset]
    if valid_common:
        return min(valid_common)

    steps = 0
    while (frontierA or frontierB) and steps < 100:
        steps += 1
        if frontierA:
            new_fA: Set[int] = set()
            for node in frontierA:
                if node not in blocks:
                    continue
                for successor in blocks[node].successors:
                    if (node, successor) in backEdges or successor <= branchOffset:
                        continue
                    if successor not in visitedA:
                        visitedA.add(successor)
                        new_fA.add(successor)
            frontierA = new_fA
            common = visitedA & visitedB
            valid_common = [c for c in common if c > branchOffset]
            if valid_common:
                return min(valid_common)

        if frontierB:
            new_fB: Set[int] = set()
            for node in frontierB:
                if node not in blocks:
                    continue
                for successor in blocks[node].successors:
                    if (node, successor) in backEdges or successor <= branchOffset:
                        continue
                    if successor not in visitedB:
                        visitedB.add(successor)
                        new_fB.add(successor)
            frontierB = new_fB
            common = visitedA & visitedB
            valid_common = [c for c in common if c > branchOffset]
            if valid_common:
                return min(valid_common)

    return None


def _isTerminatingPath(
    blocks: Dict[int, BasicBlock],
    startOffset: int,
    backEdges: Set[Tuple[int, int]],
    maxSteps: int = 15,
) -> bool:
    """Checks if path from startOffset only reaches terminal blocks without loops or escaping."""
    visited: Set[int] = set()
    frontier: Set[int] = {startOffset}
    steps = 0
    while frontier and steps < maxSteps:
        steps += 1
        new_frontier: Set[int] = set()
        for node in frontier:
            visited.add(node)
            block = blocks.get(node)
            if not block or not block.successors:
                # Terminal block (e.g. return, athrow)
                continue
            for succ in block.successors:
                if (node, succ) in backEdges:
                    return False
                if succ not in visited:
                    new_frontier.add(succ)
        frontier = new_frontier

    return len(frontier) == 0


@dataclass
class BlockNode:
    block: BasicBlock


@dataclass
class SequenceNode:
    nodes: List[Any]


@dataclass
class IfElseNode:
    conditionBlock: BasicBlock
    thenBranch: Any
    elseBranch: Optional[Any]


@dataclass
class WhileLoopNode:
    conditionBlock: BasicBlock
    body: Any


@dataclass
class UnstructuredNode:
    block: BasicBlock
    reason: str


def structureRegion(
    blocks: Dict[int, BasicBlock],
    currentOffset: Optional[int],
    stopOffset: Optional[int],
    loops: Dict[int, Dict[str, Any]],
    _callStack: Optional[Set[Any]] = None,
    _depth: int = 0,
    _budget: Optional[List[int]] = None,
    backEdges: Optional[Set[Tuple[int, int]]] = None,
) -> Any:
    if _budget is None:
        _budget = [1000]

    if _budget[0] <= 0 or _depth > 30:
        block = blocks.get(currentOffset) if currentOffset is not None else None
        if block is not None:
            return UnstructuredNode(block, "control-flow structuring complexity budget exceeded")
        return SequenceNode([])

    if _callStack is None:
        _callStack = set()

    regionKey = (currentOffset, stopOffset)
    if regionKey in _callStack:
        block = blocks.get(currentOffset)
        if block is not None:
            return UnstructuredNode(
                block,
                f"control-flow cycle detected structuring region ({currentOffset} -> {stopOffset}); "
                f"likely a loop shape with >2 effective successors that this algorithm doesn't model yet",
            )
        return SequenceNode([])
    _callStack = _callStack | {regionKey}

    sequenceNodes: List[Any] = []
    visitedInThisRegion: Set[int] = set()

    while currentOffset is not None and currentOffset != stopOffset and _budget[0] > 0:
        if currentOffset in visitedInThisRegion:
            break 
        visitedInThisRegion.add(currentOffset)
        _budget[0] -= 1

        block = blocks[currentOffset]
        lastMnemonic = block.instructions[-1]["mnemonic"] if block.instructions else ""

        if currentOffset in loops:
            loopInfo = loops[currentOffset]
            if loopInfo["bodyEntry"] is not None:
                bodyNode = structureRegion(
                    blocks, loopInfo["bodyEntry"], currentOffset, loops, _callStack,
                    _depth=_depth + 1, _budget=_budget, backEdges=backEdges
                )
            else:
                bodyNode = SequenceNode([])
            sequenceNodes.append(WhileLoopNode(conditionBlock=block, body=bodyNode))
            currentOffset = loopInfo["exitTarget"]
            continue

        if lastMnemonic in switchMnemonics:
            sequenceNodes.append(UnstructuredNode(block, "switch/tableswitch not yet decoded by disassembler.py"))
            currentOffset = None
            continue

        if len(block.successors) == 2:
            branchTarget = resolveBranchTarget(block.instructions[-1])
            fallthroughOffsets = [s for s in block.successors if s != branchTarget]
            thenOffset = fallthroughOffsets[0] if fallthroughOffsets else sorted(block.successors)[0]
            elseOffset = branchTarget if branchTarget in block.successors else sorted(block.successors)[1]

            mergeOffset = findMergePoint(
                blocks, thenOffset, elseOffset,
                branchOffset=currentOffset, backEdges=backEdges
            )

            if mergeOffset is not None:
                thenNode = structureRegion(
                    blocks, thenOffset, mergeOffset, loops, _callStack,
                    _depth=_depth + 1, _budget=_budget, backEdges=backEdges
                )
                elseNode = None if elseOffset == mergeOffset else structureRegion(
                    blocks, elseOffset, mergeOffset, loops, _callStack,
                    _depth=_depth + 1, _budget=_budget, backEdges=backEdges
                )

                sequenceNodes.append(IfElseNode(conditionBlock=block, thenBranch=thenNode, elseBranch=elseNode))
                currentOffset = mergeOffset
                continue
            else:
                # Early return guard pattern check: if one branch terminates early,
                # the other branch is the linear continuation of the method!
                thenTerm = _isTerminatingPath(blocks, thenOffset, backEdges or set())
                elseTerm = _isTerminatingPath(blocks, elseOffset, backEdges or set())

                if thenTerm and not elseTerm:
                    thenNode = structureRegion(
                        blocks, thenOffset, None, loops, _callStack,
                        _depth=_depth + 1, _budget=_budget, backEdges=backEdges
                    )
                    sequenceNodes.append(IfElseNode(conditionBlock=block, thenBranch=thenNode, elseBranch=None))
                    currentOffset = elseOffset
                    continue
                elif elseTerm and not thenTerm:
                    elseNode = structureRegion(
                        blocks, elseOffset, None, loops, _callStack,
                        _depth=_depth + 1, _budget=_budget, backEdges=backEdges
                    )
                    sequenceNodes.append(IfElseNode(conditionBlock=block, thenBranch=None, elseBranch=elseNode))
                    currentOffset = thenOffset
                    continue
                else:
                    sequenceNodes.append(UnstructuredNode(block, "unmerged branch bifurcation"))
                    currentOffset = None
                    continue

        sequenceNodes.append(BlockNode(block))
        currentOffset = next(iter(block.successors)) if len(block.successors) == 1 else None

    if len(sequenceNodes) == 1:
        return sequenceNodes[0]
    return SequenceNode(sequenceNodes)


def structureMethod(blocks: Dict[int, BasicBlock]) -> Any:
    """Entry point: builds the full structured tree for one method's CFG."""
    if not blocks:
        return SequenceNode([])
    entryOffset = min(blocks.keys())
    dominators = computeDominators(blocks, entryOffset)
    loops = identifyLoops(blocks, dominators)

    # Compute set of back-edges (node -> succ where succ dominates node)
    backEdges: Set[Tuple[int, int]] = set()
    for offset, block in blocks.items():
        dom_set = dominators.get(offset, set())
        for succ in block.successors:
            if succ in dom_set:
                backEdges.add((offset, succ))

    return structureRegion(blocks, entryOffset, None, loops, backEdges=backEdges)

def _formatInstruction(instruction: Dict[str, Any]) -> str:
    operandStr = " ".join(str(operand) for operand in instruction["operands"])
    return f"{instruction['mnemonic']} {operandStr}".rstrip()


def renderPseudocode(node: Any, indent: int = 0) -> List[str]:
    pad = "    " * indent
    lines: List[str] = []

    if isinstance(node, SequenceNode):
        for child in node.nodes:
            lines.extend(renderPseudocode(child, indent))

    elif isinstance(node, BlockNode):
        for instruction in node.block.instructions:
            lines.append(f"{pad}{_formatInstruction(instruction)}")

    elif isinstance(node, IfElseNode):
        for instruction in node.conditionBlock.instructions[:-1]:
            lines.append(f"{pad}{_formatInstruction(instruction)}")
        testMnemonic = node.conditionBlock.instructions[-1]["mnemonic"]
        lines.append(f"{pad}if (<{testMnemonic} test — see module docstring on polarity>) {{")
        lines.extend(renderPseudocode(node.thenBranch, indent + 1))
        if node.elseBranch is not None:
            lines.append(f"{pad}}} else {{")
            lines.extend(renderPseudocode(node.elseBranch, indent + 1))
        lines.append(f"{pad}}}")

    elif isinstance(node, WhileLoopNode):
        for instruction in node.conditionBlock.instructions[:-1]:
            lines.append(f"{pad}{_formatInstruction(instruction)}")
        testMnemonic = node.conditionBlock.instructions[-1]["mnemonic"]
        lines.append(f"{pad}while (<{testMnemonic} test>) {{")
        lines.extend(renderPseudocode(node.body, indent + 1))
        lines.append(f"{pad}}}")

    elif isinstance(node, UnstructuredNode):
        lines.append(f"{pad}/* UNSTRUCTURED @ offset {node.block.startOffset}: {node.reason} */")

    return lines


def nodeToDict(node: Any) -> Dict[str, Any]:
    if isinstance(node, SequenceNode):
        return {"kind": "sequence", "nodes": [nodeToDict(child) for child in node.nodes]}

    if isinstance(node, BlockNode):
        return {
            "kind": "block",
            "startOffset": node.block.startOffset,
            "instructions": node.block.instructions,
        }

    if isinstance(node, IfElseNode):
        return {
            "kind": "if_else",
            "conditionOffset": node.conditionBlock.startOffset,
            "conditionInstructions": node.conditionBlock.instructions,
            "then": nodeToDict(node.thenBranch),
            "else": nodeToDict(node.elseBranch) if node.elseBranch is not None else None,
        }

    if isinstance(node, WhileLoopNode):
        return {
            "kind": "while",
            "conditionOffset": node.conditionBlock.startOffset,
            "conditionInstructions": node.conditionBlock.instructions,
            "body": nodeToDict(node.body),
        }

    if isinstance(node, UnstructuredNode):
        return {
            "kind": "unstructured",
            "startOffset": node.block.startOffset,
            "reason": node.reason,
            "instructions": node.block.instructions,
        }

    raise TypeError(f"Unknown structured node type: {type(node)!r}")


if __name__ == "__main__":
    import json

    from class_parser import parseClassDirectly
    from disassembler import disassembleMethod
    from cfg_builder import buildControlFlowGraph

    for classFile in ("EngineMath.class", "LoopTest.class"):
        methodBytecodes = parseClassDirectly(classFile)
        for methodName, methodBytes in methodBytecodes.items():
            instructions = disassembleMethod(methodName, methodBytes)
            cfg = buildControlFlowGraph(instructions)
            tree = structureMethod(cfg)

            print(f"\n=== {classFile} :: {methodName} ===")
            print("\n".join(renderPseudocode(tree)))

        if classFile == "LoopTest.class":
            methodBytecodes = parseClassDirectly(classFile)
            instructions = disassembleMethod("sumUpTo", methodBytecodes["sumUpTo"])
            cfg = buildControlFlowGraph(instructions)
            tree = structureMethod(cfg)
            print("\n=== sumUpTo :: JSON hand-off shape ===")
            print(json.dumps(nodeToDict(tree), indent=2))
