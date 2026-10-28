"""
lifter.py — Phase 2: Symbolic Stack Machine & AST Lifter for NeuroDecomp

Simulates the JVM stack-based execution model symbolically over basic blocks
and lifts structured AST nodes into clean, human-readable Java pseudo-code.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import re

try:
    from javadecompiler.class_parser import (
        ClassInfo,
        MethodInfo,
        resolveRef,
        resolveClass,
        resolveString,
        parseDescriptor,
    )
    from javadecompiler.cfg_builder import BasicBlock, buildControlFlowGraph, resolveBranchTarget
    from javadecompiler.structurer import (
        BlockNode,
        SequenceNode,
        IfElseNode,
        WhileLoopNode,
        UnstructuredNode,
        structureMethod,
    )
except ImportError:
    from class_parser import (
        ClassInfo,
        MethodInfo,
        resolveRef,
        resolveClass,
        resolveString,
        parseDescriptor,
    )
    from cfg_builder import BasicBlock, buildControlFlowGraph, resolveBranchTarget
    from structurer import (
        BlockNode,
        SequenceNode,
        IfElseNode,
        WhileLoopNode,
        UnstructuredNode,
        structureMethod,
    )


def _cleanExpr(expr: str) -> str:
    """Removes redundant outermost parentheses if expression is fully wrapped."""
    expr = expr.strip()
    if expr.startswith("(") and expr.endswith(")"):
        depth = 0
        for i, ch in enumerate(expr):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(expr) - 1:
                    return expr
        return expr[1:-1].strip()
    return expr


def invertCondition(cond: str) -> str:
    """Inverts a boolean comparison condition for fallthrough/branch polarity."""
    cond = cond.strip()
    # Normalize outer parens
    inner = _cleanExpr(cond)
    
    comparisons = [
        (" == ", " != "),
        (" != ", " == "),
        (" <= ", " > "),
        (" >= ", " < "),
        (" < ", " >= "),
        (" > ", " <= "),
    ]
    for orig, inv in comparisons:
        if orig in inner:
            parts = inner.split(orig, 1)
            return f"{parts[0].strip()}{inv}{parts[1].strip()}"
            
    if inner.startswith("!(") and inner.endswith(")"):
        return inner[2:-1].strip()
    return f"!({inner})"


@dataclass
class LifterContext:
    class_name: str
    method_info: MethodInfo
    constant_pool: Dict[int, Any]
    param_map: Dict[int, str] = field(default_factory=dict)
    var_types: Dict[int, str] = field(default_factory=dict)

    @classmethod
    def create(cls, class_info: ClassInfo, method_info: MethodInfo) -> "LifterContext":
        param_map: Dict[int, str] = {}
        slot = 0
        if not method_info.is_static:
            param_map[0] = "this"
            slot = 1

        for i, pType in enumerate(method_info.param_types):
            pName = f"param{i}"
            param_map[slot] = pName
            slot += 2 if pType in ("long", "double") else 1

        return cls(
            class_name=class_info.class_name,
            method_info=method_info,
            constant_pool=class_info.constant_pool,
            param_map=param_map,
        )


@dataclass
class BlockLiftResult:
    start_offset: int
    statements: List[str] = field(default_factory=list)
    condition: Optional[str] = None
    branch_target: Optional[int] = None
    terminator: Optional[str] = None


class StackSimulator:
    """Simulates JVM operand stack and local variable assignments over instructions in a block."""

    def __init__(self, context: LifterContext) -> None:
        self.context = context
        self.stack: List[str] = []
        self.locals: Dict[int, str] = dict(context.param_map)

    def _pop(self) -> str:
        if self.stack:
            return self.stack.pop()
        return "/* stack_underflow */"

    def _push(self, val: str) -> None:
        self.stack.append(val)

    def _getVar(self, slot: int) -> str:
        if slot in self.context.param_map:
            return self.context.param_map[slot]
        return f"var{slot}"

    def liftBlock(self, block: BasicBlock) -> BlockLiftResult:
        statements: List[str] = []
        condition: Optional[str] = None
        branch_target: Optional[int] = None
        terminator: Optional[str] = None
        cp = self.context.constant_pool

        for instruction in block.instructions:
            mnemonic: str = instruction["mnemonic"]
            operands: List[int] = instruction["operands"]
            offset: int = instruction["offset"]

            # --- Constants ---
            if mnemonic == "nop":
                continue
            elif mnemonic == "aconst_null":
                self._push("null")
            elif mnemonic == "iconst_m1":
                self._push("-1")
            elif mnemonic.startswith("iconst_"):
                self._push(mnemonic.split("_")[1])
            elif mnemonic.startswith("lconst_"):
                self._push(f"{mnemonic.split('_')[1]}L")
            elif mnemonic.startswith("fconst_"):
                self._push(f"{float(mnemonic.split('_')[1])}f")
            elif mnemonic.startswith("dconst_"):
                self._push(f"{float(mnemonic.split('_')[1])}")
            elif mnemonic == "bipush":
                val = operands[0] if operands[0] < 128 else operands[0] - 256
                self._push(str(val))
            elif mnemonic == "sipush":
                raw = (operands[0] << 8) | operands[1]
                val = raw if raw < 0x8000 else raw - 0x10000
                self._push(str(val))
            elif mnemonic in ("ldc", "ldc_w", "ldc2_w"):
                idx = operands[0] if mnemonic == "ldc" else ((operands[0] << 8) | operands[1])
                entry = cp.get(idx, {})
                eType = entry.get("type", "")
                if eType == "String":
                    sVal = resolveString(cp, idx)
                    escaped = sVal.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                    self._push(f'"{escaped}"')
                elif eType == "Primitive32":
                    self._push(str(entry.get("value", 0)))
                elif eType == "Primitive64":
                    self._push(f"{entry.get('high', 0)}_{entry.get('low', 0)}")
                elif eType == "Class":
                    cName = resolveClass(cp, idx).replace('/', '.')
                    self._push(f"{cName.split('.')[-1]}.class")
                else:
                    self._push(f"Const_{idx}")

            # --- Loads ---
            elif mnemonic in ("iload", "lload", "fload", "dload", "aload"):
                slot = operands[0]
                self._push(self._getVar(slot))
            elif any(mnemonic.startswith(prefix) for prefix in ("iload_", "lload_", "fload_", "dload_", "aload_")):
                slot = int(mnemonic.split("_")[1])
                self._push(self._getVar(slot))

            # --- Stores ---
            elif mnemonic in ("istore", "lstore", "fstore", "dstore", "astore"):
                slot = operands[0]
                val = self._pop()
                statements.append(f"{self._getVar(slot)} = {val};")
            elif any(mnemonic.startswith(prefix) for prefix in ("istore_", "lstore_", "fstore_", "dstore_", "astore_")):
                slot = int(mnemonic.split("_")[1])
                val = self._pop()
                statements.append(f"{self._getVar(slot)} = {val};")

            # --- Math & Logic ---
            elif mnemonic in ("iadd", "ladd", "fadd", "dadd"):
                b, a = self._pop(), self._pop()
                self._push(f"{a} + {b}")
            elif mnemonic in ("isub", "lsub", "fsub", "dsub"):
                b, a = self._pop(), self._pop()
                self._push(f"{a} - {b}")
            elif mnemonic in ("imul", "lmul", "fmul", "dmul"):
                b, a = self._pop(), self._pop()
                self._push(f"{a} * {b}")
            elif mnemonic in ("idiv", "ldiv", "fdiv", "ddiv"):
                b, a = self._pop(), self._pop()
                self._push(f"{a} / {b}")
            elif mnemonic in ("irem", "lrem", "frem", "drem"):
                b, a = self._pop(), self._pop()
                self._push(f"{a} % {b}")
            elif mnemonic in ("iand", "land"):
                b, a = self._pop(), self._pop()
                self._push(f"({a} & {b})")
            elif mnemonic in ("ior", "lor"):
                b, a = self._pop(), self._pop()
                self._push(f"({a} | {b})")
            elif mnemonic in ("ixor", "lxor"):
                b, a = self._pop(), self._pop()
                self._push(f"({a} ^ {b})")
            elif mnemonic in ("ishl", "lshl"):
                b, a = self._pop(), self._pop()
                self._push(f"({a} << {b})")
            elif mnemonic in ("ishr", "lshr"):
                b, a = self._pop(), self._pop()
                self._push(f"({a} >> {b})")
            elif mnemonic in ("iushr", "lushr"):
                b, a = self._pop(), self._pop()
                self._push(f"({a} >>> {b})")
            elif mnemonic in ("ineg", "lneg", "fneg", "dneg"):
                a = self._pop()
                self._push(f"-{a}")
            elif mnemonic == "iinc":
                slot = operands[0]
                amount = operands[1] if operands[1] < 128 else operands[1] - 256
                varName = self._getVar(slot)
                if amount == 1:
                    statements.append(f"{varName}++;")
                elif amount == -1:
                    statements.append(f"{varName}--;")
                elif amount > 0:
                    statements.append(f"{varName} += {amount};")
                else:
                    statements.append(f"{varName} -= {-amount};")

            # --- Conversions ---
            elif mnemonic in ("i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l", "d2f"):
                t = {"l": "long", "f": "float", "d": "double", "i": "int"}[mnemonic[-1]]
                a = self._pop()
                self._push(f"(({t}) {a})")
            elif mnemonic in ("i2b", "i2c", "i2s"):
                t = {"b": "byte", "c": "char", "s": "short"}[mnemonic[-1]]
                a = self._pop()
                self._push(f"(({t}) {a})")

            # --- Array Operations ---
            elif mnemonic == "newarray":
                typeCode = operands[0]
                tNames = {4: "boolean", 5: "char", 6: "float", 7: "double", 8: "byte", 9: "short", 10: "int", 11: "long"}
                sz = self._pop()
                self._push(f"new {tNames.get(typeCode, 'int')}[{sz}]")
            elif mnemonic == "anewarray":
                idx = (operands[0] << 8) | operands[1]
                cName = resolveClass(cp, idx).replace('/', '.').split('.')[-1]
                sz = self._pop()
                self._push(f"new {cName}[{sz}]")
            elif mnemonic == "arraylength":
                arr = self._pop()
                self._push(f"{arr}.length")
            elif mnemonic in ("iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload"):
                idx = self._pop()
                arr = self._pop()
                self._push(f"{arr}[{idx}]")
            elif mnemonic in ("iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore"):
                val = self._pop()
                idx = self._pop()
                arr = self._pop()
                statements.append(f"{arr}[{idx}] = {val};")

            # --- Stack Manipulation ---
            elif mnemonic == "dup":
                if self.stack:
                    self._push(self.stack[-1])
            elif mnemonic == "dup_x1":
                if len(self.stack) >= 2:
                    v1 = self._pop()
                    v2 = self._pop()
                    self._push(v1)
                    self._push(v2)
                    self._push(v1)
            elif mnemonic == "dup2":
                if self.stack:
                    self._push(self.stack[-1])
            elif mnemonic in ("pop", "pop2"):
                v = self._pop()
                # If popped expression might have side effects (e.g., function call), emit statement
                if "(" in v or "new " in v:
                    statements.append(f"{v};")
            elif mnemonic == "swap":
                if len(self.stack) >= 2:
                    v1 = self._pop()
                    v2 = self._pop()
                    self._push(v1)
                    self._push(v2)

            # --- Fields ---
            elif mnemonic == "getstatic":
                idx = (operands[0] << 8) | operands[1]
                ref = resolveRef(cp, idx)
                cName = ref.get("class", "").replace('/', '.').split('.')[-1]
                fName = ref.get("name", "")
                self._push(f"{cName}.{fName}")
            elif mnemonic == "putstatic":
                idx = (operands[0] << 8) | operands[1]
                ref = resolveRef(cp, idx)
                cName = ref.get("class", "").replace('/', '.').split('.')[-1]
                fName = ref.get("name", "")
                val = self._pop()
                statements.append(f"{cName}.{fName} = {val};")
            elif mnemonic == "getfield":
                idx = (operands[0] << 8) | operands[1]
                ref = resolveRef(cp, idx)
                obj = self._pop()
                self._push(f"{obj}.{ref.get('name', '')}")
            elif mnemonic == "putfield":
                idx = (operands[0] << 8) | operands[1]
                ref = resolveRef(cp, idx)
                val = self._pop()
                obj = self._pop()
                statements.append(f"{obj}.{ref.get('name', '')} = {val};")

            # --- Objects & Invocations ---
            elif mnemonic == "new":
                idx = (operands[0] << 8) | operands[1]
                cName = resolveClass(cp, idx).replace('/', '.').split('.')[-1]
                self._push(f"new {cName}")

            elif mnemonic in ("invokevirtual", "invokespecial", "invokestatic", "invokeinterface"):
                idx = (operands[0] << 8) | operands[1]
                ref = resolveRef(cp, idx)
                rawClass = ref.get("class", "").replace('/', '.')
                simpleClass = rawClass.split('.')[-1] if rawClass else ""
                mName = ref.get("name", "")
                desc = ref.get("descriptor", "")
                pTypes, retType = parseDescriptor(desc)

                args = []
                for _ in range(len(pTypes)):
                    args.append(self._pop())
                args.reverse()

                if mnemonic == "invokestatic":
                    target = simpleClass or rawClass
                    callExpr = f"{target}.{mName}({', '.join(args)})"
                    if retType == "void":
                        statements.append(f"{callExpr};")
                    else:
                        self._push(callExpr)
                else:
                    obj = self._pop()
                    if mName == "<init>":
                        if obj.startswith("new "):
                            callExpr = f"{obj}({', '.join(args)})"
                            # Standard JVM new/dup/<init> pattern:
                            if self.stack and self.stack[-1] == obj:
                                self.stack[-1] = callExpr
                            else:
                                statements.append(f"{callExpr};")
                        elif obj == "this":
                            statements.append(f"super({', '.join(args)});")
                        else:
                            statements.append(f"{obj}.super({', '.join(args)});")
                    else:
                        callExpr = f"{obj}.{mName}({', '.join(args)})"
                        if retType == "void":
                            statements.append(f"{callExpr};")
                        else:
                            self._push(callExpr)

            # --- Returns & Terminators ---
            elif mnemonic in ("ireturn", "lreturn", "freturn", "dreturn", "areturn"):
                retVal = self._pop()
                statements.append(f"return {retVal};")
                terminator = mnemonic
            elif mnemonic == "return":
                # For void methods, only emit return if there was prior code or explicit return path
                statements.append("return;")
                terminator = mnemonic
            elif mnemonic == "athrow":
                ex = self._pop()
                statements.append(f"throw {ex};")
                terminator = mnemonic

            # --- Comparisons & Jumps ---
            elif mnemonic in ("lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg"):
                b, a = self._pop(), self._pop()
                self._push(f"compare({a}, {b})")

            elif mnemonic in ("ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "ifnull", "ifnonnull"):
                a = self._pop()
                opMap = {
                    "ifeq": " == 0",
                    "ifne": " != 0",
                    "iflt": " < 0",
                    "ifge": " >= 0",
                    "ifgt": " > 0",
                    "ifle": " <= 0",
                    "ifnull": " == null",
                    "ifnonnull": " != null",
                }
                condition = f"{a}{opMap[mnemonic]}"
                branch_target = resolveBranchTarget(instruction)
                terminator = mnemonic

            elif mnemonic in ("if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne"):
                b = self._pop()
                a = self._pop()
                opMap = {
                    "if_icmpeq": " == ",
                    "if_icmpne": " != ",
                    "if_icmplt": " < ",
                    "if_icmpge": " >= ",
                    "if_icmpgt": " > ",
                    "if_icmple": " <= ",
                    "if_acmpeq": " == ",
                    "if_acmpne": " != ",
                }
                condition = f"{a}{opMap[mnemonic]}{b}"
                branch_target = resolveBranchTarget(instruction)
                terminator = mnemonic

            elif mnemonic in ("goto", "goto_w"):
                branch_target = resolveBranchTarget(instruction)
                terminator = mnemonic

        return BlockLiftResult(
            start_offset=block.startOffset,
            statements=statements,
            condition=condition,
            branch_target=branch_target,
            terminator=terminator,
        )


def _renderStructuredNode(
    node: Any,
    lifted_blocks: Dict[int, BlockLiftResult],
    indent: int = 1,
    loop_context: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Recursively formats structured AST nodes into clean pseudo-code lines."""
    pad = "    " * indent
    lines: List[str] = []

    if isinstance(node, SequenceNode):
        for child in node.nodes:
            lines.extend(_renderStructuredNode(child, lifted_blocks, indent, loop_context))

    elif isinstance(node, BlockNode):
        res = lifted_blocks.get(node.block.startOffset)
        if res:
            for stmt in res.statements:
                # Omit synthetic return in constructors or at the very end of void methods
                lines.append(f"{pad}{stmt}")

    elif isinstance(node, IfElseNode):
        res = lifted_blocks.get(node.conditionBlock.startOffset)
        if res:
            for stmt in res.statements:
                lines.append(f"{pad}{stmt}")

            cond = res.condition or "true"
            # Note on branch polarity in JVM:
            # Jumping to branch_target occurs when condition is TRUE.
            # In structurer.py:
            # fallthrough is assigned to thenBranch, branchTarget is assigned to elseBranch.
            # Therefore, entering thenBranch requires INVERTING the jump condition!
            effectiveCond = invertCondition(cond)

            lines.append(f"{pad}if ({effectiveCond}) {{")
            thenLines = _renderStructuredNode(node.thenBranch, lifted_blocks, indent + 1, loop_context)
            lines.extend(thenLines)

            if node.elseBranch is not None:
                lines.append(f"{pad}}} else {{")
                elseLines = _renderStructuredNode(node.elseBranch, lifted_blocks, indent + 1, loop_context)
                lines.extend(elseLines)
            lines.append(f"{pad}}}")

    elif isinstance(node, WhileLoopNode):
        res = lifted_blocks.get(node.conditionBlock.startOffset)
        if res:
            for stmt in res.statements:
                lines.append(f"{pad}{stmt}")

            cond = res.condition or "true"
            # In JVM while loops, the condition block branches to EXIT when condition is met,
            # and falls through into the loop body.
            # Therefore, staying in the body requires INVERTING the condition test!
            effectiveCond = invertCondition(cond)

            lines.append(f"{pad}while ({effectiveCond}) {{")
            curLoop = {"header": node.conditionBlock.startOffset}
            bodyLines = _renderStructuredNode(node.body, lifted_blocks, indent + 1, curLoop)
            lines.extend(bodyLines)
            lines.append(f"{pad}}}")

    elif isinstance(node, UnstructuredNode):
        res = lifted_blocks.get(node.block.startOffset)
        if res:
            for stmt in res.statements:
                lines.append(f"{pad}{stmt}")
        lines.append(f"{pad}/* Fallback jump: offset {node.block.startOffset} ({node.reason}) */")

    return lines


def liftMethod(
    class_info: ClassInfo,
    method_name: str,
    method_info: Optional[MethodInfo] = None,
) -> str:
    """Entry point: decompiles a single method into Phase 2 lifted pseudo-code."""
    if method_info is None:
        method_info = class_info.methods[method_name]

    if not method_info.bytecode:
        # Abstract or native method
        sig = _formatMethodSignature(class_info, method_info)
        return f"{sig};"

    try:
        from javadecompiler.disassembler import disassembleMethod
    except ImportError:
        from disassembler import disassembleMethod
    instructions = disassembleMethod(method_name, method_info.bytecode)
    cfg = buildControlFlowGraph(instructions)
    tree = structureMethod(cfg)

    context = LifterContext.create(class_info, method_info)
    simulator = StackSimulator(context)

    # Simulate and lift each basic block in the CFG
    lifted_blocks: Dict[int, BlockLiftResult] = {}
    for offset, block in cfg.items():
        # Fresh simulator per block (in basic blocks stack depth resets or flows cleanly)
        blockSim = StackSimulator(context)
        lifted_blocks[offset] = blockSim.liftBlock(block)

    bodyLines = _renderStructuredNode(tree, lifted_blocks, indent=1)

    # Clean up redundant final 'return;' in void methods
    if method_info.return_type == "void" and bodyLines and bodyLines[-1].strip() == "return;":
        bodyLines.pop()

    sig = _formatMethodSignature(class_info, method_info)
    code = f"{sig} {{\n" + "\n".join(bodyLines) + "\n}"
    return code


def _formatMethodSignature(class_info: ClassInfo, method_info: MethodInfo) -> str:
    parts = []
    # Access modifiers
    flags = method_info.access_flags
    if flags & 0x0001:
        parts.append("public")
    elif flags & 0x0002:
        parts.append("private")
    elif flags & 0x0004:
        parts.append("protected")

    if method_info.is_static:
        parts.append("static")

    if flags & 0x0010:
        parts.append("final")

    if method_info.name == "<init>":
        simpleName = class_info.class_name.split('/')[-1].split('.')[-1]
        parts.append(simpleName)
    else:
        parts.append(method_info.return_type)
        parts.append(method_info.name)

    # Parameters
    paramList = []
    for i, pType in enumerate(method_info.param_types):
        paramList.append(f"{pType} param{i}")

    head = " ".join(parts)
    return f"{head}({', '.join(paramList)})"


def liftClass(class_info: ClassInfo) -> Dict[str, str]:
    """Decompiles all methods in a class into Phase 2 lifted pseudo-code."""
    results: Dict[str, str] = {}
    for mName, mInfo in class_info.methods.items():
        try:
            results[mName] = liftMethod(class_info, mName, mInfo)
        except Exception as e:
            results[mName] = f"// Error lifting {mName}: {e}"
    return results
