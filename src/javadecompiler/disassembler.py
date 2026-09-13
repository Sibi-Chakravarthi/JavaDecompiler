from typing import List, Tuple, Dict

jvmOpcodes: Dict[int, Tuple[str, int]] = {

    # --- Constants ---

    0x00: ("nop", 0),

    0x01: ("aconst_null", 0),
    0x02: ("iconst_m1", 0),    # Push int constant -1
    0x03: ("iconst_0", 0),     # Push int constant 0
    0x04: ("iconst_1", 0),     # Push int constant 1
    0x05: ("iconst_2", 0),     # Push int constant 2
    0x06: ("iconst_3", 0),     # Push int constant 3
    0x07: ("iconst_4", 0),     # Push int constant 4
    0x08: ("iconst_5", 0),     # Push int constant 5
    0x09: ("lconst_0", 0),
    0x0a: ("lconst_1", 0),
    0x0b: ("fconst_0", 0),
    0x0c: ("fconst_1", 0),
    0x0d: ("fconst_2", 0),
    0x0e: ("dconst_0", 0),
    0x0f: ("dconst_1", 0),
    0x10: ("bipush", 1),       # Push byte
    0x11: ("sipush", 2),       # Push short
    0x12: ("ldc", 1),          # Load constant
    0x13: ("ldc_w", 2),        # Load constant, wide index
    0x14: ("ldc2_w", 2),       # Load long/double constant, wide index

    # --- Loads ---

    0x15: ("iload", 1),
    0x16: ("lload", 1),
    0x17: ("fload", 1),
    0x18: ("dload", 1),
    0x19: ("aload", 1),
    0x1a: ("iload_0", 0), 0x1b: ("iload_1", 0), 0x1c: ("iload_2", 0), 0x1d: ("iload_3", 0),
    0x1e: ("lload_0", 0), 0x1f: ("lload_1", 0), 0x20: ("lload_2", 0), 0x21: ("lload_3", 0),
    0x22: ("fload_0", 0), 0x23: ("fload_1", 0), 0x24: ("fload_2", 0), 0x25: ("fload_3", 0),
    0x26: ("dload_0", 0), 0x27: ("dload_1", 0), 0x28: ("dload_2", 0), 0x29: ("dload_3", 0),
    0x2a: ("aload_0", 0), 0x2b: ("aload_1", 0), 0x2c: ("aload_2", 0), 0x2d: ("aload_3", 0),
    0x2e: ("iaload", 0), 0x2f: ("laload", 0), 0x30: ("faload", 0), 0x31: ("daload", 0),
    0x32: ("aaload", 0), 0x33: ("baload", 0), 0x34: ("caload", 0), 0x35: ("saload", 0),

    # --- Stores ---

    0x36: ("istore", 1),
    0x37: ("lstore", 1),
    0x38: ("fstore", 1),
    0x39: ("dstore", 1),
    0x3a: ("astore", 1),
    0x3b: ("istore_0", 0), 0x3c: ("istore_1", 0), 0x3d: ("istore_2", 0), 0x3e: ("istore_3", 0),
    0x3f: ("lstore_0", 0), 0x40: ("lstore_1", 0), 0x41: ("lstore_2", 0), 0x42: ("lstore_3", 0),
    0x43: ("fstore_0", 0), 0x44: ("fstore_1", 0), 0x45: ("fstore_2", 0), 0x46: ("fstore_3", 0),
    0x47: ("dstore_0", 0), 0x48: ("dstore_1", 0), 0x49: ("dstore_2", 0), 0x4a: ("dstore_3", 0),
    0x4b: ("astore_0", 0), 0x4c: ("astore_1", 0), 0x4d: ("astore_2", 0), 0x4e: ("astore_3", 0),
    0x4f: ("iastore", 0), 0x50: ("lastore", 0), 0x51: ("fastore", 0), 0x52: ("dastore", 0),
    0x53: ("aastore", 0), 0x54: ("bastore", 0), 0x55: ("castore", 0), 0x56: ("sastore", 0),

    # --- Stack ---

    0x57: ("pop", 0),
    0x58: ("pop2", 0),
    0x59: ("dup", 0),
    0x5a: ("dup_x1", 0),
    0x5b: ("dup_x2", 0),
    0x5c: ("dup2", 0),
    0x5d: ("dup2_x1", 0),
    0x5e: ("dup2_x2", 0),
    0x5f: ("swap", 0),

    # --- Arithmetic ---

    0x60: ("iadd", 0), 0x61: ("ladd", 0), 0x62: ("fadd", 0), 0x63: ("dadd", 0),
    0x64: ("isub", 0), 0x65: ("lsub", 0), 0x66: ("fsub", 0), 0x67: ("dsub", 0),
    0x68: ("imul", 0), 0x69: ("lmul", 0), 0x6a: ("fmul", 0), 0x6b: ("dmul", 0),
    0x6c: ("idiv", 0), 0x6d: ("ldiv", 0), 0x6e: ("fdiv", 0), 0x6f: ("ddiv", 0),
    0x70: ("irem", 0), 0x71: ("lrem", 0), 0x72: ("frem", 0), 0x73: ("drem", 0),
    0x74: ("ineg", 0), 0x75: ("lneg", 0), 0x76: ("fneg", 0), 0x77: ("dneg", 0),
    0x78: ("ishl", 0), 0x79: ("lshl", 0), 0x7a: ("ishr", 0), 0x7b: ("lshr", 0),
    0x7c: ("iushr", 0), 0x7d: ("lushr", 0),
    0x7e: ("iand", 0), 0x7f: ("land", 0), 0x80: ("ior", 0), 0x81: ("lor", 0),
    0x82: ("ixor", 0), 0x83: ("lxor", 0),
    0x84: ("iinc", 2),         # Increment local variable by constant

    # --- Type conversions ---

    0x85: ("i2l", 0), 0x86: ("i2f", 0), 0x87: ("i2d", 0),
    0x88: ("l2i", 0), 0x89: ("l2f", 0), 0x8a: ("l2d", 0),
    0x8b: ("f2i", 0), 0x8c: ("f2l", 0), 0x8d: ("f2d", 0),
    0x8e: ("d2i", 0), 0x8f: ("d2l", 0), 0x90: ("d2f", 0),
    0x91: ("i2b", 0), 0x92: ("i2c", 0), 0x93: ("i2s", 0),

    # --- Comparisons ---

    0x94: ("lcmp", 0), 0x95: ("fcmpl", 0), 0x96: ("fcmpg", 0),
    0x97: ("dcmpl", 0), 0x98: ("dcmpg", 0),

    # --- Conditional / unconditional branches ---

    0x99: ("ifeq", 2), 0x9a: ("ifne", 2), 0x9b: ("iflt", 2),
    0x9c: ("ifge", 2), 0x9d: ("ifgt", 2), 0x9e: ("ifle", 2),
    0x9f: ("if_icmpeq", 2), 0xa0: ("if_icmpne", 2), 0xa1: ("if_icmplt", 2),
    0xa2: ("if_icmpge", 2), 0xa3: ("if_icmpgt", 2), 0xa4: ("if_icmple", 2),
    0xa5: ("if_acmpeq", 2), 0xa6: ("if_acmpne", 2),
    0xa7: ("goto", 2),
    0xc6: ("ifnull", 2), 0xc7: ("ifnonnull", 2),
    # NOTE: goto_w (0xc8) and jsr_w/jsr/ret (0xa8, 0xa9, 0xc9) deliberately
    # excluded — goto_w uses a 4-byte signed offset, and resolveBranchTarget
    # in cfg_builder.py currently assumes 2-byte branches everywhere. Adding
    # goto_w here without also updating that assumption would parse the
    # opcode but resolve its target wrong. Flag for whoever does that work.

    # --- Returns ---

    0xac: ("ireturn", 0), 0xad: ("lreturn", 0), 0xae: ("freturn", 0),
    0xaf: ("dreturn", 0), 0xb0: ("areturn", 0), 0xb1: ("return", 0),

    # --- Fields / objects ---

    0xb2: ("getstatic", 2),
    0xb3: ("putstatic", 2),
    0xb4: ("getfield", 2),
    0xb5: ("putfield", 2),
    0xb6: ("invokevirtual", 2),
    0xb7: ("invokespecial", 2),
    0xb8: ("invokestatic", 2),
    # NOTE: invokeinterface (0xb9) and invokedynamic (0xba) deliberately
    # excluded — both are 4-byte operands but with irregular internal
    # layout (invokeinterface has a count byte + reserved zero byte;
    # invokedynamic indexes a different constant pool entry format used
    # for lambdas/string-concat). Treating them as a plain 4-byte skip
    # would parse without crashing but silently mis-tag what the operand
    # bytes mean — flag for dedicated handling, don't fake it.

    0xbb: ("new", 2),
    0xbc: ("newarray", 1),
    0xbd: ("anewarray", 2),
    0xbe: ("arraylength", 0),
    0xbf: ("athrow", 0),
    0xc0: ("checkcast", 2),
    0xc1: ("instanceof", 2),
    0xc2: ("monitorenter", 0),
    0xc3: ("monitorexit", 0),
    0xc5: ("multianewarray", 3),
    # NOTE: wide (0xc4) deliberately excluded — it's a prefix opcode that
    # changes how the NEXT opcode's operand is read (widens a 1-byte local
    # index to 2 bytes, or wraps iinc into a 5-byte form). Needs its own
    # parsing branch, not a fixed-length table entry.
    # NOTE: tableswitch (0xaa) / lookupswitch (0xab) deliberately excluded
    # — both have padding bytes to reach a 4-byte-aligned boundary before
    # their variable-length jump table. cfg_builder.py already recognizes
    # both mnemonics as block terminators (see switchMnemonics) and treats
    # them as a safe dead end rather than guessing; decoding the actual
    # jump table is real follow-up work, not a table entry.
}



def disassembleMethod(methodName: str, rawBytecode: bytes) -> List[Dict[str,any]]:
    instructions: List[Dict[str, any]] = []
    currentOffset: int = 0
    codeLength: int = len(rawBytecode)

    while currentOffset < codeLength:
        instructionOffset: int = currentOffset
        opcode: int = rawBytecode[currentOffset]
        currentOffset += 1

        if opcode not in jvmOpcodes:
            raise ValueError(
                f"Unrecognized opcode 0x{opcode:02x} at offset {instructionOffset} in method '{methodName}'. "
                f"Not in jvmOpcodes — add it (with its correct operand length) before this method can be "
                f"disassembled correctly."
            )

        mnemonic, operandCount = jvmOpcodes[opcode]
        operands: List[int] = []

        if operandCount > 0:
            for _ in range(operandCount):
                if currentOffset < codeLength:
                    operands.append(rawBytecode[currentOffset])
                    currentOffset += 1
        instructions.append({
            "offset": instructionOffset,
            "mnemonic": mnemonic,
            "operands": operands
        })

    return instructions