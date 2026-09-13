from typing import List, Tuple, Dict

jvmOpcodes: Dict[int, Tuple[str, int]] = {
    0x02: ("iconst_m1", 0),    # Push int constant -1
    0x03: ("iconst_0", 0),     # Push int constant 0
    0x04: ("iconst_1", 0),     # Push int constant 1
    0x05: ("iconst_2", 0),     # Push int constant 2
    0x06: ("iconst_3", 0),     # Push int constant 3
    0x07: ("iconst_4", 0),     # Push int constant 4
    0x08: ("iconst_5", 0),     # Push int constant 5
    0x10: ("bipush", 1),       # Push byte
    0x12: ("ldc", 1),          # Load constant
    0x15: ("iload", 1),        # Load int from local variable
    0x1a: ("iload_0", 0),      # Load int from local variable 0
    0x1b: ("iload_1", 0),      # Load int from local variable 1
    0x1c: ("iload_2", 0),      # Load int from local variable 2
    0x1d: ("iload_3", 0),      # Load int from local variable 3
    0x2a: ("aload_0", 0),      # Load reference from local variable 0 (this)
    0x36: ("istore", 1),       # Store int into local variable (generic)
    0x3b: ("istore_0", 0),     # Store int into local variable 0
    0x3c: ("istore_1", 0),     # Store int into local variable 1
    0x3d: ("istore_2", 0),     # Store int into local variable 2
    0x3e: ("istore_3", 0),     # Store int into local variable 3
    0x57: ("pop", 0),          # Discard the top value on the operand stack
    0x60: ("iadd", 0),         # Add int
    0x64: ("isub", 0),         # Subtract int
    0x70: ("irem", 0),         # Remainder int
    0x84: ("iinc", 2),         # Increment local variable by constant
    0x99: ("ifeq", 2),         # Branch if int comparison with zero succeeds
    0x9a: ("ifne", 2),         # Branch if int comparison with zero fails (!= 0)
    0x9b: ("iflt", 2),         # Branch if int comparison < 0
    0x9c: ("ifge", 2),         # Branch if int comparison >= 0
    0x9d: ("ifgt", 2),         # Branch if int comparison > 0
    0x9e: ("ifle", 2),         # Branch if int comparison <= 0
    0x9f: ("if_icmpeq", 2),    # Branch if int comparison equal
    0xa0: ("if_icmpne", 2),    # Branch if int comparison not equal
    0xa1: ("if_icmplt", 2),    # Branch if int comparison less than
    0xa2: ("if_icmpge", 2),    # Branch if int comparison greater or equal
    0xa3: ("if_icmpgt", 2),    # Branch if int comparison greater than
    0xa4: ("if_icmple", 2),    # Branch if int comparison less or equal
    0xa5: ("if_acmpeq", 2),    # Branch if reference comparison equal
    0xa6: ("if_acmpne", 2),    # Branch if reference comparison not equal
    0xa7: ("goto", 2),         # Branch always
    0xac: ("ireturn", 0),      # Return int from method
    0xad: ("lreturn", 0),      # Return long from method
    0xae: ("freturn", 0),      # Return float from method
    0xaf: ("dreturn", 0),      # Return double from method
    0xb0: ("areturn", 0),      # Return reference from method
    0xb1: ("return", 0),       # Return void from method
    0xb2: ("getstatic", 2),    # Get static field from class
    0xb6: ("invokevirtual", 2),# Invoke instance method
    0xb7: ("invokespecial", 2),# Invoke instance method (constructors, private, super)
    0xb8: ("invokestatic", 2), # Invoke a class (static) method
    0xbf: ("athrow", 0),       # Throw exception or error
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
            instructions.append({
                "offset": instructionOffset,
                "mnemonic": f"unknown_0x{opcode:02x}",
                "operands": []
            })
            continue

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