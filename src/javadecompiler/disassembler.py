from typing import List, Tuple, Dict

jvmopcodes: Dict[int, Tuple[str, int]] = {
    0x10: ("bipush", 1),       # Push byte
    0x12: ("ldc", 1),          # Load constant
    0x15: ("iload", 1),        # Load int from local variable
    0x1a: ("iload_0", 0),      # Load int from local variable 0
    0x1b: ("iload_1", 0),      # Load int from local variable 1
    0x1c: ("iload_2", 0),      # Load int from local variable 2
    0x1d: ("iload_3", 0),      # Load int from local variable 3
    0x3b: ("istore_0", 0),     # Store int into local variable 0
    0x3c: ("istore_1", 0),     # Store int into local variable 1
    0x3d: ("istore_2", 0),     # Store int into local variable 2
    0x3e: ("istore_3", 0),     # Store int into local variable 3
    0x60: ("iadd", 0),         # Add int
    0x64: ("isub", 0),         # Subtract int
    0x84: ("iinc", 2),         # Increment local variable by constant
    0x99: ("ifeq", 2),         # Branch if int comparison with zero succeeds
    0xa7: ("goto", 2),         # Branch always
    0xb1: ("return", 0),       # Return void from method
    0xb2: ("getstatic", 2),    # Get static field from class
    0xb6: ("invokevirtual", 2),# Invoke instance method
    0xb8: ("invokestatic", 2), # Invoke a class (static) method
}