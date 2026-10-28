# Bug Audit Report: `javadecompiler` Core Pipeline

**Generated:** 2026-10-29  
**Repository:** `Sibi-Chakravarthi/JavaDecompiler`  
**Auditor:** Antigravity Autonomous Agent  
**Environment:** Python 3.10+, uv, Windows 11 / PowerShell  

---

## Executive Summary

A comprehensive, line-by-line inspection of the `javadecompiler` core pipeline (`class_parser.py`, `disassembler.py`, `cfg_builder.py`, `lifter.py`, `semantic_restorer.py`, `report.py`, `cli.py`, and `scripts/build_fixtures.py`) was performed prior to code modifications. 

This audit identified **16 critical and high-priority bugs and architectural vulnerabilities** spanning all 6 pipeline phases:
1. **Phase 1 (Class Parsing):** Missing `None` placeholders for 8-byte constant pool entries, unhandled JVM tags (17, 19, 20), non-compliant Modified UTF-8 decoding, missing class-level attributes (`BootstrapMethods`, `InnerClasses`), disk leaks in archive unpacking, and unparsed exception tables.
2. **Phase 2a (Disassembly):** Missing opcode `0xC4` (`wide`) causing immediate crashes on wide instructions, unvalidated variable-length switch tables (`tableswitch` / `lookupswitch`), and unhandled signed branch offsets.
3. **Phase 2b (CFG Construction):** Hardcoded 2-byte operand assumption in branch target resolution (breaking 4-byte `goto_w` / `jsr_w`), lack of exception table leader integration and edge wiring, and loop back-edge boundary preservation.
4. **Phase 2c (Symbolic Lifting):** Missing handler for Java 9+ `invokedynamic` (`makeConcatWithConstants`), stack underflow in catch handlers emitting raw comments instead of `caughtEx` or fallback, and static method local slot stepping edge cases.
5. **Phase 3 (Semantic Restoration):** Fragile JSON parsing susceptible to LLM markdown code blocks (````json ... ````) and conversational preambles, and unstripped backticks in reconstructed Java code.
6. **Phase 4 & Cross-Cutting:** Missing HTML escaping on method names (`<init>`, `<clinit>`), variable names, and badges; and implicit system default encodings on Windows file writes.

---

## Detailed Bug Findings & Remediation Strategies

### 1. `class_parser.py` (Phase 1 — Binary & Constant Pool Parsing)

#### Bug 1.1: 8-Byte Constant Pool Slot Missing Placeholder (`None`)
- **File & Line:** [class_parser.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/class_parser.py#L153-L159)
- **Root Cause:** In JVM Spec §4.4.5, `CONSTANT_Long` (tag 5) and `CONSTANT_Double` (tag 6) take up two constant pool entries: if an entry is at index $n$, the next entry is at index $n+2$, and index $n+1$ must exist in the pool as an unusable slot. `parseConstantPool` incremented `currentIndex` by 1 inside the branch and by 1 at loop termination, but never assigned `constantPool[currentIndex] = None`. As a result, index $n+1$ is missing from the dictionary, raising `KeyError` on direct lookup.
- **Triggering Input:** Any class containing `long` or `double` constants where downstream code checks or iterates constant pool indices.
- **Fix Strategy:** Explicitly assign `constantPool[currentIndex + 1] = None` and increment `currentIndex += 1` inside the `tagLong` / `tagDouble` handler.

#### Bug 1.2: Missing JVM Constant Pool Tags (Tags 17, 19, 20)
- **File & Line:** [class_parser.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/class_parser.py#L98-L188)
- **Root Cause:** Modern Java class files (Java 9 modularity and Java 11 dynamic constants) introduce Tag 17 (`CONSTANT_Dynamic`, 4 bytes), Tag 19 (`CONSTANT_Module`, 2 bytes), and Tag 20 (`CONSTANT_Package`, 2 bytes). Currently, encountering any of these tags triggers `NotImplementedError`, abruptly halting parsing.
- **Triggering Input:** `module-info.class` from any modular JAR or classes compiled with dynamic constants (`invokedynamic` / `ldc` dynamic).
- **Fix Strategy:** Add definitions and parsers for tag 17 (u2 bootstrap_method_attr_index, u2 name_and_type_index), tag 19 (u2 name_index), and tag 20 (u2 name_index).

#### Bug 1.3: Non-Compliant Modified UTF-8 String Decoding
- **File & Line:** [class_parser.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/class_parser.py#L119)
- **Root Cause:** Standard Python UTF-8 decoding (`utf8Bytes.decode('utf-8', errors='replace')`) fails to properly decode JVM Modified UTF-8. Specifically, the null character `\u0000` is encoded as two bytes `0xC0 0x80`, and supplementary characters are encoded as surrogate pairs (`0xED 0xA0..0xAF 0xED 0xB0..0xBF`). Standard UTF-8 replaces `0xC0 0x80` with replacement characters `\ufffd\ufffd` or raises errors.
- **Triggering Input:** Bytecode containing null characters in Utf8 strings or obfuscated strings using two-byte null sequences.
- **Fix Strategy:** Implement a robust `decodeModifiedUtf8` function that converts `0xC0 0x80` to `\u0000`, decodes surrogate pairs, and falls back gracefully with `errors="replace"`.

#### Bug 1.4: Missing Class-Level Attributes & `BootstrapMethods`
- **File & Line:** [class_parser.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/class_parser.py#L325-L370)
- **Root Cause:** In `parseClassInfo`, parsing terminates immediately after the `methods` table. The trailing `attributes_count` and class-level attributes (`BootstrapMethods`, `InnerClasses`, `SourceFile`) are never read or stored. Without `BootstrapMethods`, invokedynamic calls (such as string concatenation) cannot resolve their bootstrap arguments.
- **Triggering Input:** Any class compiled with Java 9+ string concatenation or invokedynamic expressions.
- **Fix Strategy:** Parse class-level attributes into a dictionary on `ClassInfo`, explicitly preserving `BootstrapMethods` entries.

#### Bug 1.5: Disk Leaks and File Collisions in `extractAndParseJar`
- **File & Line:** [class_parser.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/class_parser.py#L384-L412)
- **Root Cause:** `extractAndParseJar` extracts `.class` files to a hardcoded local directory `"extractedClasses"` on disk. On Windows, file locking, concurrent test execution, or permission limitations cause collisions and file leaks.
- **Triggering Input:** Concurrent invocations or read-only directory environments.
- **Fix Strategy:** Read class bytes directly from `zipfile.ZipFile.read()` into memory without writing temporary files to disk, utilizing a bytes-backed `ClassFileReader`.

#### Bug 1.6: Unparsed Exception Tables in `Code` Attributes
- **File & Line:** [class_parser.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/class_parser.py#L348-L351)
- **Root Cause:** In the JVM `Code` attribute, following the code array is `u2 exception_table_length` and an array of 8-byte exception handlers (`start_pc`, `end_pc`, `handler_pc`, `catch_type`). `class_parser.py` slices only `payload[8 : 8 + codeLength]` and completely discards the exception table.
- **Triggering Input:** Any method with `try-catch` or `try-finally` blocks.
- **Fix Strategy:** Parse the exception table from the `Code` attribute payload and attach `exception_handlers: List[Dict[str, int]]` to `MethodInfo`.

---

### 2. `disassembler.py` (Phase 2a — Bytecode Instruction Decoding)

#### Bug 2.1: Missing Opcode `0xC4` (`wide`) Implementation
- **File & Line:** [disassembler.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/disassembler.py#L4-L144), [L215-L220](file:///D:/Github/JavaDecompiler/src/javadecompiler/disassembler.py#L215-L220)
- **Root Cause:** Opcode `0xC4` (`wide`) is missing from `jvmOpcodes`. When `wide` is encountered, line 216 raises `ValueError: Unrecognized opcode 0xc4`. `wide` modifies subsequent load/store/ret instructions to use 2-byte local indices (4 bytes total), or modifies `iinc` to use a 2-byte index and 2-byte signed constant (6 bytes total).
- **Triggering Input:** Methods with >255 local variables or constants requiring wide instructions.
- **Fix Strategy:** Add specialized decoding for opcode `0xC4`: inspect the sub-opcode; if `0x84` (`iinc`), read 2-byte unsigned index and 2-byte signed short; otherwise read 2-byte unsigned index.

#### Bug 2.2: Switch Variable-Length Bounds & Padding Validation
- **File & Line:** [disassembler.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/disassembler.py#L158-L213)
- **Root Cause:** Padding calculation `pad = (3 - (instructionOffset % 4))` works, but does not guard against invalid bounds: if `high < low` in `tableswitch` or `npairs < 0` in `lookupswitch`, `disassembler.py` leaves `currentOffset` unadvanced or creates negative loops without error, desynchronizing the bytecode stream.
- **Triggering Input:** Malformed or obfuscated switch bytecodes.
- **Fix Strategy:** Explicitly validate `high >= low` and `npairs >= 0`, and ensure padding strictly adheres to `(4 - ((instructionOffset + 1) % 4)) % 4`.

---

### 3. `cfg_builder.py` (Phase 2b — Control Flow Graph Construction)

#### Bug 3.1: 4-Byte Wide Branch Targets (`goto_w`, `jsr_w`) Unresolved
- **File & Line:** [cfg_builder.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/cfg_builder.py#L20-L35)
- **Root Cause:** `resolveBranchTarget` explicitly enforces `if len(operands) != 2: return None`. For `goto_w` (0xC8) and `jsr_w` (0xC9), operands contain 4 bytes (signed 32-bit offset). Consequently, `resolveBranchTarget` returns `None`, failing to identify the jump target as a leader and leaving the CFG disconnected.
- **Triggering Input:** Methods spanning >32KB of bytecode utilizing `goto_w`.
- **Fix Strategy:** Check mnemonic in `("goto_w", "jsr_w")` and unpack 4 signed bytes (`>i`) from `operands`.

#### Bug 3.2: Exception Handlers Missing as Leaders and CFG Edges
- **File & Line:** [cfg_builder.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/cfg_builder.py#L67-L91), [L110-L142](file:///D:/Github/JavaDecompiler/src/javadecompiler/cfg_builder.py#L110-L142)
- **Root Cause:** `buildControlFlowGraph` does not accept exception handlers. Therefore, handler entry points (`handler_pc`) and protected boundaries (`start_pc`, `end_pc`) are not registered as leaders, and catch blocks are treated as dead unreachable code or merged into unrelated basic blocks.
- **Triggering Input:** Any method containing `try-catch` structures.
- **Fix Strategy:** Pass `exception_handlers` to `findLeaders` and `wireEdges`, registering `start_pc`, `end_pc`, and `handler_pc` as block leaders and adding exception edges from protected blocks to `handler_pc`.

---

### 4. `lifter.py` (Phase 2c — Symbolic Stack Machine & AST Lifter)

#### Bug 4.1: Missing Java 9+ `invokedynamic` (`makeConcatWithConstants`) Lifting
- **File & Line:** [lifter.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/lifter.py#L361-L402)
- **Root Cause:** `invokedynamic` (opcode `0xBA`) is omitted from the invocation dispatch chain in `liftBlock`. In Java 9+, string concatenation (`"a" + b`) is compiled to `invokedynamic` with `makeConcatWithConstants`. Because `invokedynamic` is unhandled, operands remain on the symbolic stack, polluting downstream instructions and causing wrong assignments or crashes.
- **Triggering Input:** Any Java 9+ bytecode performing string concatenation.
- **Fix Strategy:** Implement `invokedynamic` handling in `liftBlock`: resolve call site name and descriptor, pop arguments, and lift `makeConcatWithConstants` as string concatenation expressions (`arg0 + arg1 + ...`).

#### Bug 4.2: Catch Block Stack Underflow Emits `/* stack_underflow */`
- **File & Line:** [lifter.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/lifter.py#L136-L139)
- **Root Cause:** JVM exception handlers begin execution with the caught exception object on the operand stack. Because `StackSimulator` initializes with an empty stack (`self.stack = []`), the first store instruction (`astore_1` / `astore`) triggers underflow and emits `var1 = /* stack_underflow */;`.
- **Triggering Input:** Any method with a `catch` block that stores the exception object.
- **Fix Strategy:** Check if a block starts at an exception handler PC or when an underflow occurs in a catch block; supply `caughtEx` (or clean fallback identifier `_stack_undef`) instead of a raw comment.

#### Bug 4.3: Static vs Instance Method Slot Mapping & Category-2 Stepping Helper
- **File & Line:** [lifter.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/lifter.py#L100-L116)
- **Root Cause:** Parameter mapping correctly skips slot 0 for instance methods, but does not expose a clean query helper for Category-2 types (`long` `'J'`, `double` `'D'`) which consume two local slots.
- **Triggering Input:** Static methods with alternating Category-1 and Category-2 parameters.
- **Fix Strategy:** Provide a dedicated helper `getSlotForParameter(method_info, param_index)` and ensure bidirectional mapping is consistent.

---

### 5. `semantic_restorer.py` (Phase 3 — NLP Semantic Restoration)

#### Bug 5.1: Markdown Code Fence & Conversational Preamble Crash
- **File & Line:** [semantic_restorer.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/semantic_restorer.py#L295-L318)
- **Root Cause:** When local LLMs respond, they frequently enclose JSON responses in markdown code fences (````json\n{...}\n````) or prepend conversational text ("Here is the decompiled result:"). `json.loads(replyText)` raises `JSONDecodeError`, causing the pipeline to discard the LLM output. Furthermore, if `reconstructed_code` inside the JSON includes ````java ... ```` fences, they are preserved verbatim in the Java output file.
- **Triggering Input:** Standard responses from LLMs such as Ollama `qwen2.5-coder`.
- **Fix Strategy:** Implement robust pre-processing to extract JSON from markdown fences using regex (`re.search(r"\{.*\}", replyText, re.DOTALL)`), strip markdown fences (````java ... ````) and conversational greetings from `reconstructed_code`, and validate non-empty output before accepting.

#### Bug 5.2: LLM Timeout & Offline Resilience
- **File & Line:** [semantic_restorer.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/semantic_restorer.py#L260-L268)
- **Root Cause:** If Ollama daemon is unresponsive or times out, network errors must never propagate to the user or terminate the pipeline.
- **Triggering Input:** Unreachable Ollama daemon or socket timeout.
- **Fix Strategy:** Ensure all HTTP/socket exceptions in `_queryOllama` are caught and logged, guaranteeing automatic fallback to `_heuristicFallback`.

---

### 6. `report.py`, `cli.py`, `scripts/build_fixtures.py` (Phase 4 & Cross-Cutting)

#### Bug 6.1: HTML Injection / Unescaped Tag Rendering in Report
- **File & Line:** [report.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/report.py#L398-L400), [L332-L341]
- **Root Cause:** In `generateHtmlReport`, methods named `<init>` or `<clinit>` in `renamed_variables` or category badges are formatted without `html.escape()`. Browsers treat `<init>` as an unclosed HTML tag, corrupting the layout and rendering blank sections.
- **Triggering Input:** Classes with constructors (`<init>`) or static initializers (`<clinit>`).
- **Fix Strategy:** Apply `html.escape()` to all dictionary keys and values in `renamed_html`, category badges, and code snippets.

#### Bug 6.2: Missing Explicit UTF-8 Encoding in File Operations
- **File & Line:** [report.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/report.py), [cli.py](file:///D:/Github/JavaDecompiler/src/javadecompiler/cli.py)
- **Root Cause:** On Windows, Python defaults to `cp1252` when `encoding` is omitted from `open()`. Outputting decompiled source files or HTML reports containing unicode arrows (`→`), mathematical symbols, or UTF-8 characters fails with `UnicodeEncodeError`.
- **Triggering Input:** Running `javadecompiler` on Windows with decompiled code containing non-ASCII characters.
- **Fix Strategy:** Verify that every file read/write across the codebase explicitly specifies `encoding="utf-8"`.

---

## Action Plan & Atomic Commits

1. **Commit 1:** `fix(parser): 8-byte CP slot stepping, tags 17/19/20, modified UTF-8, attributes & exception table`
2. **Commit 2:** `fix(disassembler): implement wide opcode 0xC4, validate switch bounds and padding`
3. **Commit 3:** `fix(cfg): resolve 4-byte wide branch targets, integrate exception handlers and loop leaders`
4. **Commit 4:** `fix(lifter): handle invokedynamic, catch block stack resilience, and Category-2 slot stepping`
5. **Commit 5:** `fix(restorer): strip markdown fences from LLM responses and harden error resilience`
6. **Commit 6:** `fix(report): escape HTML entities for constructors and ensure UTF-8 encoding across I/O`
7. **Commit 7:** `test(bugfixes): add regression test suite for core pipeline`
