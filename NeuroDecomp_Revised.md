# Project NeuroDecomp — Full Project Explainer

> **Purpose of this file:** This is a context-dump document. Drop this into any new chat (Claude, ChatGPT, etc.) if the conversation history is lost, so the AI immediately understands the full project — what it does, why, how each pipeline phase works internally, the tech stack, and the team roadmap — without needing to re-explain from scratch.

---

## 1. One-Line Pitch

**NeuroDecomp is an AI-powered "X-ray" for Java libraries** — it takes an untrusted `.jar` file, reverse-engineers it down to raw JVM bytecode, and uses an LLM to reconstruct human-readable code from that bytecode without needing the original source code. 

*(Note: Automated security scanning/flagging is strictly designated as a future scope.)*

Think of it as: **decompiler + AI code-renamer, chained into one pipeline.**

---

## 2. The Problem We're Solving

Modern software almost never gets built from scratch — everyone imports third-party libraries. In the Java world, these come as compiled `.jar`/`.class` files, not source code. This creates a **"blind trust" problem**:

- Developers `import` a library and never actually look inside it.
- The library is compiled bytecode — humans can't read it directly.
- Standard decompilers (like CFR, Procyon, JD-GUI) *can* turn bytecode back into Java-like code, but the output is technically valid, yet **unreadable spaghetti**: variables are named `var1`, `var2`, `param0`, control flow is flattened, and there are zero comments. No one has the patience to manually audit that.
- Attackers exploit exactly this blind spot. The real-world **XZ Utils backdoor (2024)** is the textbook example — a malicious maintainer slipped obfuscated backdoor logic into a compression library that almost made it into major Linux distributions, and it went undetected for a long time specifically *because* nobody audits compiled dependency internals.

**Our thesis:** if we can make decompiled code *readable* again (via AI-restored variable names + auto-generated comments), a human (or a future automated security system) can actually eyeball it and catch malicious behavior before it ships.

---

## 3. What the Final Product Actually Does (End-to-End)

**Input:** `untrusted_library.jar` (any third-party Java dependency)

**Output:** 
1. AI-reconstructed, human-readable pseudo-source-code for every method in the jar.
2. Auto-generated documentation and context-aware variable names to make manual auditing viable.

**Future Scope (Security Integration):**
In the future, this readable output is designed to slot into a **DevSecOps pipeline** (acting as the foundation for a security scanner that flags dangerous APIs, assesses behavioral intent, and generates Trust Scores for dependencies).

---

## 4. Why This Is a Good Academic Project (Course Outcome Alignment)

This project was deliberately designed to touch **three separate course outcomes** in one coherent build, instead of three disconnected mini-projects:

| CO | Area | How NeuroDecomp Covers It |
|----|------|---------------------------|
| **CO1** | Low-Level Languages | We manually decode raw hexadecimal JVM opcodes (e.g., `0x1B`) into human-readable assembly-style instructions (`iload_1`), and manage program execution flow at that level. |
| **CO2** | Virtual Machines | We parse and simulate the JVM's **stack-based execution model** — literally pushing/popping symbolic values off a virtual stack to reconstruct what the bytecode is mathematically/logically doing. |
| **CO4** | OS / Compilers | We analyze how recovered variables interact with OS-level resources — file systems, network sockets, process execution — to infer what a variable's *real-world purpose* is. |

So the project isn't just "a cool AI tool" — it's structured so every phase maps cleanly back to something gradeable in the syllabus.

---

## 5. Tech Stack

| Layer | Tool/Library | Purpose |
|---|---|---|
| Core language | Python 3.10+ | Entire pipeline is Python |
| Binary parsing | `struct`, `io`, `zipfile` (all built-in, no external deps needed) | Read raw bytes, unzip `.jar` archives |
| Code representation | Custom Python classes | Represent Control Flow Graphs (CFGs) internally |
| AI/NLP engine | Local LLM — Llama-3 via `ollama` Python library, **or** CodeT5 via HuggingFace `transformers` | Variable renaming + comment generation |

**Note on "local LLM":** Using a local model (Ollama/Llama-3) instead of a cloud API is a deliberate design choice — it means you're not sending a client's potentially sensitive/proprietary dependency code to an external API. Good talking point for the viva.

---

## 6. Full Pipeline Architecture (Flowchart)

```
[Input: untrusted_library.jar]
       │
       ▼
┌─────────────────────────────────────────────┐
│ PHASE 1: Unpacker & Binary Parser            │
│   ├─ Extract .class files (via zipfile)      │
│   ├─ Verify Magic Number (0xCAFEBABE)        │
│   └─ Parse Constant Pool (strings/methods)   │
└─────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│ PHASE 2: JVM Disassembler & CFG Builder      │
│   ├─ Map hex opcodes → JVM Assembly          │
│   │     (e.g. iload, iadd)                   │
│   ├─ Simulate stack-based execution          │
│   └─ Generate raw pseudo-code                │
│        (e.g. var1 = var2 + Socket.getPort)   │
└─────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│ PHASE 3: NLP Semantic Restorer               │
│   ├─ Tokenize raw pseudo-code                │
│   ├─ Prompt local LLM with code + OS context │
│   ├─ Recover names (var1 → networkPort)      │
│   └─ Generate human-readable docstrings      │
└─────────────────────────────────────────────┘
       │
       ▼
[Output: Clean, Readable Source Code]
```

Each phase's **output becomes the next phase's input** — this is important to emphasize in the viva, because it's what makes it a "pipeline" rather than three disconnected scripts. Specifically:

- Phase 1 outputs → raw `.class` binary bytes + a Constant Pool dictionary
- Phase 2 consumes those bytes → outputs a CFG + raw pseudo-code (still has ugly variable names)
- Phase 3 consumes the raw pseudo-code → outputs clean, renamed, commented pseudo-code

---

## 7. Deep Dive: How Each Phase Actually Works

### Phase 1 — Unpacking & Parsing

A `.jar` file is literally just a ZIP archive. So:

1. Python's `zipfile` module opens the jar and extracts every `.class` file inside it.
2. Each `.class` file is opened in binary mode (`rb`) — we're reading raw bytes, not text.
3. Per the official JVM class file spec, the **first 4 bytes** of every valid `.class` file must equal the magic number `CAFEBABE` (hex). This is basically a sanity check — "is this actually a compiled Java class, or garbage/corrupted data?"
4. After the header, we parse the **Constant Pool** — this is a table embedded in every class file that stores every string literal, method name, field name, and class reference used in that class. We build this into a Python dictionary so that later phases can look up "what does constant pool index #47 actually say?" instead of dealing with raw indices everywhere.

**Why this matters:** Nothing after this phase is possible without the Constant Pool — it's the "dictionary" that gives meaning to all the numeric references used throughout the rest of the bytecode.

### Phase 2 — Disassembly & CFG (Control Flow Graph) Construction

This is the core "low-level languages + VM" phase (CO1 + CO2).

1. Inside each method, there's a `Code` attribute containing the actual compiled bytecode as a raw byte array.
2. We iterate byte-by-byte, and match each byte value against the JVM opcode table. Example: the byte `0x1B` corresponds to the instruction `iload_1` (load integer local variable slot 1 onto the stack).
3. The JVM is a **stack machine** — operations don't use registers, they push/pop values on/off an operand stack. So we simulate this: an instruction like `iadd` pops the top two values off our simulated stack, adds them, and pushes the result back. By tracking this symbolically (using placeholder variable names instead of real numbers), we reconstruct what mathematical/logical operation the original Java code was doing.
4. Jump instructions (`ifeq`, `goto`, etc.) don't execute linearly — they branch. We map these branches into a **Control Flow Graph**, which lets us reconstruct higher-level structures like `if/else` blocks and `while`/`for` loops from what was originally just "jump to byte offset X if condition."
5. Output of this phase: raw, technically-correct but ugly pseudo-code, e.g.:
   ```
   var1 = var2 + Socket.getPort()
   if (var1 > 1024) { ... }
   ```

### Phase 3 — AI Semantic Recovery (the "NeuroDecomp" part)

This is where it stops being "just another decompiler" and becomes AI-powered.

1. Compiled bytecode strips out all original variable names — the JVM doesn't need them, so `.class` files generally only retain generic slot numbers. That's why Phase 2's output looks like `var1`, `param0`, etc.
2. We take that raw pseudo-code block and send it to a locally-running LLM (Ollama/Llama-3, or CodeT5).
3. We prompt the model using **context clues from the code itself** — e.g., "this variable gets passed into a cryptographic hashing function; infer and rename it accordingly." This is essentially a masked-language-modeling-style prompt: the LLM infers semantic meaning from *usage context*, not from any name that was actually there originally (because there isn't one).
4. The LLM returns:
   - Renamed variables (e.g., `var1` → `userPasswordHash`)
   - Auto-generated docstrings/comments explaining what each function does

**This is the single biggest value-add of the whole project** — it converts something no human would bother reading into something a human (or a future AI scanner) can actually audit in minutes.

### Future Scope — Threat Scanning & Verification

While the current implementation focuses on reconstructing semantic meaning, the strict **future scope** for this project involves building a two-tier threat detection module on top of the clean code:
- **Heuristic Engine:** Using Python `re` to flag dynamic class loading, hardcoded IPs, or unrestricted shell execution.
- **Behavioral Engine:** Asking the LLM direct classification questions about the intended logic of the function (e.g., "Does this method establish a reverse shell?") to produce a final Safety Verdict.

---

## 8. Final Output Format

The pipeline emits a report (HTML or terminal-based) containing:
- The full AI-restored, readable source code.
- Clear structural representations of the original dependency logic, ready for manual review or future automated security validation.

---

## 9. Development Roadmap (10 Weeks)

| Weeks | Milestone |
|---|---|
| 1–2 | Build the `.class` parser using Python `struct`. Successfully read the Magic Number and dump the full Constant Pool. |
| 3–4 | Build the core Disassembler loop. Map at least 50 of the most common JVM opcodes (loads, stores, math ops, method invokes). |
| 5–6 | Implement the Control Flow Graph builder. Translate stack-based assembly into raw, unformatted pseudo-code (Python- or Java-style). |
| 7–8 | Integrate the NLP pipeline — set up Ollama or HuggingFace, write the prompt-engineering logic, and parse the LLM's structured output back into the system. |
| 9–10 | Finalize formatting, build the output reporting layer (HTML/Terminal), and run end-to-end testing on complex `.jar` files to ensure accurate semantic reconstruction. |

---

## 10. Key Talking Points for Viva / Defense

- **Why not just use an existing decompiler?** Existing decompilers (CFR, Procyon) solve the *syntactic* problem (bytecode → valid code) but not the *semantic* problem (what does this code actually mean/do). NeuroDecomp's contribution is specifically the AI semantic-recovery layer on top.
- **Why local LLM instead of an API?** Security/privacy — you don't want to leak a client's proprietary or sensitive dependency code to a third-party cloud API just to reverse-engineer it.
- **Why is security a 'Future Scope'?** The hardest, most technically complex part of the problem (and the part that covers our OS/VM course outcomes) is parsing bytecode into a CFG and using NLP to restore semantics. Threat scanning is effectively just pattern-matching on top of that foundation.
- **Where's the "VM" course outcome exactly?** In Phase 2 — we're literally implementing a simulated stack machine that mirrors how the real JVM executes bytecode, one opcode at a time.
- **Limitations to be upfront about:** Full JVM bytecode has 200+ opcodes; the project scopes down to the ~50 most common ones. Heavily obfuscated bytecode (e.g., with control-flow flattening or encrypted strings) would be much harder to reconstruct meaningfully.

---

## 11. Glossary (Quick Reference)

- **JVM (Java Virtual Machine):** The runtime that executes compiled Java bytecode.
- **Opcode:** A single-byte instruction code the JVM understands (e.g., `iadd` = integer add).
- **Constant Pool:** A table in every `.class` file holding all string/method/class references used by that class.
- **CFG (Control Flow Graph):** A graph representation of all possible execution paths through a function/method.
- **Stack machine:** A computation model (like the JVM) where operations work by pushing/popping values on an operand stack, rather than using named registers.
- **Decompiler:** A tool that converts compiled bytecode/machine code back into higher-level source-like code.
