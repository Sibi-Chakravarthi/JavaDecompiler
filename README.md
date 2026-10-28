# NeuroDecomp (`JavaDecompiler`)

<p align="center">
  <strong>An AI-Powered Java Bytecode Decompiler & Semantic Recovery Pipeline</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Package_Manager-uv-DE5FE9?style=flat&logo=astral&logoColor=white" alt="uv">
  <img src="https://img.shields.io/badge/Virtual_Machine-JVM_Bytecode-ED8B00?style=flat&logo=openjdk&logoColor=white" alt="JVM">
  <img src="https://img.shields.io/badge/AI_Engine-Ollama_/_Local_LLM-000000?style=flat" alt="Ollama">
  <img src="https://img.shields.io/badge/Tests-17_Passed-success" alt="Tests">
</p>

---

## 1. Overview

**NeuroDecomp** is an AI-powered "X-ray" for compiled Java libraries (`.jar` and `.class` files). It reverse-engineers raw compiled JVM bytecode through symbolic operand stack simulation and leverages a local Large Language Model (via **Ollama**) to reconstruct clean, human-readable Java code with restored variable names and structured Javadoc documentation.

### The "Blind Trust" Problem
Modern software depends heavily on third-party libraries distributed as compiled binary archives (`.jar`). Standard decompilers (such as CFR, Procyon, or JD-GUI) solve the *syntactic* problem (producing syntactically valid code), but leave behind an **unreadable spaghetti of stripped identifiers**:
```java
// Traditional decompiler output:
var1 = param0 - param1;
if (var1 == 0) {
    var1 = 100;
} else {
    var1 = var1 + 5;
}
return var1;
```
Real-world incidents—such as the **XZ Utils backdoor (2024)**—demonstrate that malicious code slips past human review primarily because auditing compiled dependencies manually is intractable when all variable names and semantic context are stripped.

**NeuroDecomp bridges this semantic gap:**
```java
// NeuroDecomp AI-Restored output:
/**
 * Decompiled method: calculateHealth
 * <p>Performs pure computational / algorithmic logic.</p>
 */
public static int calculateHealth(int baseHealth, int damage) {
    currentHealth = baseHealth - damage;
    if (currentHealth == 0) {
        currentHealth = 100;
    } else {
        currentHealth = currentHealth + 5;
    }
    return currentHealth;
}
```

---

## 2. Pipeline Architecture

NeuroDecomp is built as a strictly chained three-phase pipeline where each phase's output feeds the next:

```
[Input: untrusted_library.jar / Target.class]
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ PHASE 1: Binary Parser & Unpacker                      │
│   ├─ Unpack .jar archives in-memory (zipfile)          │
│   ├─ Verify class header magic (0xCAFEBABE)            │
│   ├─ Parse & index Constant Pool (strings, refs, etc.) │
│   └─ Extract method bytecode attributes                │
│   (Strictly zero external dependencies: struct, io)    │
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ PHASE 2: JVM Disassembler & Symbolic Stack Lifter      │
│   ├─ Map hexadecimal opcodes to JVM assembly           │
│   ├─ Construct Control Flow Graph (CFG) basic blocks   │
│   ├─ Simulate stack machine (push/pop symbolic values) │
│   ├─ Lift object instantiations & method invocations   │
│   └─ Structure branching (if/else, while loops)        │
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ PHASE 3: NLP Semantic Restorer                         │
│   ├─ Extract OS & System context (Sockets, File, etc.) │
│   ├─ Query local Ollama LLM (qwen2.5-coder:14b/llama3) │
│   ├─ Recover semantic variable names                   │
│   ├─ Generate Javadoc docstrings                       │
│   └─ Deterministic Offline Fallback mode (--no-llm)    │
└────────────────────────────────────────────────────────┘
                     │
                     ▼
[Output: Reconstructed Source Code + Multi-Column Dark HTML Report]
```

### Phase Details

1. **Phase 1 (Binary Parser & Unpacker — `class_parser.py`):**
   - Built exclusively with Python built-ins (`struct`, `io`, `zipfile`).
   - Validates class version and magic `0xCAFEBABE`.
   - Parses the complete Constant Pool (Utf8, Class, Ref, String, NameAndType, Primitives).
   - Resolves method descriptors to deduce parameter types, counts, and return types.

2. **Phase 2 (JVM Disassembler & Symbolic Lifter — `disassembler.py`, `cfg_builder.py`, `lifter.py`):**
   - Decodes 80+ JVM opcodes with operand length mapping.
   - Partitions instructions into basic blocks based on leaders and jump targets.
   - Uses a symbolic stack simulator to track operand pushes, pops, binary operations, local stores (`istore`, `astore`), and method invocations (`invokevirtual`, `invokestatic`, `invokespecial`).
   - Accurately detects and lifts the standard JVM idiom `new` &rarr; `dup` &rarr; `invokespecial <init>` into high-level instantiations (`var = new Socket(host, port);`).
   - Computes dominators and natural loops to lift branching into structured `if (...) { ... } else { ... }` and `while (...) { ... }` blocks.

3. **Phase 3 (NLP Semantic Restorer — `semantic_restorer.py`):**
   - Scans Constant Pool and bytecode instructions for OS and resource interactions:
     - **Network / Sockets:** `java.net.Socket`, `ServerSocket`, `URL`, `HttpURLConnection`
     - **File I/O & Storage:** `java.io.File`, `FileInputStream`, `FileOutputStream`, `Path`, `Files`
     - **Cryptography & Hashing:** `java.security.MessageDigest`, `javax.crypto.Cipher`, `SecretKey`
     - **Process Execution:** `java.lang.Runtime`, `ProcessBuilder`, `System.exit`
   - Formulates a deterministic prompt to a local Ollama model (`qwen2.5-coder:14b` or `llama3`) to recover semantic variable names and produce Javadoc documentation.
   - **Offline / `--no-llm` Fallback Mode:** When Ollama is offline or the `--no-llm` flag is passed, a deterministic heuristic engine recovers variable names (e.g., `param0` &rarr; `host`, `var5` &rarr; `socket`) and attaches structured Javadoc without crashing or requiring cloud access.

---

## 3. Academic & Course Outcome Alignment

NeuroDecomp was designed to span three critical systems and compiler engineering outcomes:

| Outcome | Focus Area | How NeuroDecomp Covers It |
|---|---|---|
| **CO1** | Low-Level Languages | Hexadecimal JVM opcode decoding, instruction offset resolution, and byte-level disassembly. |
| **CO2** | Virtual Machines | Simulated stack machine execution model, tracking symbolic values pushed/popped across operand stacks and local variable slots. |
| **CO4** | Compilers & OS | Dominance frontier calculation, natural loop back-edge detection, CFG structuring, and OS-level resource context extraction (sockets, files, crypto). |

---

## 4. Installation & Setup

### Prerequisites
- **Python:** 3.10 or higher
- **Package Manager:** `uv` (recommended) or standard `pip`
- **Optional for Phase 3 LLM:** [Ollama](https://ollama.com/) with `qwen2.5-coder:14b` or `llama3`

### Setup with `uv`
```bash
# Clone the repository
git clone https://github.com/Sibi-Chakravarthi/JavaDecompiler.git
cd JavaDecompiler

# Sync dependencies and initialize environment
uv sync
```

> For a full step-by-step install/verify guide (including JDK fixture compilation,
> Ollama setup, and troubleshooting), see [`howtorun.md`](howtorun.md).

---

## 5. Usage & CLI

NeuroDecomp provides a unified command-line interface runnable either via `uv run javadecompiler` or `uv run python -m javadecompiler.cli`.

### Basic Decompilation
```bash
# Decompile a single .class file (connects to local Ollama if available)
uv run javadecompiler path/to/Target.class

# Decompile an entire .jar archive
uv run javadecompiler path/to/untrusted_library.jar
```

### Offline / Heuristic Mode (`--no-llm`)
Runs Phases 1 and 2, and uses the deterministic heuristic engine for Phase 3 (zero network/LLM calls):
```bash
uv run javadecompiler path/to/Target.class --no-llm
```

### Generate Dark-Themed Side-by-Side HTML Report (`--output-html`)
Generates an interactive, standalone single-file HTML report:
```bash
uv run javadecompiler path/to/library.jar --no-llm --output-html report.html
```

The report features:
- Constant Pool & Class Metadata summary card.
- Detected OS & API resource badges (Network, Crypto, File I/O, Process).
- Side-by-side 3-way view:
  1. **Phase 2 Bytecode & CFG Blocks**
  2. **Phase 2 Raw Pseudo-Code**
  3. **Phase 3 AI-Restored Source Code & Javadoc**

### Export Reconstructed `.java` Files (`--output-dir`)
```bash
uv run javadecompiler path/to/library.jar --output-dir ./decompiled_src/
```

### CLI Options Reference
```
usage: javadecompiler [-h] [--model MODEL] [--no-llm]
                      [--output-html PATH.html] [--output-dir DIR] [-v]
                      input_path

positional arguments:
  input_path            Path to target .class file or .jar archive

options:
  -h, --help            Show this help message and exit
  --model MODEL         Ollama model name for Phase 3 (default: qwen2.5-coder:14b)
  --no-llm              Run in offline mode (deterministic heuristic Javadoc/renaming)
  --output-html PATH    Path to generate multi-column side-by-side HTML report
  --output-dir DIR      Directory to save reconstructed .java files
  -v, --verbose         Enable detailed diagnostic logs
```

---

## 6. Repository Layout

```
JavaDecompiler/
├── pyproject.toml              # Project dependencies and CLI entry point
├── README.md                   # Project documentation (this project).
├── howtorun.md                 # Step-by-step setup, run & troubleshooting guide
├── scripts/
│   └── build_fixtures.py       # Compiles Java test fixtures + sample_library.jar
├── NeuroDecomp_Revised.md      # Architecture specification & roadmap
├── src/
│   └── javadecompiler/
│       ├── __init__.py         # Package entry point
│       ├── class_parser.py     # Phase 1: Binary parser, unpacker & CP resolver
│       ├── disassembler.py     # Phase 2: Bytecode disassembler & opcode table
│       ├── cfg_builder.py      # Phase 2: BasicBlock builder & CFG edge wiring
│       ├── structurer.py       # Phase 2: Dominator tree & loop analyzer
│       ├── lifter.py           # Phase 2: Symbolic stack simulator & AST lifter
│       ├── semantic_restorer.py# Phase 3: OS context extractor & Ollama restorer
│       ├── report.py           # Multi-column dark-themed HTML report generator
│       ├── cli.py              # Unified CLI runner
│       ├── run_batch.py        # Batch test runner across multiple classes
│       └── Java_Test_Files/    # Java test sources and compiled .class fixtures
│           ├── EngineMath.java
│           ├── LoopTest.java
│           ├── CombinedTest.java
│           └── NetworkCryptoService.java
└── tests/
    ├── test_class_parser.py    # Phase 1 tests
    ├── test_disassembler.py    # Disassembler tests
    ├── test_lifter.py          # Stack machine & AST lifter tests
    ├── test_semantic_restorer.py # Phase 3 OS context & LLM prompt tests
    └── test_cli.py             # End-to-end CLI tests
```

---

## 7. Verification & Testing

Run the full automated test suite using `uv`:

```bash
# Test fixtures ship as .java sources only; compile them once (requires a JDK)
uv run python scripts/build_fixtures.py

uv run python -m unittest discover tests
```

Output:
```
Ran 17 tests in 0.019s
OK
```

Run the batch runner across test class fixtures:
```bash
uv run python src/javadecompiler/run_batch.py src/javadecompiler/Java_Test_Files
```

---

## 8. Why a Local LLM?

- **Privacy & IP Protection:** Proprietary dependency code and internal libraries never leave the local machine.
- **Offline Capable:** The pipeline runs entirely air-gapped using either a local Ollama daemon or the built-in deterministic heuristic fallback.
- **Zero Cloud API Costs:** No external API keys or recurring per-token fees required.

---

## 9. Future Scope

- **Security & Vulnerability Scanning:** Automated regex/heuristic scanning for suspicious patterns (reflection, dynamic class loading, unrestricted process execution).
- **Behavioral Intent Classification:** Threat verdicts assessing whether decompiled methods exhibit backdoor or reverse shell behaviors.
- **Broader JVM Opcode Coverage:** Support for advanced JVM instructions such as `tableswitch`, `lookupswitch`, and `invokedynamic` lambda metafactories.

