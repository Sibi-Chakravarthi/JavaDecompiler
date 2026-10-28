# NeuroDecomp (`JavaDecompiler`)

<p align="center">
  <strong>An AI-Powered Java Bytecode Decompiler, Semantic Recovery & Behavioral Security Auditor</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Package_Manager-uv-DE5FE9?style=flat&logo=astral&logoColor=white" alt="uv">
  <img src="https://img.shields.io/badge/Virtual_Machine-JVM_Bytecode-ED8B00?style=flat&logo=openjdk&logoColor=white" alt="JVM">
  <img src="https://img.shields.io/badge/AI_Engine-Ollama_/_Local_LLM-000000?style=flat" alt="Ollama">
  <img src="https://img.shields.io/badge/Tests-90_Passed_(100%25)-success" alt="Tests">
  <img src="https://img.shields.io/badge/Security-Zero_Third--Party_Dependencies-blue" alt="Zero Dependencies">
</p>

---

## 1. Overview

**NeuroDecomp** is an AI-powered "X-ray" for compiled Java libraries (`.jar` and `.class` files). It reverse-engineers raw compiled JVM bytecode through symbolic operand stack simulation, reconstructs clean human-readable Java code with restored variable names via a local Large Language Model (via **Ollama**), and audits binaries for software vulnerabilities and malicious behavioral backdoors across a multi-layered security engine.

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
Real-world incidents—such as the **XZ Utils backdoor (2024)** and Log4Shell (CWE-502 / CWE-470)—demonstrate that malicious code slips past human review primarily because auditing compiled dependencies manually is intractable when all variable names and semantic context are stripped.

**NeuroDecomp bridges this semantic gap:**
```java
// NeuroDecomp AI-Restored output with Semantic Context:
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

## 2. Multi-Layer Pipeline Architecture

NeuroDecomp is built as a strictly chained, zero-dependency four-phase pipeline:

```
[Input: untrusted_library.jar / Target.class]
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ PHASE 1: Binary Parser & Archive Hardening             │
│   ├─ Zip-slip, zip-bomb & malformed bytecode guards    │
│   ├─ Embedded native binary (.dll, .so) detection      │
│   ├─ Manifest agent & remote classpath audits          │
│   ├─ Constant Pool indexing (strings, refs, dyn)       │
│   └─ Zero external dependencies (struct, io, zipfile)  │
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ PHASE 2: JVM Disassembler & Symbolic Stack Lifter      │
│   ├─ Full JVM opcode table (incl. tableswitch & lookup)│
│   ├─ BasicBlock partitioning & CFG successor wiring    │
│   ├─ Symbolic stack machine (push/pop operand typing)  │
│   ├─ Java 9+ invokedynamic (makeConcatWithConstants)   │
│   └─ Dominance frontier & loop structure recovery      │
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ PHASE 3: NLP Semantic Restorer                         │
│   ├─ OS & API Context Extraction (Sockets, Crypto, I/O)│
│   ├─ Local Ollama LLM query (qwen2.5-coder:14b/llama3) │
│   ├─ Semantic variable renaming & Javadoc generation   │
│   └─ Deterministic Heuristic Offline Fallback (--no-llm│
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ PHASE 4: Security Auditor & Behavioral Analysis        │
│   ├─ Layer A: 10-Family Static Rule Engine (30+ CWEs)  │
│   ├─ Layer B: 7 Multi-Step Behavior Chains (Taint-Lite)│
│   ├─ Layer C: Local LLM Auditor Harness (qwen2.5-coder)│
│   │   ├─ Strict JSON Schema Validation & Auto-Repair   │
│   │   ├─ Anti-Hallucination Grounding (I:0x.., CP:, L:)│
│   │   ├─ Adversarial Verifier (Devil's Advocate pass)  │
│   │   ├─ Majority Voting (--llm-votes N)               │
│   │   └─ Bounded Agentic Investigator (max 8 steps)    │
│   └─ Weighted 0–100 Scoring & Verdict (CLEAN -> MAL)   │
└────────────────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│ OUTPUT INTERFACES                                      │
│   ├─ Interactive Drag-and-Drop Web UI (--ui)           │
│   ├─ Multi-Column Dark-Themed HTML Standalone Report   │
│   ├─ Machine-Readable SARIF 2.1.0 & JSON Outputs       │
│   └─ CI/CD Quality Gate Fail-On CLI Exit Codes         │
└────────────────────────────────────────────────────────┘
```

---

## 3. Security Engine & Rule Catalog (Phase 4)

NeuroDecomp audits JVM binaries across three cooperative inspection layers:

### Layer A: Deterministic Static Rules (`security/rules/`)
- **Archive & Container (`jar_checks.py`):** Zip-slip traversal (`JD-ARCH-ZIPSLIP`), zip-bombs with ratio > 100:1 (`JD-ARCH-ZIPBOMB`), embedded native binaries (`JD-ARCH-NATIVE`), manifest Java agents (`JD-ARCH-MANIFEST-AGENT`), remote classpath URLs (`JD-ARCH-CLASSPATH-REMOTE`), SPI service providers (`JD-ARCH-SPI`), and declared class-name mismatches (`JD-ARCH-MISMATCH`).
- **Execution (`execution.py`):** `Runtime.exec`, `ProcessBuilder`, and unquoted command string injection (`JD-EXEC-001`, CWE-78).
- **Network (`network.py`):** Raw network sockets (`JD-NET-001`, CWE-319), hardcoded public IPv4 literals (`JD-NET-002`), and DNS exfiltration sinks (`JD-NET-003`, CWE-359).
- **Dynamic Loading & Reflection (`dynamic.py`):** Arbitrary reflection (`JD-DYN-001`, CWE-470), remote `URLClassLoader` (`JD-DYN-002`), dynamic JNDI lookups (`JD-DYN-003`, CWE-502), embedded script engines (`JD-DYN-004`, CWE-94), and `sun.misc.Unsafe` usage (`JD-DYN-005`).
- **Deserialization (`deserialization.py`):** Unsafe `ObjectInputStream.readObject` (`JD-DESER-001`, CWE-502), `XMLDecoder.readObject` (`JD-DESER-002`), and gadget declarations (`JD-DESER-003`).
- **Injection (`injection.py`):** SQL injection via dynamic query string concatenation (`JD-INJ-001`, CWE-89), path traversal without canonicalization (`JD-INJ-002`, CWE-22), and insecure XXE `DocumentBuilderFactory` (`JD-INJ-003`, CWE-611).
- **Cryptography (`crypto.py`):** Weak hash algorithms MD5/SHA-1 (`JD-CRYP-001`, CWE-328), broken ciphers DES/RC4/AES-ECB (`JD-CRYP-002`, CWE-327), hardcoded constant keys/IVs (`JD-CRYP-003`, CWE-321), predictable `java.util.Random` in security contexts (`JD-CRYP-004`, CWE-330), and trust-all `X509TrustManager` / permissive `HostnameVerifier` (`JD-CRYP-005`, CWE-295).
- **Secrets (`secrets.py`):** Hardcoded AWS credentials, GitHub tokens, PEM private keys, and high-entropy secrets (`JD-SEC-001`, CWE-798). Secrets are automatically redacted in all logs and reports.
- **Evasion & Obfuscation (`evasion.py`):** XOR decryption loops feeding dangerous sinks (`JD-EVA-001`), Base64 decode-and-execute chains (`JD-EVA-002`), JDWP debugger/sandbox checks (`JD-EVA-003`), timestamp logic bombs (`JD-EVA-004`), and LLM prompt-injection subversion attempts (`JD-EVA-005`).
- **System & Persistence (`system.py`):** Shutdown hook persistence (`JD-SYS-001`) and host reconnaissance (`JD-SYS-002`).
- **Load-Time Triggers (`loadtime.py`):** Dangerous sinks reachable automatically at class initialization time (`<clinit>`, `JD-LOAD-001`, CWE-506). Automatically escalates finding severity by +1 level.

### Layer B: Multi-Step Behavior Chains (`security/behavior.py`)
Multi-instruction taint-lite chains connecting sources to transformations and sinks:
- `JD-CHAIN-REVSHELL`: Reverse shell stream piping connecting process I/O to network sockets.
- `JD-CHAIN-DROPPER`: Remote payload download &rarr; local file write &rarr; process execution.
- `JD-CHAIN-DECODE-EXEC`: Obfuscated string literal &rarr; Base64/XOR decrypt &rarr; dynamic execution.
- `JD-CHAIN-EXFIL`: Sensitive file read (`.ssh`, `.aws`, environment) &rarr; outbound network stream.
- `JD-CHAIN-TAINT-SINK`: Untrusted method parameters &rarr; string concatenation &rarr; command/SQL/JNDI injection sinks.
- `JD-CHAIN-TIMEBOMB`: Date comparison guarding execution branch.
- `JD-CHAIN-CLINIT`: Static class initializer triggering dangerous sinks on load.

### Layer C: Local LLM Auditor Harness (`security/llm/`)
Pairs local LLM reasoning (`qwen2.5-coder:14b` via Ollama) with anti-hallucination guardrails:
1. **Prompt Sanitization:** Untrusted bytecode/strings are wrapped in unique random boundary tags (`<UNTRUSTED_TARGET_DATA_xxx>`) with defusal of closing tags and prompt-injection phrases.
2. **Strict Schema Validation & Auto-Repair:** LLM responses are validated against a strict JSON schema. Malformed responses trigger an automatic repair retry prompt.
3. **Anti-Hallucination Evidence Grounding:** Every cited evidence ID (`I:0x..` for bytecode offsets, `CP:..` for constant pool indices, `L:..` for lifted lines) is verified against the actual binary. Ungrounded findings are dropped, and LLM-only findings are capped at `medium` severity.
4. **Adversarial Verifier (Devil's Advocate):** For findings &ge; `medium`, a refutation prompt challenges the model to disprove the vulnerability using only verified code evidence.
5. **Self-Consistency Majority Voting (`--llm-votes N`):** Runs multiple independent verification passes and accepts only majority-confirmed findings.
6. **Bounded Agentic Investigator (`--llm-investigate`):** Autonomous read-only investigation loop (up to 8 steps) querying bytecode, lifted source, callers, callees, and constant pools.

### Scoring & Verdicts
```text
Score (0–100) = Sum(Weight * Confidence * CategoryDecay) + MultiCategoryBonus + LoadTimeBonus
```
- **Verdicts:** `CLEAN`, `REVIEW_RECOMMENDED`, `VULNERABLE`, `SUSPICIOUS`, `LIKELY_MALICIOUS`.
- *Safety Guarantee:* A binary is **never** marked `CLEAN` if any method suffered partial disassembly coverage (downgraded to `REVIEW_RECOMMENDED`).

---

## 4. Interactive Drag-and-Drop Web UI (`--ui`)

NeuroDecomp includes a standalone, dark-themed Web UI served via Python's standard library (`http.server`):

```bash
uv run javadecompiler --ui --port 8080
```
Open `http://localhost:8080` in any modern browser:
- **Drag-and-Drop Zone:** Drop any `.class` or `.jar` archive directly into the browser.
- **Top Summary Banner:** 0–100 Risk Score gauge, color-coded verdict pill, coverage status, and top 3 plain-English audit reasons.
- **3-Pane IDE Layout:**
  1. **Left Pane (Explorer):** Tree of classes and methods sorted by risk score with color-coded severity pills.
  2. **Center Pane (Code & Bytecode Viewport):** Decompiled Java pseudo-code with line numbers and a tab toggle for raw Bytecode instructions. **Inline Vulnerability Highlighting:** Vulnerable lines are highlighted in red/orange/yellow with expandable inline finding banners detailing CWE, origin, evidence citations, and remediation.
  3. **Right Pane (Findings & Rationale Inspector):** Filter findings by severity (Critical, High, Medium, Low) and export reports to JSON, SARIF 2.1.0, or standalone HTML.

---

## 5. Measured Evaluation Benchmark

Evaluated against the 42-class synthetic corpus (`tests/security_corpus/{benign,vulnerable,suspicious}`) compiled via `javac`:

| Metric | `static-only` (Deterministic) | `hybrid-ollama` (`qwen2.5-coder:14b` Live) |
|---|---|---|
| **Precision** | **96.2%** | **83.3%** |
| **Recall** | **92.6%** | **92.6%** |
| **F1 Score** | **94.3%** | **87.7%** |
| **Benign False-Positive Rate (FPR)** | **6.7%** | **13.3%** |
| **Verdict Accuracy** | **88.1%** | **81.0%** |
| **Evidence Grounding Rate** | **100.0%** | **100.0%** |
| **Prompt Injection Resilience** | **PASS** | **PASS** |
| **Average Latency / Class** | **1.72 ms** | **1,842 ms** |

Run the benchmark regression check:
```bash
uv run python scripts/eval_security.py --baseline tests/security_corpus/baseline_static.json
```

---

## 6. Installation & Setup

### Prerequisites
- **Python:** 3.10 or higher
- **Package Manager:** `uv` (recommended) or standard `pip`
- **Optional for AI Restorer & LLM Auditor:** [Ollama](https://ollama.com/) with `qwen2.5-coder:14b` or `llama3`

### Setup with `uv`
```bash
# Clone the repository
git clone https://github.com/Sibi-Chakravarthi/JavaDecompiler.git
cd JavaDecompiler

# Sync environment
uv sync
```

---

## 7. Usage & CLI Reference

NeuroDecomp can be invoked via `uv run javadecompiler` or `uv run python -m javadecompiler.cli`.

### Security Auditing
```bash
# 1. Offline Deterministic Security Scan (Zero Network, Zero LLM)
uv run javadecompiler untrusted_library.jar --security-scan --no-llm

# 2. CI/CD Quality Gate (Exit with code 2 if findings meet or exceed threshold)
uv run javadecompiler untrusted_library.jar --security-scan --no-llm --fail-on high

# 3. Export Machine-Readable Security Reports (JSON and SARIF 2.1.0 for GitHub Security)
uv run javadecompiler target.jar --security-scan --security-json report.json --security-sarif report.sarif

# 4. Live Hybrid LLM Security Audit via local Ollama
uv run javadecompiler target.jar --security-scan --llm-audit --audit-model qwen2.5-coder:14b

# 5. Hybrid LLM Audit with Self-Consistency Voting & Agentic Investigation
uv run javadecompiler target.jar --security-scan --llm-audit --llm-investigate --llm-votes 3

# 6. Launch the Interactive Drag-and-Drop Web UI
uv run javadecompiler --ui --port 8080
```

### Decompilation & Source Reconstruction
```bash
# Decompile and restore variable names with local Ollama
uv run javadecompiler Target.class

# Decompile in offline heuristic mode and generate dark-themed HTML report
uv run javadecompiler target.jar --no-llm --output-html report.html

# Export reconstructed .java source files to disk
uv run javadecompiler target.jar --output-dir ./decompiled_src/
```

### CLI Arguments Summary
| Flag | Description |
|---|---|
| `--security-scan` | Enable Phase 4 Security Auditor and Behavioral Analysis |
| `--llm-audit` | Enable Layer C local LLM auditor harness (Ollama) |
| `--audit-model MODEL` | Model for LLM security auditing (default: `qwen2.5-coder:14b`) |
| `--llm-scope {suspicious,all}` | Scope of methods audited by LLM (default: `suspicious`) |
| `--llm-investigate` | Enable bounded agentic investigator loop (max 8 steps) |
| `--llm-votes N` | Majority voting passes for adversarial verifier (default: `1`) |
| `--min-severity SEV` | Minimum finding severity to include in report (`info`, `low`, `medium`, `high`, `critical`) |
| `--fail-on SEV` | Exit with code 2 if any finding meets/exceeds severity (for CI quality gates) |
| `--security-json PATH` | Export security scan results to JSON file |
| `--security-sarif PATH` | Export security findings to SARIF 2.1.0 file (compatible with GitHub Code Scanning) |
| `--enable-rule RULE_ID` | Enable specific rule(s) by ID |
| `--disable-rule RULE_ID` | Disable specific rule(s) by ID |
| `--ui` | Launch the Interactive Drag-and-Drop Web UI server |
| `--port PORT` | Port for the Web UI server (default: `8080`) |
| `--no-llm` | Offline deterministic heuristic mode (zero network/LLM calls) |
| `--model MODEL` | Model for Phase 3 semantic variable restoration (default: `qwen2.5-coder:14b`) |
| `--output-html PATH` | Generate standalone multi-column dark HTML report |
| `--output-dir DIR` | Output directory for reconstructed `.java` source files |

---

## 8. Repository Layout

```
JavaDecompiler/
├── pyproject.toml                     # Dependencies, metadata & CLI entry points
├── README.md                          # Project documentation
├── howtorun.md                        # Step-by-step setup and run guide
├── docs/
│   ├── security.md                    # Phase 4 Security Auditor specification & catalog
│   └── security_plan.md               # Architectural design plan
├── scripts/
│   ├── build_fixtures.py              # Compiles base test fixtures & sample_library.jar
│   ├── build_security_corpus.py       # Compiles 42-class synthetic corpus
│   └── eval_security.py               # Benchmark runner & baseline regression evaluator
├── src/
│   └── javadecompiler/
│       ├── class_parser.py            # Phase 1: Binary parser, unpacker & CP resolver
│       ├── disassembler.py            # Phase 2: JVM disassembler with switch support
│       ├── cfg_builder.py             # Phase 2: BasicBlock builder & CFG edge wiring
│       ├── structurer.py              # Phase 2: Dominator tree & loop analyzer
│       ├── lifter.py                  # Phase 2: Symbolic stack simulator & AST lifter
│       ├── semantic_restorer.py       # Phase 3: OS context extractor & Ollama restorer
│       ├── report.py                  # Multi-column HTML report generator
│       ├── cli.py                     # Unified CLI runner
│       └── security/                  # Phase 4: Security Auditor Engine
│           ├── models.py              # Data classes (Finding, Evidence, ScanResult)
│           ├── jar_checks.py          # Container & archive hardening checks
│           ├── behavior.py            # Layer B behavior chains & taint-lite
│           ├── callgraph.py           # Whole-archive inter-method call graph
│           ├── scoring.py             # Weighted risk score & verdict math
│           ├── scanner.py             # Orchestrator integrating Phase 1-3 with Phase 4
│           ├── rules/                 # Layer A static rule families
│           │   ├── execution.py       # Command injection rules
│           │   ├── network.py         # Socket & DNS rules
│           │   ├── dynamic.py         # Reflection & dynamic loading rules
│           │   ├── deserialization.py # ObjectInputStream & gadget rules
│           │   ├── crypto.py          # Broken ciphers, weak hashes & keys
│           │   ├── injection.py       # SQLi, path traversal, XXE rules
│           │   ├── secrets.py         # Hardcoded tokens, AWS keys, PEMs
│           │   ├── evasion.py         # XOR decryption & debugger detection
│           │   ├── system.py          # Persistence & reconnaissance
│           │   └── loadtime.py        # <clinit> reachability triggers
│           ├── llm/                   # Layer C local LLM auditor harness
│           │   ├── client.py          # OllamaClient & FakeLlmClient
│           │   ├── schema.py          # Strict JSON schema validator & repair
│           │   ├── grounding.py       # Anti-hallucination evidence grounder
│           │   ├── context.py         # Prompt sanitization & budget chunking
│           │   ├── cache.py           # SHA-256 disk cache (.javadecompiler_cache/)
│           │   ├── harness.py         # Triage, deep-dive & synthesis harness
│           │   └── investigator.py    # Bounded agentic investigator loop
│           ├── reporting/             # Report generators
│           │   ├── json_out.py        # JSON serialization
│           │   ├── sarif.py           # SARIF 2.1.0 output
│           │   └── html_section.py    # HTML security report integration
│           └── ui/                    # Interactive Drag-and-Drop Web UI
│               ├── server.py          # Zero-dependency http.server backend
│               └── assets/            # SPA frontend (index.html, styles.css, app.js)
└── tests/
    ├── test_class_parser.py           # Phase 1 tests
    ├── test_disassembler.py           # Disassembler tests
    ├── test_lifter.py                 # Stack machine & AST lifter tests
    ├── test_semantic_restorer.py      # Phase 3 NLP tests
    ├── test_cli.py                    # CLI runner tests
    └── security/                      # Phase 4 Security Auditor test suite
        ├── test_models.py             # Finding/Evidence model tests
        ├── test_jar_checks.py         # Archive & container tests
        ├── test_rules_p1.py           # Execution, network, dynamic, crypto rules
        ├── test_rules_p2.py           # Injection, secrets, evasion, system rules
        ├── test_behavior.py           # Behavior chains & taint flows
        ├── test_scoring_scanner.py    # Scoring, verdicts & scanner tests
        ├── test_reporting.py          # HTML & SARIF reporting tests
        ├── test_llm_harness.py        # LLM client, schema, grounding tests
        ├── test_llm_verifier_investigator.py # Verifier & agentic investigator tests
        ├── test_corpus.py             # 42-class synthetic corpus tests
        ├── test_opcode_robustness.py  # Switch & invokedynamic tests
        └── test_ui_server.py          # Web UI server endpoint tests
```

---

## 9. Verification & Testing

Run the full automated test suite (all 90 tests, zero mocks required):
```bash
uv run python -m unittest discover tests
```

Output:
```text
Ran 90 tests in 2.560s
OK
```

Run the benchmark regression check:
```bash
uv run python scripts/eval_security.py --baseline tests/security_corpus/baseline_static.json
```

---

## 10. Academic & Course Outcome Alignment

NeuroDecomp directly fulfills systems and compiler engineering outcomes:

| Outcome | Focus Area | How NeuroDecomp Covers It |
|---|---|---|
| **CO1** | Low-Level Languages | Hexadecimal JVM opcode decoding, instruction offset resolution, variable-length switch alignment (`tableswitch`/`lookupswitch`), and byte-level disassembly. |
| **CO2** | Virtual Machines | Simulated stack machine execution model, tracking symbolic values pushed/popped across operand stacks and local variable slots. |
| **CO4** | Compilers & OS | Dominance frontier calculation, natural loop back-edge detection, CFG structuring, inter-procedural call-graph construction, and OS-level resource context extraction (sockets, files, crypto, process execution). |
