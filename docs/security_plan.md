# NeuroDecomp Security Auditing Layer (Phase 4) Implementation Plan

## 1. Executive Summary & Goals

Phase 4 extends NeuroDecomp from a 3-phase decompiler (`Phase 1: Binary Parser` -> `Phase 2: Disassembler & Lifter` -> `Phase 3: Semantic Restorer`) into a full-featured security auditing platform and interactive review tool:
1. **Deterministic Static Rule Engine (Layer A):** 10 rule families detecting vulnerabilities, suspicious malware indicators, and load-time execution vectors with zero external runtime dependencies (stdlib only).
2. **Behavior-Chain & Taint-Lite Detection (Layer B):** Intra-method def-use and 1-hop inter-procedural call graph summaries detecting multi-step exploit chains (reverse shells, droppers, decode-exec, exfiltration, time bombs).
3. **Evidence-Grounded LLM Auditor Harness (Layer C):** Local LLM (`qwen2.5-coder:14b` via Ollama) layered on top of static findings with strict JSON schema validation, automatic 1-step repair retry, evidence verification (anti-hallucination), prompt-injection hardening, self-consistency voting, and a bounded agentic investigator (max 8 steps).
4. **Standardized Reporting:** Schema-versioned JSON output, SARIF 2.1.0 output for GitHub/IDE integration, and an integrated multi-column HTML security report tab.
5. **Interactive Drag-and-Drop Web UI (`--ui`):** Zero-dependency local web interface (`http.server`) with a 3-pane IDE layout, class explorer, split-pane lifted Java vs bytecode/CP viewer with inline severity-coded line highlighting, expandable finding annotation cards, and instant scan trigger.
6. **Synthetic Benchmark Corpus & Evaluation Harness:** 42+ inert Java classes (`benign/`, `vulnerable/`, `suspicious/`), ground-truth `manifest.json`, and benchmark script evaluating precision, recall, false-positive rate, grounding rate, and prompt-injection resilience.

---

## 2. Package & File Layout

```text
src/javadecompiler/
├── security/
│   ├── __init__.py                # Single product name constant and version exports
│   ├── models.py                  # Finding, Evidence, Severity, Category, Verdict, ScanResult
│   ├── rules/
│   │   ├── __init__.py            # Export all rule sets & registry
│   │   ├── base.py                # SecurityRule base class, decorator, registry
│   │   ├── execution.py           # JD-EXEC-001, JD-EXEC-002, JD-EXEC-003
│   │   ├── network.py             # JD-NET-001, JD-NET-002, JD-NET-003
│   │   ├── dynamic.py             # JD-DYN-001, JD-DYN-002, JD-DYN-003
│   │   ├── deserialization.py     # JD-DESER-001, JD-DESER-002
│   │   ├── injection.py           # JD-INJ-001, JD-INJ-002, JD-INJ-003
│   │   ├── crypto.py              # JD-CRYP-001..005
│   │   ├── secrets.py             # JD-SEC-001 (Shannon entropy, regex, redaction)
│   │   ├── evasion.py             # JD-EVA-001..005 (Anti-AI prompt injection included)
│   │   ├── system.py              # JD-SYS-001, JD-SYS-002
│   │   └── loadtime.py            # JD-LOAD-001 (<clinit>, Agent-Class, ServiceLoader)
│   ├── behavior.py                # JD-CHAIN-001..007 (def-use & call-flow chains)
│   ├── jar_checks.py              # Archive limits, zip-slip, zip-bomb, malformed bytecode guard
│   ├── callgraph.py               # Lightweight intra-JAR call graph & reachability
│   ├── scoring.py                 # Risk score (0-100), severity weights, verdict aggregation
│   ├── scanner.py                 # Orchestrates Layer A + Layer B + Layer C + Scoring
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── client.py              # LlmClient ABC, OllamaClient (qwen2.5-coder:14b), FakeLlmClient
│   │   ├── prompts/               # Versioned prompt templates (.txt/.md)
│   │   │   ├── triage.txt
│   │   │   ├── deep_dive.txt
│   │   │   ├── synthesis.txt
│   │   │   ├── verify.txt
│   │   │   └── investigate.txt
│   │   ├── schema.py              # JSON schemas & stdlib validator & repair prompt
│   │   ├── harness.py             # Staged pipeline: triage -> deep-dive -> synthesis -> verify
│   │   ├── grounding.py           # Verification of I:0x.., CP:.., L:.. evidence IDs
│   │   ├── investigator.py        # 8-step bounded agentic JSON loop
│   │   ├── context.py             # Token budgeting, basic-block chunking, injection delimiter escaping
│   │   └── cache.py               # Disk cache in .javadecompiler_cache/
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── json_out.py            # JSON report formatter
│   │   ├── sarif.py               # SARIF 2.1.0 generator
│   │   └── html_section.py        # HTML section generator integrated with report.py
│   └── ui/
│       ├── __init__.py
│       ├── server.py              # Python http.server REST API (/api/scan, /api/health)
│       └── assets/
│           ├── index.html         # Modern dark-themed 3-pane IDE layout
│           ├── styles.css         # Responsive dark theme styling
│           └── app.js             # Drag & drop, code highlighting, finding inspector
scripts/
├── build_security_corpus.py       # Compiles inert Java test corpus
└── eval_security.py               # Benchmark harness (precision, recall, grounding, FPR)
tests/
├── security/                      # Unit, integration, fuzz, and UI tests
│   ├── test_models.py
│   ├── test_jar_checks.py
│   ├── test_rules_p1.py
│   ├── test_rules_p2.py
│   ├── test_behavior.py
│   ├── test_scoring_scanner.py
│   ├── test_reporting.py
│   ├── test_llm_harness.py
│   ├── test_llm_verifier_investigator.py
│   └── test_ui_server.py
└── security_corpus/               # Java test files & ground truth
    ├── benign/
    ├── vulnerable/
    ├── suspicious/
    ├── manifest.json
    └── baseline_static.json
docs/
├── security_plan.md               # This plan document
└── security.md                    # User and developer documentation
```

---

## 3. Public Interfaces Between Components

### 3.1 Data Model (`models.py`)
- `Finding`: Represents a discrete issue with unique stable `findingId`, `ruleId`, `title`, `description`, `remediation`, `kind`, `category`, `severity`, `confidence`, `cwe`, `location` (with line numbers and bytecode offsets), `evidence` list, and `origin`.
- `ScanResult`: Complete result containing `schemaVersion`, `inputSha256`, `overallVerdict`, `overallRiskScore`, `topReasons`, `classes` (dictionary of `ClassAnalysis`), `jarFindings`, `coverageStats`, and `llmStats`.
- Serialization via `to_dict()`, `from_dict()`, `to_json()`, `from_json()`.

### 3.2 Rules Framework (`rules/base.py`)
- `SecurityRule`: Base class defining metadata and two analysis hooks:
  - `analyze_class(class_info: ClassInfo, call_graph: Optional[CallGraph]) -> List[Finding]`
  - `analyze_method(class_info: ClassInfo, method_name: str, method_info: MethodInfo, lifted_lines: List[str], instructions: List[Dict[str, Any]], cfg: Dict[int, BasicBlock], call_graph: Optional[CallGraph]) -> List[Finding]`
- `@register_rule`: Decorator registering rule classes in a centralized registry with enable/disable filters.

### 3.3 Call Graph (`callgraph.py`)
- `CallGraph`: Builds intra-JAR caller-callee mappings and entry-point reachability (`<clinit>`, `main`, constructors, agents) from `ClassInfo` structures.

### 3.4 Behavior Chains (`behavior.py`)
- Detects multi-instruction patterns using intra-method def-use and call summaries. Produces ordered evidence chains (`source` -> `transform` -> `sink`).

### 3.5 Scanner Orchestrator (`scanner.py`)
- `SecurityScanner`: Configured with rules, LLM harness options, and archive limits.
- `scan_class(class_info: ClassInfo, raw_lifted: Optional[str] = None) -> ClassAnalysis`
- `scan_jar(jar_path: str) -> ScanResult`
- `scan_file(file_path: str) -> ScanResult`

### 3.6 LLM Harness (`llm/`)
- `LlmClient`: Abstract interface with `OllamaClient` and `FakeLlmClient`.
- `LlmAuditorHarness`: Coordinates triage -> deep-dive -> synthesis -> adversarial verification.
- `EvidenceGrounder`: Validates every cited `I:0x..`, `CP:..`, and `L:..` against genuine method artifacts.

### 3.7 Web UI Server (`ui/server.py`)
- Stdlib `http.server` supporting:
  - `GET /` and static assets (`styles.css`, `app.js`)
  - `GET /api/health` -> Ollama status, models, version
  - `POST /api/scan` -> multipart or JSON base64 upload, runs scanner in memory, returns `ScanResult`.

---

## 4. Milestone Schedule

- **Milestone 1:** Exploration, Plan & Scaffolding (`models.py`, `rules/base.py`, `FakeLlmClient`, CLI skeleton, unit tests).
- **Milestone 2:** Parser Hardening & Archive/JAR Checks (`jar_checks.py`, zip-slip/bomb guards, fuzz tests).
- **Milestone 3:** Static Rules Part 1 (`execution.py`, `network.py`, `dynamic.py`, `deserialization.py`, `crypto.py` + tests).
- **Milestone 4:** Static Rules Part 2 & Call Graph (`injection.py`, `secrets.py`, `evasion.py`, `system.py`, `callgraph.py`, `loadtime.py` + tests).
- **Milestone 5:** Behavior Chains & Taint-Lite (`behavior.py` 7 chains + tests).
- **Milestone 6:** Scoring, Verdicts, JSON & SARIF (`scoring.py`, `scanner.py`, `json_out.py`, `sarif.py`, CLI exit codes + tests).
- **Milestone 7:** HTML Report Integration (`html_section.py`, `report.py` update + tests).
- **Milestone 8:** LLM Auditor Harness Core (`OllamaClient`, prompts, `schema.py`, `context.py`, `cache.py`, `grounding.py`, triage/deep-dive + tests).
- **Milestone 9:** Adversarial Verifier, Self-Consistency & Bounded Investigator (`verify.txt`, `investigator.py` + tests).
- **Milestone 10:** Test Corpus, Live Evaluation & Documentation (42+ classes, `eval_security.py`, baseline, `docs/security.md`).
- **Milestone 11:** Interactive Drag-and-Drop Web UI (`ui/server.py`, `ui/assets/` + tests).
- **Milestone 12:** Modern Opcode Robustness (`invokedynamic` string concat / switch fallback, final audit).

---

## 5. Assumptions, Conflicts & Resolutions

1. **Pre-existing Code Preservation:**
   - Existing phases (1, 2, 3) must remain 100% functional.
   - Minor additive hooks: in `class_parser.py`, ensure access flags and raw bytes are accessible; in `lifter.py`, keep line numbers accessible or structure lifted output with line metadata.
2. **Unsupported Opcodes (`tableswitch`, `lookupswitch`, `invokedynamic`):**
   - Current `disassembler.py` raises `ValueError` if an unknown opcode is encountered.
   - Resolution: When disassembling for security scanning, if an unknown opcode occurs, fall back gracefully to constant-pool and raw-bytecode pattern matching, record `analysisCoverage: "partial"` with the reason, and ensure the method is never silently skipped.
3. **Local LLM Availability:**
   - Ollama with `qwen2.5-coder:14b` is running on `http://localhost:11434`.
   - In CI or offline test runs, `FakeLlmClient` allows 100% deterministic test execution. Live evaluation uses `OllamaClient`.
4. **Zero Third-Party Runtime Dependencies:**
   - All modules use standard library only (`dataclasses`, `json`, `hashlib`, `urllib`, `http.server`, `zipfile`, `re`, `math`).
