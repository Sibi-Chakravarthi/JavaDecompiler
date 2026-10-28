# NeuroDecomp Security Auditor & Behavioral Analysis (Phase 4)

## 1. Architectural Overview

NeuroDecomp Phase 4 extends the decompilation and semantic recovery pipeline with a multi-layered security auditor designed to detect both software vulnerabilities (unintentional flaws) and suspicious/malicious behaviors (intentional backdoors, droppers, info-stealers) inside JVM binaries.

```
       +-------------------------------------------------------------+
       |                  Hostile Java Binary (.class / .jar)         |
       +-------------------------------------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |  Archive & Parser Hardening (jar_checks.py)                 |
       |  Zip-bomb limits, zip-slip, embedded binaries, manifests    |
       +-------------------------------------------------------------+
                                      |
            +-------------------------+-------------------------+
            |                                                   |
            v                                                   v
+-------------------------------+               +-------------------------------+
| Layer A: Static Rule Engine   |               | Layer B: Behavior Chains      |
| 10 families, 30+ CWE rules    |               | 7 multi-step taint-lite flows |
+-------------------------------+               +-------------------------------+
            |                                                   |
            +-------------------------+-------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |  Layer C: Local LLM Auditor Harness (llm/)                  |
       |  - Staged: Triage -> Deep Dive -> Cross-Method Synthesis    |
       |  - Strict stdlib JSON Schema Validation + Auto-Repair Retry |
       |  - Anti-Hallucination Evidence Grounding (I:0x.., CP:, L:)  |
       |  - Adversarial Verifier (Devil's Advocate refutation)       |
       |  - Self-Consistency Majority Voting (--llm-votes N)         |
       |  - Bounded Agentic Investigator (--llm-investigate, <= 8 st)|
       +-------------------------------------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |  Scoring & Verdict Engine (scoring.py)                      |
       |  0–100 Weighted Score, Verdicts: CLEAN -> LIKELY_MALICIOUS   |
       +-------------------------------------------------------------+
                                      |
            +-------------------------+-------------------------+
            |                         |                         |
            v                         v                         v
       CLI Table / Fail-On        JSON & SARIF 2.1.0        Dark-Themed HTML & Web UI
```

---

## 2. Rule Catalog

### 2.1 Archive & Parser Hardening (`jar_checks.py`)
- `JD-ARCH-ZIPSLIP`: Path traversal filename in archive entry (`..`, `/`, `\`).
- `JD-ARCH-ZIPBOMB`: Abnormal compression ratio (> 100:1) or total uncompressed size limit exceeded (> 256 MB).
- `JD-ARCH-NATIVE`: Embedded native dynamic library (`.dll`, `.so`, `.dylib`, or `MZ`/ELF magic header).
- `JD-ARCH-MANIFEST-AGENT`: Premain/Agent-Class defined in `META-INF/MANIFEST.MF`.
- `JD-ARCH-CLASSPATH-REMOTE`: Remote HTTP/FTP URL in `Class-Path` manifest attribute.
- `JD-ARCH-SPI`: `META-INF/services/` ServiceLoader dynamic provider registration.
- `JD-ARCH-MALFORMED`: Corrupted or truncated class/archive payload guarded gracefully.
- `JD-ARCH-MISMATCH`: Declared class name does not match archive entry path.

### 2.2 Layer A: Deterministic Static Rules (`rules/`)
1. **Execution (`execution.py`):**
   - `JD-EXEC-001` (CWE-78): Command injection via `Runtime.getRuntime().exec` or `ProcessBuilder`.
2. **Network (`network.py`):**
   - `JD-NET-001` (CWE-319): Raw network socket creation (`new Socket`, `ServerSocket`, `DatagramSocket`).
   - `JD-NET-002`: Hardcoded public IPv4 addresses in constant pool or code.
   - `JD-NET-003` (CWE-359): Potential DNS exfiltration via `InetAddress.getByName`.
3. **Dynamic Loading & Reflection (`dynamic.py`):**
   - `JD-DYN-001` (CWE-470): Reflection via `Class.forName` or `Method.invoke`.
   - `JD-DYN-002` (CWE-470): Dynamic class loading via `URLClassLoader` or custom `ClassLoader.defineClass`.
   - `JD-DYN-003` (CWE-502): Dynamic JNDI lookup via `InitialContext.lookup`.
   - `JD-DYN-004` (CWE-94): Embedded scripting engine via `ScriptEngineManager.eval`.
   - `JD-DYN-005`: Direct usage of `sun.misc.Unsafe`.
4. **Deserialization (`deserialization.py`):**
   - `JD-DESER-001` (CWE-502): Unsafe Java object deserialization via `ObjectInputStream.readObject`.
   - `JD-DESER-002` (CWE-502): Deserialization via `XMLDecoder.readObject`.
   - `JD-DESER-003` (CWE-502): Custom `readObject` gadget definition.
5. **Injection (`injection.py`):**
   - `JD-INJ-001` (CWE-89): SQL injection via dynamic string concatenation in queries.
   - `JD-INJ-002` (CWE-22): Path traversal without canonical prefix checks.
   - `JD-INJ-003` (CWE-611): XML External Entity (XXE) injection via insecure XML parser configuration.
6. **Cryptography (`crypto.py`):**
   - `JD-CRYP-001` (CWE-328): Weak hash algorithm (`MD5`, `SHA-1`).
   - `JD-CRYP-002` (CWE-327): Weak or broken cipher (`DES`, `RC4`, `AES/ECB`).
   - `JD-CRYP-003` (CWE-321): Hardcoded constant cryptographic key or static IV parameter.
   - `JD-CRYP-004` (CWE-330): Use of predictable `java.util.Random` in security-sensitive methods.
   - `JD-CRYP-005` (CWE-295): Trust-all `X509TrustManager` or permissive `HostnameVerifier`.
7. **Secrets (`secrets.py`):**
   - `JD-SEC-001` (CWE-798): Hardcoded credentials, AWS keys, GitHub tokens, PEM private keys, or high-entropy string constants. Redacted automatically in all outputs.
8. **Evasion & Obfuscation (`evasion.py`):**
   - `JD-EVA-001`: XOR or byte-manipulation decryption loop feeding a dangerous sink.
   - `JD-EVA-002`: Base64 decode flowing into reflection or execution.
   - `JD-EVA-003`: Sandbox or debugger detection (`getInputArguments` checking for `jdwp`).
   - `JD-EVA-004`: Time bomb or logic bomb guarding execution with timestamps.
   - `JD-EVA-005`: Prompt-injection attack strings attempting to subvert AI analyzers.
9. **System & Persistence (`system.py`):**
   - `JD-SYS-001`: Persistence mechanisms (`addShutdownHook`, `setSecurityManager`, `loadLibrary`).
   - `JD-SYS-002`: Sensitive host reconnaissance (`System.getenv`, `.ssh`, `.aws`, `user.home`).
10. **Load-Time Triggers (`loadtime.py`):**
    - `JD-LOAD-001` (CWE-506): Dangerous sinks reachable from `<clinit>`, `Premain-Class`, or agents. Automatically escalates severity by +1 level.

### 2.3 Layer B: Multi-Step Behavior Chains (`behavior.py`)
- `JD-CHAIN-REVSHELL`: Reverse shell stream piping connecting network socket to process streams.
- `JD-CHAIN-DROPPER`: Network stream read -> file write -> process execution.
- `JD-CHAIN-DECODE-EXEC`: Encoded string constant -> Base64/XOR decode -> execution.
- `JD-CHAIN-EXFIL`: Sensitive file or environment read -> network output stream.
- `JD-CHAIN-TAINT-SINK`: Method parameters flowing through string concatenation into dangerous sinks.
- `JD-CHAIN-TIMEBOMB`: Time/date comparison guarding a dangerous sink.
- `JD-CHAIN-CLINIT`: `<clinit>` load-time invocation of dangerous sinks.

---

## 3. Scoring & Verdict Math

The Risk Score (0–100) is calculated using a calibrated weighted formula:
```text
Base Finding Weights:
  Critical: 40 points
  High:     25 points
  Medium:   12 points
  Low:       4 points
  Info:      1 point

Score = Sum(Weight * Confidence * CategoryDecay) + MultiCategoryBonus + LoadTimeBonus
```

- **Category Decay:** Duplicate findings in the same category provide diminishing returns (0.8x for 2nd, 0.6x for 3rd, 0.4x thereafter).
- **Multi-Category Bonus:** +15 points when findings span multiple critical categories (e.g., `execution` + `network` + `evasion`).
- **Load-Time Bonus:** +15 points when dangerous sinks are reachable automatically during class load (`<clinit>`).
- **Verdicts:**
  - `0.0`: **CLEAN** (if 100% full coverage; partial coverage downgrades to **REVIEW_RECOMMENDED**)
  - `0.1 – 24.9`: **REVIEW_RECOMMENDED** (or **VULNERABLE** if a vulnerability rule is flagged)
  - `25.0 – 49.9`: **VULNERABLE**
  - `50.0 – 69.9`: **SUSPICIOUS**
  - `70.0 – 100.0`: **LIKELY_MALICIOUS**

---

## 4. LLM Auditor Harness (Layer C)

When `--llm-audit` is enabled, NeuroDecomp pairs local LLM auditing (`qwen2.5-coder:14b` via Ollama) with strict anti-hallucination guardrails:
1. **Prompt Sanitization:** Wraps code in random boundary tokens (`<UNTRUSTED_TARGET_DATA_xxx>`) and defuses closing tags and prompt-injection phrases.
2. **Schema Validation & Repair:** All model responses are validated against a strict JSON schema. If the model outputs malformed JSON, an automatic repair prompt is generated for a single-step retry.
3. **Anti-Hallucination Evidence Grounding:** Every evidence citation emitted by the model (`I:0x..`, `CP:..`, `L:..`) is verified against actual bytecode instruction offsets, constant pool indices, and lifted line numbers.
   - If 0 cited evidence IDs exist, the finding is discarded completely (`ungroundedDropped`).
   - If partial citations exist, invalid IDs are stripped and confidence is scaled by `* 0.6`.
   - LLM-only findings are capped at `medium` severity.
4. **Adversarial Verifier (Devil's Advocate):** For all LLM findings with severity >= medium, an adversarial pass challenges the model to refute the finding using only code evidence.
5. **Self-Consistency Voting (`--llm-votes N`):** Runs multiple verification queries and takes the majority verdict. Refuted findings are dropped.
6. **Bounded Agentic Investigator (`--llm-investigate`):** For complex cases, an agent loop takes up to 8 strictly read-only analytical actions (`getMethodBytecode`, `getLiftedSource`, `getCallers`, `getCallees`, `getConstants`, `getStaticFindings`).

---

## 5. Usage & CLI Flags

### 5.1 CLI Scanning
```powershell
# 1. Offline Deterministic Security Scan (Zero Network, Zero LLM)
uv run python -m javadecompiler.cli target.jar --security-scan --no-llm

# 2. CI Quality Gate with Failure Threshold
uv run python -m javadecompiler.cli target.jar --security-scan --no-llm --fail-on high

# 3. Export to JSON & SARIF 2.1.0
uv run python -m javadecompiler.cli target.jar --security-scan --security-json report.json --security-sarif report.sarif

# 4. Live Hybrid Scan with Local Ollama qwen2.5-coder:14b
uv run python -m javadecompiler.cli target.jar --security-scan --llm-audit --audit-model qwen2.5-coder:14b

# 5. Hybrid Scan with Adversarial Voting & Agentic Investigator
uv run python -m javadecompiler.cli target.jar --security-scan --llm-audit --llm-investigate --llm-votes 3
```

### 5.2 Interactive Drag-and-Drop Web UI
```powershell
uv run python -m javadecompiler.cli --ui --port 8080
```
Then open `http://localhost:8080` in your browser. Drag and drop any `.class` or `.jar` file to view real-time decompilation and highlighted inline vulnerability banners.
