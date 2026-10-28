# How to Run NeuroDecomp (`JavaDecompiler`)

A step-by-step guide to install, verify, and run the **NeuroDecomp** Java bytecode
decompiler on a clean machine.

Everything here was executed and verified on Windows 11 + PowerShell with
**uv 0.13.6**, **CPython 3.10.22** (inside `.venv`), and **Temurin JDK 25**.
The same commands work on macOS/Linux — `bash` equivalents are given where they differ.

---

## 1. What you need

| Requirement | Version | Required for | Notes |
|---|---|---|---|
| Python | 3.10 or newer | Everything | `uv` will download a suitable interpreter automatically |
| [uv](https://docs.astral.sh/uv/) | 0.13.6 (latest) | Environment + dependency management | Only tool needed to install the project |
| JDK (`javac`, `jar`) | 11 or newer | Compiling the bundled Java test fixtures | **Not** needed to decompile existing `.class`/`.jar` files |
| [Ollama](https://ollama.com/) | any recent | Phase 3 LLM-based renaming/Javadoc | Optional — the tool falls back to a deterministic offline engine |
| git | any | Getting the latest code | Optional if you already have the source |

> Only Python 3.10+ and uv are needed to *run* the decompiler.
> The project has **zero third-party runtime dependencies** — it is built purely
> on the Python standard library (`struct`, `zipfile`, `urllib`, `dataclasses`, `typing`).

---

## 2. Quick start (TL;DR)

```powershell
# from the repository root
git pull
uv sync
uv run python scripts/build_fixtures.py      # compiles the Java test fixtures (needs a JDK)
uv run python -m unittest discover -s tests  # expect: Ran 17 tests ... OK
uv run javadecompiler sample_library.jar --no-llm --output-html report.html --output-dir decompiled_src
```

If `uv` is not on your PATH, see [Troubleshooting](#8-troubleshooting) — you can run it as
`python -m uv ...` instead.

---

## 3. Step-by-step setup

### 3.1 Get the latest code

```powershell
git pull
```

Verified state of this checkout: `main` is identical to `origin/main`
(commit `783faed`, the newest commit across all remote branches).

### 3.2 Install `uv` (skip if already installed)

Recommended (official installer, puts `uv` on PATH):

```powershell
# Windows PowerShell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Alternative if you already have Python and pip:

```powershell
python -m pip install --upgrade uv
```

Check it works:

```powershell
uv --version          # uv 0.13.6
python -m uv --version  # works too, even when uv is not on PATH
```

### 3.3 Create the virtual environment and install the project

`uv sync` creates `.venv/` in the repository root, installs a compatible CPython
(this project pins **3.10** in `.python-version`) and installs the project itself
in editable mode, including the `javadecompiler` console script.

```powershell
uv sync
```

Expected output (there are no third-party packages to download):

```
Using CPython 3.10.22
Creating virtual environment at: .venv
Resolved 1 package
Built javadecompiler @ file:///.../JavaDecompiler
Installed 1 package in 12ms
 + javadecompiler==0.1.0 (from file:///.../JavaDecompiler)
```

Upgrade everything to the newest resolvable versions at any time:

```powershell
uv lock --upgrade
uv sync --upgrade
```

### 3.4 Verify the install

```powershell
uv run python -c "import sys, javadecompiler, javadecompiler.cli, javadecompiler.report; print(sys.version.split()[0]); print('imports ok')"
uv run javadecompiler --help
```

Expected: `3.10.22`, `imports ok`, and the CLI usage banner listing
`input_path`, `--model`, `--no-llm`, `--output-html`, `--output-dir`, `-v`.

> Prefer the environment without `uv`? Activate it directly:
> `.venv\Scripts\Activate.ps1` (Windows) or `source .venv/bin/activate` (macOS/Linux),
> then run `python -m javadecompiler.cli ...`.

---

## 4. Build the Java test fixtures (required before running tests)

The repository stores the test fixtures (`src/javadecompiler/Java_Test_Files/`)
as **`.java` sources only** — compiled `*.class` / `*.jar` files are git-ignored.
The unit tests need the compiled forms, so build them once:

```powershell
uv run python scripts/build_fixtures.py
```

This compiles `EngineMath.java`, `LoopTest.java`, `CombinedTest.java` and
`NetworkCryptoService.java` in place with `javac`, then packages them into
`sample_library.jar` at the repository root (used by the JAR pipeline tests).

Requirements: a JDK on PATH (`javac -version` must work). If `javac` is missing,
the script exits with a clear message. Install Temurin/OpenJDK 11+ and retry.

---

## 5. Run the test suite

```powershell
uv run python -m unittest discover -s tests -v
```

Verified result:

```
Ran 17 tests in 0.023s

OK
```

Tests covered: `test_class_parser.py` (Phase 1), `test_disassembler.py`,
`test_lifter.py` (Phase 2), `test_semantic_restorer.py` (Phase 3, including a
mocked Ollama call), and `test_cli.py` (end-to-end single-class + JAR runs).

`test_pipeline_jar_archive` is **skipped** if `sample_library.jar` is absent —
running `scripts/build_fixtures.py` makes it run.

---

## 6. Run the decompiler

All commands below are run from the repository root.

### 6.1 A single class file

```powershell
uv run javadecompiler src/javadecompiler/Java_Test_Files/EngineMath.class --no-llm
```

### 6.2 A JAR archive

```powershell
uv run javadecompiler sample_library.jar --no-llm
```

### 6.3 Offline / deterministic mode (`--no-llm`)

Skips Ollama entirely and uses the built-in heuristic engine for variable
renaming and Javadoc. No network calls at all:

```powershell
uv run javadecompiler target.class --no-llm
```

Running **without** `--no-llm` is also safe: if Ollama is not reachable the tool
prints a notice and automatically falls back to the same heuristic engine:

```
[!] Ollama not reachable at http://localhost:11434. Engaging graceful Offline Heuristic Fallback.
```

### 6.4 Generate the HTML report

```powershell
uv run javadecompiler sample_library.jar --no-llm --output-html report.html
```

Produces a single self-contained dark-themed report with the metadata summary,
detected OS/resource badges, and the three side-by-side columns (bytecode/CFG,
raw pseudo-code, AI-restored source). Open `report.html` in any browser.

### 6.5 Export reconstructed `.java` files

```powershell
uv run javadecompiler sample_library.jar --no-llm --output-dir decompiled_src
```

Writes one `.java` file per class into `decompiled_src/` (the directory is
created automatically).

### 6.6 CLI reference

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
  --output-html PATH    Path to generate the multi-column side-by-side HTML report
  --output-dir DIR      Directory to save reconstructed .java files
  -v, --verbose         Enable detailed diagnostic logs
```

Equivalent invocation without the console script:

```powershell
uv run python -m javadecompiler.cli target.class --no-llm
```

Exit codes: `0` on success, `1` for a missing input file or a file that is not a
valid JVM class file (the failure is reported as a clean message, not a traceback).

---

## 7. Optional: enable the local LLM (Ollama)

1. Install [Ollama](https://ollama.com/download) and start it:
   ```powershell
   ollama serve
   ```
2. Pull a model:
   ```powershell
   ollama pull qwen2.5-coder:14b
   ```
3. Run without `--no-llm`, optionally choosing another model:
   ```powershell
   uv run javadecompiler target.class --model qwen2.5-coder:14b
   ```

The restorer probes `http://localhost:11434/api/tags` (2 s timeout) and calls
`/api/generate` per method (15 s timeout). Any error or timeout silently falls
back to the offline heuristic engine, so the pipeline never fails because of the LLM.

---

## 8. Batch runner (stress testing)

Walks a directory (or a JAR) of `.class` files and reports disassembly/CFG/
structuring failures:

```powershell
uv run python src/javadecompiler/run_batch.py src/javadecompiler/Java_Test_Files
uv run python src/javadecompiler/run_batch.py sample_library.jar cfg_maps
```

Verified summary for the bundled fixtures:

```
Methods processed: 12
Methods with at least one unrecognized opcode: 0
Per-class output written to: cfg_maps/
```

`cfg_maps/` is git-ignored.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `'uv' is not recognized as the name of a cmdlet...` | pip installed `uv.exe` into a Scripts directory that is not on PATH | Use `python -m uv <args>` (e.g. `python -m uv sync`), or run the official installer, or call `& "$env:APPDATA\Python\Python314\Scripts\uv.exe" sync` |
| `FileNotFoundError: ... EngineMath.class` when running tests | Fixtures were never compiled (only `.java` is committed) | `uv run python scripts/build_fixtures.py` |
| `javac not found on PATH` while building fixtures | No JDK installed | Install Temurin/OpenJDK 11+ and reopen the terminal |
| `[!] Ollama not reachable at http://localhost:11434` | Ollama daemon not running/model not pulled | Expected and harmless (heuristic fallback). Start `ollama serve` + `ollama pull <model>` to use the LLM |
| `Unrecognized opcode 0x..` / `NotImplementedError: Unsupported Constant Pool Tag` | Bytecode/class feature newer than the tables in `disassembler.py` / `class_parser.py` | Use `--no-llm` to keep the rest of the pipeline running, and extend the opcode table / constant-pool parser |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| Tests pass but a decompiled method looks wrong | Known Phase 2 limitation (e.g. `tableswitch`, uninitialized locals) | See "Future Scope" in `README.md`; the HTML report shows the raw bytecode for comparison |

---

## 10. Project layout (quick reference)

```
JavaDecompiler/
├── pyproject.toml                 # metadata, console script, uv build backend
├── uv.lock                        # exact lockfile (regenerate with `uv lock`)
├── .python-version                # interpreter pinned by uv (3.10)
├── .venv/                         # local virtual environment (git-ignored)
├── scripts/build_fixtures.py      # compiles Java fixtures + sample_library.jar
├── src/javadecompiler/
│   ├── class_parser.py            # Phase 1: class/JAR parsing, constant pool
│   ├── disassembler.py            # Phase 2: opcode decoding
│   ├── cfg_builder.py             # Phase 2: basic blocks + CFG edges
│   ├── structurer.py              # Phase 2: dominators, loops, if/while nesting
│   ├── lifter.py                  # Phase 2: symbolic stack machine -> pseudo-code
│   ├── semantic_restorer.py       # Phase 3: OS context, Ollama, heuristic fallback
│   ├── report.py                  # dark-themed side-by-side HTML report
│   ├── cli.py                     # unified CLI (`javadecompiler`)
│   ├── run_batch.py               # batch stress runner
│   └── Java_Test_Files/           # .java fixture sources (+ compiled output)
└── tests/                         # 17 unittest cases across 5 modules
```

---

## 11. Verified environment

| Item | Value |
|---|---|
| OS / shell | Windows 11, PowerShell |
| uv | 0.13.6 (2026-10-26) |
| Python (in `.venv`) | 3.10.22 |
| JDK | Temurin 25.0.1 (`javac 25.0.1`) |
| Runtime dependencies | none (standard library only) |
| Test result | `Ran 17 tests ... OK` |
| Pipeline checks | single `.class`, 4-class JAR, HTML report, `--output-dir`, batch runner, missing/invalid input handling — all exit 0 (or clean exit 1 for invalid input) |

To rebuild everything from scratch:

```powershell
Remove-Item -Recurse -Force .venv
uv sync
uv run python scripts/build_fixtures.py
uv run python -m unittest discover -s tests -v
```
