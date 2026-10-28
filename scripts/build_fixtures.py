#!/usr/bin/env python3
"""Compile the Java test fixtures required by the NeuroDecomp test suite.

The repository intentionally ships only the ``.java`` sources of its fixtures
(``*.class`` / ``*.jar`` are ignored by git). The unittest suite needs the
compiled forms, so this script:

  1. compiles every ``.java`` file in ``src/javadecompiler/Java_Test_Files``
     with ``javac`` (same directory, no external classpath), and
  2. packages the resulting ``.class`` files into ``sample_library.jar`` at the
     repository root, which exercises the JAR code path in ``parseJarFile``.

Usage:
    uv run python scripts/build_fixtures.py

Requires a JDK (``javac``) on PATH.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "src" / "javadecompiler" / "Java_Test_Files"
JAR_PATH = REPO_ROOT / "sample_library.jar"


def run(command: list[str], cwd: Path) -> None:
    printable = " ".join(command)
    print(f"[+] {printable}")
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.rstrip())
    if result.returncode != 0:
        print(result.stderr.rstrip(), file=sys.stderr)
        raise SystemExit(f"[!] Command failed with exit code {result.returncode}: {printable}")


def main() -> int:
    if shutil.which("javac") is None:
        raise SystemExit("[!] javac not found on PATH. Install a JDK 11+ and retry.")

    java_sources = sorted(FIXTURE_DIR.glob("*.java"))
    if not java_sources:
        raise SystemExit(f"[!] No .java fixtures found in {FIXTURE_DIR}")

    run(["javac", *[source.name for source in java_sources]], cwd=FIXTURE_DIR)

    class_files = sorted(FIXTURE_DIR.glob("*.class"))
    if not class_files:
        raise SystemExit("[!] javac produced no .class files")

    run(["jar", "--create", "--file", str(JAR_PATH), *[path.name for path in class_files]], cwd=FIXTURE_DIR)

    print(f"\n[+] Compiled {len(class_files)} fixture class file(s) in {FIXTURE_DIR}")
    for class_file in class_files:
        print(f"    - {class_file.name}")
    print(f"[+] Wrote {JAR_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
