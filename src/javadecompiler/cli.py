"""
cli.py — Unified Command Line Interface for NeuroDecomp

Usage:
    uv run python -m javadecompiler.cli <path-to-.class-or-.jar> [options]
    uv run javadecompiler <path-to-.class-or-.jar> [options]
"""

import argparse
import os
import sys
import time
from typing import Dict, List

try:
    from javadecompiler.class_parser import ClassInfo, parseClassFile, parseJarFile
    from javadecompiler.lifter import liftMethod
    from javadecompiler.semantic_restorer import (
        RestorationResult,
        SemanticRestorer,
        extractOsContext,
        restoreClassSemantics,
    )
    from javadecompiler.report import generateHtmlReport
except ImportError:
    from class_parser import ClassInfo, parseClassFile, parseJarFile
    from lifter import liftMethod
    from semantic_restorer import (
        RestorationResult,
        SemanticRestorer,
        extractOsContext,
        restoreClassSemantics,
    )
    from report import generateHtmlReport


def print_banner() -> None:
    banner = r"""
  _   _                      _____                             
 | \ | |                    |  __ \                            
 |  \| | ___ _   _ _ __ ___ | |  | | ___  ___ ___  _ __ ___    
 | . ` |/ _ \ | | | '__/ _ \| |  | |/ _ \/ __/ _ \| '_ ` _ \   
 | |\  |  __/ |_| | | | (_) | |__| |  __/ (_| (_) | | | | | |  
 |_| \_|\___|\__,_|_|  \___/|_____/ \___|\___\___/|_| |_| |_|  
   AI-Powered Java Bytecode Decompiler & Semantic Restorer
"""
    print(banner)


def run_pipeline(
    input_path: str,
    model: str = "qwen2.5-coder:14b",
    no_llm: bool = False,
    output_html: str = "",
    output_dir: str = "",
    verbose: bool = False,
) -> int:
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        return 1

    is_jar = input_path.endswith(".jar")
    print(f"\n[*] Target: {input_path} ({'JAR Archive' if is_jar else 'Single Class'})")

    # =========================================================================
    # PHASE 1: Binary Parser & Unpacker
    # =========================================================================
    print("\n" + "=" * 65)
    print("[PHASE 1] Unpacking & Binary Class Parsing")
    print("=" * 65)
    t0 = time.time()

    classes: List[ClassInfo] = []
    try:
        if is_jar:
            print(f"[-] Unpacking JAR archive...")
            classes = parseJarFile(input_path)
            print(f"[+] Extracted and parsed {len(classes)} class file(s) from JAR.")
        else:
            classes = [parseClassFile(input_path)]
            print(f"[+] Parsed class file: {classes[0].class_name}")

        for cInfo in classes:
            print(f"    - {cInfo.class_name} (version {cInfo.major_version}.{cInfo.minor_version}, "
                  f"{len(cInfo.constant_pool)} CP entries, {len(cInfo.methods)} methods)")

    except Exception as e:
        print(f"[!] Phase 1 failed: {e}")
        return 1

    t1 = time.time()
    print(f"[Phase 1 complete in {(t1 - t0):.2f}s]")

    # =========================================================================
    # PHASE 2: Disassembler, CFG Builder & Symbolic Stack Lifter
    # =========================================================================
    print("\n" + "=" * 65)
    print("[PHASE 2] JVM Disassembly, CFG Structuring & Symbolic Stack Lifting")
    print("=" * 65)
    t2 = time.time()

    raw_methods: Dict[str, Dict[str, str]] = {}

    for cInfo in classes:
        cName = cInfo.class_name
        raw_methods[cName] = {}
        print(f"\n[-] Lifting class {cName}:")

        for mName, mInfo in cInfo.methods.items():
            if not mInfo.bytecode:
                continue
            try:
                lifted_code = liftMethod(cInfo, mName, mInfo)
                raw_methods[cName][mName] = lifted_code
                print(f"    [+] Method '{mName}': successfully lifted ({len(mInfo.bytecode)} bytecode bytes)")
            except Exception as e:
                print(f"    [!] Method '{mName}' lifting error: {e}")
                raw_methods[cName][mName] = f"// Error lifting {mName}: {e}"

    t3 = time.time()
    print(f"\n[Phase 2 complete in {(t3 - t2):.2f}s]")

    # =========================================================================
    # PHASE 3: NLP Semantic Recovery
    # =========================================================================
    print("\n" + "=" * 65)
    print("[PHASE 3] NLP Semantic Variable Recovery & Javadoc Generation")
    print("=" * 65)
    t4 = time.time()

    restorer = SemanticRestorer(model=model, no_llm=no_llm)
    active_engine = "Deterministic Offline Heuristic" if no_llm else f"Local LLM ({model})"
    if not no_llm:
        if restorer.isOllamaAvailable():
            print(f"[-] Connected to local Ollama daemon at {restorer.host} (model: {model})")
        else:
            print(f"[!] Ollama not reachable at {restorer.host}. Engaging graceful Offline Heuristic Fallback.")
            active_engine = "Offline Heuristic Fallback"

    restored_methods: Dict[str, Dict[str, RestorationResult]] = {}

    for cInfo in classes:
        cName = cInfo.class_name
        restored_methods[cName] = {}
        cRaw = raw_methods.get(cName, {})

        # Whole class OS context
        whole_ctx = extractOsContext(cInfo)
        print(f"\n[-] Class: {cName}")
        print(f"    OS Context: {whole_ctx.summary()}")

        for mName, rawCode in cRaw.items():
            mInfo = cInfo.methods.get(mName)
            mCtx = extractOsContext(cInfo, mName, rawCode, mInfo)
            res = restorer.restoreMethod(cInfo, mName, rawCode)
            restored_methods[cName][mName] = res

            renamed_str = ", ".join(f"{k}->{v}" for k, v in list(res.renamed_variables.items())[:4])
            print(f"    [+] Method '{mName}' [{res.mode}]: {len(res.renamed_variables)} vars restored ({renamed_str or 'none'})")

    t5 = time.time()
    print(f"\n[Phase 3 complete in {(t5 - t4):.2f}s]")

    # =========================================================================
    # Terminal Display of Reconstructed Code
    # =========================================================================
    print("\n" + "=" * 65)
    print("RECONSTRUCTED SOURCE CODE SUMMARY")
    print("=" * 65)

    for cInfo in classes:
        cName = cInfo.class_name
        print(f"\n// ==================== Class: {cName} ====================")
        for mName, res in restored_methods[cName].items():
            print(f"\n{res.reconstructed_code}")

    # =========================================================================
    # Output File Writing (Directory / HTML)
    # =========================================================================
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        for cInfo in classes:
            cName = cInfo.class_name.split('/')[-1].split('.')[-1]
            outPath = os.path.join(output_dir, f"{cName}.java")
            with open(outPath, "w", encoding="utf-8") as f:
                f.write(f"// Decompiled by NeuroDecomp\n\n")
                f.write(f"public class {cName} {{\n\n")
                for mName, res in restored_methods[cInfo.class_name].items():
                    # Indent
                    indented = "\n".join("    " + line for line in res.reconstructed_code.splitlines())
                    f.write(f"{indented}\n\n")
                f.write("}\n")
        print(f"\n[+] Saved decompiled .java source files to: {output_dir}/")

    if output_html:
        html_content = generateHtmlReport(
            classes=classes,
            raw_methods=raw_methods,
            restored_methods=restored_methods,
            target_name=os.path.basename(input_path),
            ai_engine=active_engine,
        )
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] Multi-column Dark-Themed HTML report generated: {output_html}")

    print("\n[+] Pipeline execution finished successfully.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="javadecompiler",
        description="NeuroDecomp: AI-Powered Java Bytecode Decompiler & Semantic Restorer",
    )
    parser.add_argument(
        "input_path",
        help="Path to target .class file or .jar archive",
    )
    parser.add_argument(
        "--model",
        default="qwen2.5-coder:14b",
        help="Ollama model name for Phase 3 semantic recovery (default: qwen2.5-coder:14b)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Run in offline mode (Phases 1 & 2 + deterministic heuristic Javadoc/renaming)",
    )
    parser.add_argument(
        "--output-html",
        metavar="PATH.html",
        default="",
        help="Path to generate the multi-column side-by-side HTML report",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default="",
        help="Directory to save reconstructed .java files",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed diagnostic logs",
    )

    args = parser.parse_args()
    print_banner()
    sys.exit(run_pipeline(
        input_path=args.input_path,
        model=args.model,
        no_llm=args.no_llm,
        output_html=args.output_html,
        output_dir=args.output_dir,
        verbose=args.verbose,
    ))


if __name__ == "__main__":
    main()
