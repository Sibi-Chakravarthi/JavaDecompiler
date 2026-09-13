"""
run_batch.py

Walks a directory of compiled .class files, runs every method through the
full pipeline (parse -> disassemble -> CFG -> structure), and reports what
broke. Built for stress-testing the pipeline against a real multi-class
project rather than the single-method test fixtures.

Usage:
    python3 run_batch.py <directory-of-.class-files> [output-directory]
"""

import os
import re
import sys
from collections import Counter

from class_parser import parseClassDirectly
from disassembler import disassembleMethod
from cfg_builder import buildControlFlowGraph, printControlFlowGraphToString
from structurer import structureMethod, renderPseudocode


def findClassFiles(rootDirectory):
    classFilePaths = []
    for dirPath, _, fileNames in os.walk(rootDirectory):
        for fileName in fileNames:
            if fileName.endswith(".class"):
                classFilePaths.append(os.path.join(dirPath, fileName))
    return sorted(classFilePaths)


def runBatch(rootDirectory, outputDirectory):
    os.makedirs(outputDirectory, exist_ok=True)

    unknownOpcodeCounts = Counter()
    methodsProcessed = 0
    methodsWithUnknownOpcodes = 0
    structuringFailures = []
    parseFailures = []

    for classFilePath in findClassFiles(rootDirectory):
        relativeLabel = os.path.relpath(classFilePath, rootDirectory)
        try:
            methodBytecodes = parseClassDirectly(classFilePath)
        except Exception as error:  # noqa: BLE001 - want to keep going across the whole batch
            parseFailures.append((relativeLabel, repr(error)))
            continue

        outputLines = [f"=== {relativeLabel} ==="]

        for methodName, methodBytes in methodBytecodes.items():
            methodsProcessed += 1
            outputLines.append(f"\n--- {methodName} ---")

            try:
                instructions = disassembleMethod(methodName, methodBytes)
            except ValueError as error:
                methodsWithUnknownOpcodes += 1
                match = re.search(r"0x[0-9a-f]{2}", str(error))
                if match:
                    unknownOpcodeCounts[match.group(0)] += 1
                outputLines.append(f"[DISASSEMBLY FAILED] {error}")
                structuringFailures.append((relativeLabel, methodName, "disassembler", str(error)))
                continue

            try:
                cfg = buildControlFlowGraph(instructions)
                outputLines.append(printControlFlowGraphToString(cfg, methodName))
            except Exception as error:  # noqa: BLE001
                outputLines.append(f"[CFG BUILD FAILED] {error!r}")
                structuringFailures.append((relativeLabel, methodName, "cfg_builder", repr(error)))
                continue  # can't structure without a CFG

            try:
                tree = structureMethod(cfg)
                outputLines.append("--- structured pseudocode ---")
                outputLines.append("\n".join(renderPseudocode(tree)))
            except Exception as error:  # noqa: BLE001
                outputLines.append(f"[STRUCTURING FAILED] {error!r}")
                structuringFailures.append((relativeLabel, methodName, "structurer", repr(error)))

        safeFileName = relativeLabel.replace(os.sep, "_").replace(".class", ".txt")
        with open(os.path.join(outputDirectory, safeFileName), "w", encoding="utf-8") as outputFile:
            outputFile.write("\n".join(outputLines))

    # --- Summary report ---
    print(f"\n{'=' * 60}")
    print("BATCH SUMMARY")
    print(f"{'=' * 60}")
    print(f"Methods processed: {methodsProcessed}")
    print(f"Methods with at least one unrecognized opcode: {methodsWithUnknownOpcodes}")

    if parseFailures:
        print(f"\nClasses that failed to PARSE ({len(parseFailures)}):")
        for label, error in parseFailures:
            print(f"  {label}: {error}")

    if unknownOpcodeCounts:
        print(f"\nUnrecognized opcodes (add these to disassembler.py's jvmOpcodes table):")
        for opcodeHex, count in unknownOpcodeCounts.most_common():
            print(f"  {opcodeHex}: seen {count}x")

    if structuringFailures:
        print(f"\nCFG/structuring failures ({len(structuringFailures)}):")
        for classLabel, methodName, stage, error in structuringFailures:
            print(f"  {classLabel} :: {methodName} [{stage}]: {error}")

    print(f"\nPer-class output written to: {outputDirectory}/")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 run_batch.py <directory-of-.class-files> [output-directory]")
        sys.exit(1)

    inputDirectory = sys.argv[1]
    outDirectory = sys.argv[2] if len(sys.argv) > 2 else "cfg_maps"
    runBatch(inputDirectory, outDirectory)
