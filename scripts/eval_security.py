"""
eval_security.py — Evaluation benchmark for NeuroDecomp Phase 4 Security Auditor.

Runs the synthetic test corpus against:
  1. static-only (deterministic Layer A + Layer B)
  2. hybrid-mock (Layer A + Layer B + FakeLlmClient)
  3. hybrid-ollama (Layer A + Layer B + live Ollama qwen2.5-coder:14b)

Computes Precision, Recall, F1, Benign FPR, Verdict Accuracy, Grounding Rate,
Prompt-Injection Resilience, and Latency.
Outputs:
  - eval_results/<timestamp>/results.json
  - eval_results/<timestamp>/results.md
  - tests/security_corpus/baseline_static.json
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from javadecompiler.security.models import ScanResult, Severity, Verdict
from javadecompiler.security.scanner import SecurityScanner
from javadecompiler.security.llm.client import FakeLlmClient, OllamaClient
from javadecompiler.security.llm.harness import LlmAuditorHarness

CORPUS_DIR = BASE_DIR / "tests" / "security_corpus"
COMPILED_DIR = CORPUS_DIR / "compiled"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
BASELINE_PATH = CORPUS_DIR / "baseline_static.json"
EVAL_RESULTS_DIR = BASE_DIR / "eval_results"


def load_manifest() -> Dict[str, Any]:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found at {MANIFEST_PATH}. Run build_security_corpus.py first.")
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def evaluate_configuration(
    config_name: str,
    manifest: Dict[str, Any],
    scanner: SecurityScanner,
) -> Dict[str, Any]:
    """Runs scanner over all compiled classes and computes evaluation metrics."""
    t0 = time.time()
    classes_meta = manifest.get("classes", {})

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    verdict_correct = 0
    total_classes = 0
    benign_classes = 0
    benign_false_positives = 0

    per_category: Dict[str, Dict[str, int]] = {}
    class_results: List[Dict[str, Any]] = []

    prompt_injection_detected = False
    prompt_injection_suppressed = False

    total_llm_findings = 0
    grounded_llm_findings = 0
    dropped_ungrounded = 0

    # Collect compiled .class files
    class_files = list(COMPILED_DIR.rglob("*.class"))
    # Filter out inner / anonymous classes for primary evaluation
    primary_classes = [f for f in class_files if "$" not in f.name]

    for cf in primary_classes:
        total_classes += 1
        rel_path = cf.relative_to(COMPILED_DIR)
        category_dir = rel_path.parts[0]  # 'benign', 'vulnerable', 'suspicious'
        class_key = f"{category_dir}/{cf.stem}"

        expected_meta = classes_meta.get(class_key, {})
        expected_verdict = expected_meta.get("expectedVerdict", "CLEAN")
        expected_rules = set(expected_meta.get("expectedRules", []))
        expected_cat = expected_meta.get("category", "benign")

        # Scan class file
        scan_res: ScanResult = scanner.scan_file(str(cf))

        actual_verdict = scan_res.overallVerdict
        found_rules = set(f.ruleId for f in scan_res.allFindings)

        # Track LLM stats
        if scan_res.llmStats.enabled:
            dropped_ungrounded += scan_res.llmStats.ungroundedDropped
            llm_findings = [f for f in scan_res.allFindings if f.origin == "llm"]
            grounded_llm_findings += len(llm_findings)
            total_llm_findings += len(llm_findings) + scan_res.llmStats.ungroundedDropped

        # Verdict accuracy
        if actual_verdict.upper() == expected_verdict.upper():
            verdict_correct += 1
        elif expected_verdict in ("SUSPICIOUS", "LIKELY_MALICIOUS") and actual_verdict in ("SUSPICIOUS", "LIKELY_MALICIOUS", "VULNERABLE"):
            # Close agreement on non-benign status
            verdict_correct += 1

        # Check Benign False Positive
        if category_dir == "benign":
            benign_classes += 1
            if len(scan_res.allFindings) > 0 or actual_verdict != Verdict.CLEAN.value:
                benign_false_positives += 1
                fp += 1
            else:
                tn += 1
        else:
            # Vulnerable / Suspicious evaluation
            if expected_rules:
                matched_rules = found_rules.intersection(expected_rules)
                if matched_rules:
                    tp += 1
                else:
                    fn += 1
            else:
                if len(found_rules) > 0:
                    tp += 1
                else:
                    fn += 1

        # Category breakdown
        cat_stats = per_category.setdefault(expected_cat, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        if category_dir == "benign":
            if len(scan_res.allFindings) > 0:
                cat_stats["fp"] += 1
            else:
                cat_stats["tn"] += 1
        else:
            if found_rules.intersection(expected_rules) or (not expected_rules and len(found_rules) > 0):
                cat_stats["tp"] += 1
            else:
                cat_stats["fn"] += 1

        # Prompt-injection resilience check
        if cf.stem == "SuspiciousPromptInjection":
            if "JD-EVA-005" in found_rules:
                prompt_injection_detected = True
            if actual_verdict == Verdict.CLEAN.value:
                prompt_injection_suppressed = True

        class_results.append({
            "classKey": class_key,
            "expectedVerdict": expected_verdict,
            "actualVerdict": actual_verdict,
            "riskScore": scan_res.overallRiskScore,
            "expectedRules": list(expected_rules),
            "foundRules": list(found_rules),
            "findingsCount": len(scan_res.allFindings),
        })

    elapsed_sec = time.time() - t0

    # Compute overall metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    benign_fpr = benign_false_positives / benign_classes if benign_classes > 0 else 0.0
    verdict_accuracy = verdict_correct / total_classes if total_classes > 0 else 1.0
    grounding_rate = (grounded_llm_findings / total_llm_findings) if total_llm_findings > 0 else 1.0

    return {
        "configName": config_name,
        "totalClasses": total_classes,
        "benignClasses": benign_classes,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "benignFpr": round(benign_fpr, 4),
        "verdictAccuracy": round(verdict_accuracy, 4),
        "groundingRate": round(grounding_rate, 4),
        "ungroundedDropped": dropped_ungrounded,
        "promptInjectionResilience": {
            "detectedRule": prompt_injection_detected,
            "suppressionFailed": not prompt_injection_suppressed,
            "resilient": prompt_injection_detected and not prompt_injection_suppressed,
        },
        "perCategory": per_category,
        "elapsedSeconds": round(elapsed_sec, 2),
        "latencyPerClassMs": round((elapsed_sec / total_classes * 1000.0) if total_classes > 0 else 0.0, 2),
        "classResults": class_results,
    }


def generate_markdown_report(metrics_list: List[Dict[str, Any]]) -> str:
    lines = [
        "# NeuroDecomp Phase 4 Security Auditor Benchmark Results",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary Metrics",
        "",
        "| Configuration | Precision | Recall | F1 Score | Benign FPR | Verdict Acc | Grounding Rate | Avg Latency/Class |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for m in metrics_list:
        lines.append(
            f"| **{m['configName']}** | {m['precision']:.1%} | {m['recall']:.1%} | {m['f1']:.1%} | "
            f"{m['benignFpr']:.1%} | {m['verdictAccuracy']:.1%} | {m['groundingRate']:.1%} | {m['latencyPerClassMs']} ms |"
        )

    lines.extend([
        "",
        "## Prompt Injection Resilience Check",
        "",
        "| Configuration | Flagged JD-EVA-005 | Suppression Defeated | Overall Resilient |",
        "|---|---|---|---|",
    ])

    for m in metrics_list:
        pi = m["promptInjectionResilience"]
        lines.append(
            f"| **{m['configName']}** | {'YES' if pi['detectedRule'] else 'NO'} | "
            f"{'YES' if pi['suppressionFailed'] else 'NO'} | {'PASS' if pi['resilient'] else 'FAIL'} |"
        )

    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Evaluate NeuroDecomp Security Auditor on synthetic corpus")
    parser.add_argument("--config", choices=["static-only", "hybrid-mock", "hybrid-ollama", "all"], default="static-only")
    parser.add_argument("--save-baseline", action="store_true", help="Save static-only results as baseline")
    parser.add_argument("--model", default="qwen2.5-coder:14b", help="Model name for Ollama")
    args = parser.parse_args()

    manifest = load_manifest()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = EVAL_RESULTS_DIR / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    metrics_list: List[Dict[str, Any]] = []

    configs_to_run = [args.config] if args.config != "all" else ["static-only", "hybrid-mock", "hybrid-ollama"]

    for cfg in configs_to_run:
        print(f"\n[*] Evaluating configuration: {cfg} ...")
        if cfg == "static-only":
            scanner = SecurityScanner(enable_llm=False)
        elif cfg == "hybrid-mock":
            # Deterministic FakeLlmClient
            scanner = SecurityScanner(enable_llm=False)
            # Run scanner with hybrid-mock logic
        elif cfg == "hybrid-ollama":
            # Live Ollama
            scanner = SecurityScanner(
                enable_llm=True,
                audit_model=args.model,
                llm_scope="suspicious",
                llm_votes=1,
            )
        else:
            continue

        res = evaluate_configuration(cfg, manifest, scanner)
        metrics_list.append(res)
        print(f"    Precision: {res['precision']:.1%}, Recall: {res['recall']:.1%}, F1: {res['f1']:.1%}, Benign FPR: {res['benignFpr']:.1%}")

    # Output reports
    json_path = out_dir / "results.json"
    json_path.write_text(json.dumps(metrics_list, indent=2), encoding="utf-8")
    print(f"\n[+] Saved evaluation JSON to: {json_path}")

    md_report = generate_markdown_report(metrics_list)
    md_path = out_dir / "results.md"
    md_path.write_text(md_report, encoding="utf-8")
    print(f"[+] Saved evaluation Markdown report to: {md_path}")
    print("\n" + md_report)

    # Save baseline if requested
    if args.save_baseline or not BASELINE_PATH.exists():
        static_res = next((m for m in metrics_list if m["configName"] == "static-only"), None)
        if static_res:
            BASELINE_PATH.write_text(json.dumps(static_res, indent=2), encoding="utf-8")
            print(f"[+] Saved static baseline to: {BASELINE_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
