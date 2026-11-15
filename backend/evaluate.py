"""
TriVex offline evaluation script.

Loads backend/data/dataset.csv, runs all detection systems against each URL,
and computes complete classification metrics:
  - Accuracy
  - Precision
  - Recall
  - F1-score
  - False Positive Rate (FPR)
  - False Negative Rate (FNR)
  - Confusion Matrix (TP, FP, TN, FN)

Evaluated Systems:
  1. System A — Rule-based (any rule flags)
  2. System B — Weighted scoring (score >= 45)
  3. System C — High-Confidence Phishing (blocking trigger)
  4. System C — Composite Warning (includes caution / suspicious level)

Results are printed to stdout and saved as JSON in backend/results/.

Usage:
    cd backend
    python evaluate.py
"""

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Import the detector
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from trivex_detector import analyze_url, AnalysisResult  # noqa: E402

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATASET_PATH = _SCRIPT_DIR / "data" / "dataset.csv"
RESULTS_DIR  = _SCRIPT_DIR / "results"

# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_dataset(path: Path) -> list[dict]:
    """
    Load a CSV file with columns ``url`` and ``true_label``.
    Returns a list of dicts: [{"url": str, "true_label": str}, ...]
    """
    records = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row_num, row in enumerate(reader, start=2):
            url   = (row.get("url")        or "").strip()
            label = (row.get("true_label") or "").strip().lower()
            if not url:
                print(f"  [WARN] Row {row_num}: empty URL — skipped", file=sys.stderr)
                continue
            if label not in ("phishing", "benign"):
                print(
                    f"  [WARN] Row {row_num}: unknown label {label!r} for {url!r} — skipped",
                    file=sys.stderr,
                )
                continue
            records.append({"url": url, "true_label": label})
    return records


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------

def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, float]:
    """
    Compute classification metrics from a confusion matrix.
    Positive class = "phishing".
    """
    total     = tp + fp + tn + fn
    accuracy  = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp)    if (tp + fp) else 0.0
    recall    = tp / (tp + fn)    if (tp + fn) else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (tp + fn) if (tp + fn) else 0.0

    return {
        "accuracy":            round(accuracy,  4),
        "precision":           round(precision, 4),
        "recall":              round(recall,    4),
        "f1_score":            round(f1,        4),
        "false_positive_rate": round(fpr,       4),
        "false_negative_rate": round(fnr,       4),
    }


# ---------------------------------------------------------------------------
# Per-system evaluators
# ---------------------------------------------------------------------------

def _verdict_fn_a(result: AnalysisResult) -> str:
    return "phishing" if (result.system_a and result.system_a.verdict == "phishing") else "not_flagged"

def _verdict_fn_b(result: AnalysisResult) -> str:
    return "phishing" if (result.system_b and result.system_b.verdict == "phishing") else "not_flagged"

def _verdict_fn_c_strict(result: AnalysisResult) -> str:
    # High-confidence phishing only (triggers hard block)
    return "phishing" if (result.system_c and result.system_c.verdict == "phishing") else "not_flagged"

def _verdict_fn_c_caution(result: AnalysisResult) -> str:
    # Includes caution/suspicious levels (user alert)
    return "phishing" if (result.system_c and result.system_c.verdict in ("phishing", "suspicious")) else "not_flagged"


def evaluate_detector(
    verdict_fn,
    records: list[dict],
) -> dict[str, Any]:
    """
    Run *verdict_fn* on each record's URL and compare against the true label.
    """
    tp = fp = tn = fn = 0
    errors:  list[str]  = []
    details: list[dict] = []

    for rec in records:
        url        = rec["url"]
        true_label = rec["true_label"]

        result = analyze_url(url)

        if result.error:
            errors.append(f"{url!r}: {result.error}")
            continue

        pred_verdict = verdict_fn(result)
        pred_label   = "phishing" if pred_verdict == "phishing" else "benign"

        if true_label == "phishing" and pred_label == "phishing":
            tp += 1
        elif true_label == "benign" and pred_label == "phishing":
            fp += 1
        elif true_label == "benign" and pred_label == "benign":
            tn += 1
        else:
            fn += 1

        details.append({
            "url":        url,
            "true_label": true_label,
            "predicted":  pred_label,
            "correct":    true_label == pred_label,
        })

    metrics = compute_metrics(tp, fp, tn, fn)

    return {
        "tp":      tp,
        "fp":      fp,
        "tn":      tn,
        "fn":      fn,
        "metrics": metrics,
        "errors":  errors,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _print_confusion_matrix(name: str, res: dict) -> None:
    tp, fp, tn, fn = res["tp"], res["fp"], res["tn"], res["fn"]
    m = res["metrics"]
    print(f"\n{'='*64}")
    print(f"  {name}")
    print(f"{'='*64}")
    print(f"  Confusion matrix (positive = phishing):")
    print(f"    TP (correctly flagged phishing) : {tp:>4}")
    print(f"    FP (benign wrongly flagged)     : {fp:>4}")
    print(f"    TN (correctly passed benign)    : {tn:>4}")
    print(f"    FN (phishing missed)            : {fn:>4}")
    print(f"  Metrics:")
    print(f"    Accuracy            : {m['accuracy']:.4f}  ({m['accuracy']*100:.1f}%)")
    print(f"    Precision           : {m['precision']:.4f}")
    print(f"    Recall              : {m['recall']:.4f}")
    print(f"    F1-score            : {m['f1_score']:.4f}")
    print(f"    False Positive Rate : {m['false_positive_rate']:.4f}")
    print(f"    False Negative Rate : {m['false_negative_rate']:.4f}")
    if res["errors"]:
        print(f"  Parse errors ({len(res['errors'])}):")
        for e in res["errors"]:
            print(f"    • {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Load dataset, evaluate all systems, save results."""
    print("TriVex Offline Evaluation Runner")
    print(f"  Dataset : {DATASET_PATH}")
    print(f"  Results : {RESULTS_DIR}")

    if not DATASET_PATH.exists():
        sys.exit(f"[ERROR] Dataset not found: {DATASET_PATH}")

    records = load_dataset(DATASET_PATH)
    n_phish = sum(1 for r in records if r['true_label'] == 'phishing')
    n_benign = sum(1 for r in records if r['true_label'] == 'benign')
    print(f"  Loaded  : {len(records)} records ({n_phish} phishing, {n_benign} benign)")

    systems = {
        "System A (Rule-based)": _verdict_fn_a,
        "System B (Weighted score, threshold=45)": _verdict_fn_b,
        "System C (High-Confidence Phishing / Block Trigger)": _verdict_fn_c_strict,
        "System C (Composite Warning / Caution included)": _verdict_fn_c_caution,
    }

    all_results: dict[str, Any] = {}
    for name, fn in systems.items():
        res = evaluate_detector(fn, records)
        all_results[name] = res
        _print_confusion_matrix(name, res)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    run_date = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    summary = {
        "run_date":        run_date,
        "dataset_path":    str(DATASET_PATH),
        "record_count":    len(records),
        "phishing_count":  n_phish,
        "benign_count":    n_benign,
        "systems":         {},
    }

    for name, res in all_results.items():
        summary["systems"][name] = {
            "confusion_matrix": {
                "tp": res["tp"], "fp": res["fp"],
                "tn": res["tn"], "fn": res["fn"],
            },
            "metrics":  res["metrics"],
            "errors":   res["errors"],
        }

    output_path = RESULTS_DIR / f"evaluation_{run_date}.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    latest_path = RESULTS_DIR / "latest.json"
    with open(latest_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(f"\n{'='*64}")
    print(f"  Results saved to: {output_path}")
    print(f"  Latest link    : {latest_path}")
    print(f"{'='*64}\n")


if __name__ == "__main__":
    main()
