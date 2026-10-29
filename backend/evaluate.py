"""
TriVex offline evaluation script.

Loads backend/data/dataset.csv, runs all three detection systems (A, B, C)
against each URL, and computes classification metrics for each system.

Metrics computed per system:
  - Accuracy
  - Precision
  - Recall
  - F1-score
  - False Positive Rate (FPR)

Results are printed to stdout and saved as JSON files in backend/results/.

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

# Allow running from repo root or from backend/
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
    Valid true_label values: "phishing", "benign".
    """
    records = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row_num, row in enumerate(reader, start=2):   # row 1 is header
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

    Returns:
        {accuracy, precision, recall, f1_score, false_positive_rate}
        All values in [0, 1] (not percentages).
    """
    total     = tp + fp + tn + fn
    accuracy  = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp)    if (tp + fp) else 0.0
    recall    = tp / (tp + fn)    if (tp + fn) else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0.0   # False Positive Rate

    return {
        "accuracy":           round(accuracy,  4),
        "precision":          round(precision, 4),
        "recall":             round(recall,    4),
        "f1_score":           round(f1,        4),
        "false_positive_rate": round(fpr,      4),
    }


# ---------------------------------------------------------------------------
# Per-system evaluator
# ---------------------------------------------------------------------------


def _verdict_fn_a(result: AnalysisResult) -> str:
    return result.system_a.verdict if result.system_a else "not_flagged"

def _verdict_fn_b(result: AnalysisResult) -> str:
    return result.system_b.verdict if result.system_b else "not_flagged"

def _verdict_fn_c(result: AnalysisResult) -> str:
    return result.system_c.verdict if result.system_c else "not_flagged"


def evaluate_detector(
    verdict_fn,
    records: list[dict],
) -> dict[str, Any]:
    """
    Run *verdict_fn* on each record's URL and compare against the true label.

    Args:
        verdict_fn: Callable(AnalysisResult) -> "phishing" | "not_flagged"
        records:    List of {"url": str, "true_label": str}

    Returns:
        {
            "tp", "fp", "tn", "fn",        # confusion matrix counts
            "metrics": {...},              # from compute_metrics
            "errors":  [str],              # URLs that failed to parse
            "details": [{url, true, pred}] # per-URL breakdown
        }
    """
    tp = fp = tn = fn = 0
    errors:  list[str]  = []
    details: list[dict] = []

    for rec in records:
        url        = rec["url"]
        true_label = rec["true_label"]   # "phishing" | "benign"

        result = analyze_url(url)

        if result.error:
            errors.append(f"{url!r}: {result.error}")
            continue

        pred_verdict = verdict_fn(result)
        pred_label   = "phishing" if pred_verdict == "phishing" else "benign"

        # Confusion matrix (positive = phishing)
        if true_label == "phishing" and pred_label == "phishing":
            tp += 1
        elif true_label == "benign" and pred_label == "phishing":
            fp += 1
        elif true_label == "benign" and pred_label == "benign":
            tn += 1
        else:  # true phishing, predicted benign
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
    print(f"\n{'='*56}")
    print(f"  {name}")
    print(f"{'='*56}")
    print(f"  Confusion matrix (positive = phishing):")
    print(f"    TP (correctly flagged phishing) : {tp:>4}")
    print(f"    FP (benign wrongly flagged)     : {fp:>4}")
    print(f"    TN (correctly passed benign)    : {tn:>4}")
    print(f"    FN (phishing missed)            : {fn:>4}")
    print(f"  Metrics:")
    print(f"    Accuracy           : {m['accuracy']:.4f}  ({m['accuracy']*100:.1f}%)")
    print(f"    Precision          : {m['precision']:.4f}")
    print(f"    Recall             : {m['recall']:.4f}")
    print(f"    F1-score           : {m['f1_score']:.4f}")
    print(f"    False Positive Rate: {m['false_positive_rate']:.4f}")
    if res["errors"]:
        print(f"  Parse errors ({len(res['errors'])}):")
        for e in res["errors"]:
            print(f"    • {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Load dataset, evaluate all three systems, save results."""
    print("TriVex Offline Evaluation")
    print(f"  Dataset : {DATASET_PATH}")
    print(f"  Results : {RESULTS_DIR}")

    # Load dataset
    if not DATASET_PATH.exists():
        sys.exit(f"[ERROR] Dataset not found: {DATASET_PATH}")

    records = load_dataset(DATASET_PATH)
    print(f"  Loaded  : {len(records)} records "
          f"({sum(1 for r in records if r['true_label']=='phishing')} phishing, "
          f"{sum(1 for r in records if r['true_label']=='benign')} benign)")

    # Evaluate each system
    systems = {
        "System A (Rule-based)": _verdict_fn_a,
        "System B (Weighted)":   _verdict_fn_b,
        "System C (Hybrid)":     _verdict_fn_c,
    }

    all_results: dict[str, Any] = {}
    for name, fn in systems.items():
        res = evaluate_detector(fn, records)
        all_results[name] = res
        _print_confusion_matrix(name, res)

    # Save results to JSON
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    run_date = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    summary = {
        "run_date":        run_date,
        "dataset_path":    str(DATASET_PATH),
        "record_count":    len(records),
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

    # Also write a stable "latest" file for easy access
    latest_path = RESULTS_DIR / "latest.json"
    with open(latest_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(f"\n{'='*56}")
    print(f"  Results saved to: {output_path}")
    print(f"  Latest link    : {latest_path}")
    print(f"{'='*56}\n")


if __name__ == "__main__":
    main()
