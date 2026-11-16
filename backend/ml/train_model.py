"""
train_model.py — LightGBM Binary Classification Training Pipeline.

Trains a compact, explainable LightGBM tree ensemble for phishing URL detection.
Features:
- Grouped train/validation/test split by registered domain to prevent leakage.
- Controlled tree depth and leaf count for fast, low-memory browser execution.
- Ablation study comparing feature subsets (Lexical-only vs Lexical+Heuristic).
- Exports full training metadata and evaluation metrics.
"""

import os
import json
import random
import numpy as np
import lightgbm as lgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, log_loss, brier_score_loss,
    confusion_matrix
)
from collections import defaultdict
from typing import Dict, Any, List, Tuple

try:
    from backend.ml.feature_schema import FEATURE_NAMES, SCHEMA_VERSION
    from backend.ml.feature_extractor import extract_feature_vector
    from backend.ml.validate_dataset import extract_registered_domain
except ImportError:
    from feature_schema import FEATURE_NAMES, SCHEMA_VERSION
    from feature_extractor import extract_feature_vector
    from validate_dataset import extract_registered_domain


RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)


def load_dataset(csv_path: str) -> List[Dict[str, Any]]:
    """Loads CSV, extracts features, and attaches domain metadata."""
    import csv
    records = []
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "").strip()
            label_raw = row.get("label", row.get("true_label", "")).strip().lower()
            if not url:
                continue
            if label_raw in ("1", "phishing", "malicious"):
                label = 1
            elif label_raw in ("0", "benign", "legitimate", "safe"):
                label = 0
            else:
                continue

            domain = extract_registered_domain(url)
            features = extract_feature_vector(url)
            records.append({
                "url": url,
                "label": label,
                "domain": domain,
                "features": features
            })
    return records


def split_by_domain(
    records: List[Dict[str, Any]],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    seed: int = RANDOM_SEED
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Performs domain-grouped splitting ensuring URLs from the same registered domain
    never leak across train/val/test splits.
    """
    domain_to_records = defaultdict(list)
    for r in records:
        domain_to_records[r["domain"]].append(r)

    # Separate domains with phishing vs benign to preserve balance
    domain_labels = {}
    for d, recs in domain_to_records.items():
        # majority label for domain
        labels = [r["label"] for r in recs]
        domain_labels[d] = 1 if (sum(labels) / len(labels)) >= 0.5 else 0

    rng = random.Random(seed)
    pos_domains = [d for d, lab in domain_labels.items() if lab == 1]
    neg_domains = [d for d, lab in domain_labels.items() if lab == 0]

    rng.shuffle(pos_domains)
    rng.shuffle(neg_domains)

    def allocate(doms):
        n = len(doms)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        train_d = set(doms[:n_train])
        val_d = set(doms[n_train:n_train + n_val])
        test_d = set(doms[n_train + n_val:])
        return train_d, val_d, test_d

    train_pos, val_pos, test_pos = allocate(pos_domains)
    train_neg, val_neg, test_neg = allocate(neg_domains)

    train_domains = train_pos | train_neg
    val_domains = val_pos | val_neg
    test_domains = test_pos | test_neg

    train_recs = [r for r in records if r["domain"] in train_domains]
    val_recs = [r for r in records if r["domain"] in val_domains]
    test_recs = [r for r in records if r["domain"] in test_domains]

    return train_recs, val_recs, test_recs


def train_lightgbm_model(
    train_recs: List[Dict[str, Any]],
    val_recs: List[Dict[str, Any]],
    feature_indices: List[int] = None
) -> Tuple[lgb.Booster, Dict[str, Any]]:
    """Trains a constrained LightGBM binary classifier."""
    X_train = np.array([r["features"] for r in train_recs], dtype=np.float32)
    y_train = np.array([r["label"] for r in train_recs], dtype=np.int32)

    X_val = np.array([r["features"] for r in val_recs], dtype=np.float32)
    y_val = np.array([r["label"] for r in val_recs], dtype=np.int32)

    if feature_indices is not None:
        X_train = X_train[:, feature_indices]
        X_val = X_val[:, feature_indices]
        feat_names = [FEATURE_NAMES[i] for i in feature_indices]
    else:
        feat_names = FEATURE_NAMES

    train_data = lgb.Dataset(X_train, label=y_train, feature_name=feat_names, free_raw_data=False)
    val_data = lgb.Dataset(X_val, label=y_val, feature_name=feat_names, reference=train_data, free_raw_data=False)

    params = {
        "objective": "binary",
        "metric": ["binary_logloss", "auc"],
        "boosting_type": "gbdt",
        "learning_rate": 0.05,
        "num_leaves": 15,          # Compact leaves for embedded browser tree runtime
        "max_depth": 5,            # Constrained depth prevents overfitting & keeps tree shallow
        "min_child_samples": 3,     # Safe for modest dataset
        "feature_fraction": 0.85,
        "bagging_fraction": 0.85,
        "bagging_freq": 1,
        "verbose": -1,
        "seed": RANDOM_SEED,
        "deterministic": True,
        "force_col_wise": True,
    }

    evals_result = {}
    booster = lgb.train(
        params,
        train_data,
        num_boost_round=120,
        valid_sets=[train_data, val_data],
        valid_names=["train", "val"],
        callbacks=[
            lgb.early_stopping(stopping_rounds=15, verbose=False),
            lgb.record_evaluation(evals_result)
        ]
    )

    metadata = {
        "best_iteration": booster.best_iteration,
        "params": params,
        "train_size": len(train_recs),
        "val_size": len(val_recs),
        "evals_result": evals_result
    }

    return booster, metadata


def evaluate_predictions(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> Dict[str, Any]:
    """Calculates comprehensive classification and ranking metrics."""
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    brier = float(brier_score_loss(y_true, y_prob))

    try:
        roc_auc = float(roc_auc_score(y_true, y_prob))
    except Exception:
        roc_auc = 0.5
    try:
        pr_auc = float(average_precision_score(y_true, y_prob))
    except Exception:
        pr_auc = 0.5
    try:
        loss = float(log_loss(y_true, np.clip(y_prob, 1e-7, 1 - 1e-7)))
    except Exception:
        loss = 0.0

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "brier_score": round(brier, 4),
        "log_loss": round(loss, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    }


def run_training_pipeline(csv_path: str, output_dir: str) -> Dict[str, Any]:
    """Executes the full model training and ablation workflow."""
    os.makedirs(output_dir, exist_ok=True)
    records = load_dataset(csv_path)

    # Train / Val / Test domain-grouped split
    train_recs, val_recs, test_recs = split_by_domain(records, train_ratio=0.70, val_ratio=0.15)

    # 1. Full Model (All 38 features)
    booster_full, meta_full = train_lightgbm_model(train_recs, val_recs)

    # 2. Ablation: Without Heuristic Evidence (features 0..35, excluding sys_a_score_norm & sys_b_score_norm)
    lexical_indices = list(range(len(FEATURE_NAMES) - 2))
    booster_ablated, meta_ablated = train_lightgbm_model(train_recs, val_recs, feature_indices=lexical_indices)

    # Evaluate on held-out test set
    X_test_full = np.array([r["features"] for r in test_recs], dtype=np.float32)
    y_test = np.array([r["label"] for r in test_recs], dtype=np.int32)
    X_test_ablated = X_test_full[:, lexical_indices]

    raw_preds_full = booster_full.predict(X_test_full)
    raw_preds_ablated = booster_ablated.predict(X_test_ablated)

    metrics_full = evaluate_predictions(y_test, raw_preds_full)
    metrics_ablated = evaluate_predictions(y_test, raw_preds_ablated)

    # Save model file
    model_txt_path = os.path.join(output_dir, "phishing_booster.txt")
    booster_full.save_model(model_txt_path)

    # Save training report & ablation comparison
    report = {
        "schema_version": SCHEMA_VERSION,
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "train_count": len(train_recs),
        "val_count": len(val_recs),
        "test_count": len(test_recs),
        "full_model": {
            "best_iteration": meta_full["best_iteration"],
            "test_metrics": metrics_full,
        },
        "ablation_lexical_only": {
            "best_iteration": meta_ablated["best_iteration"],
            "test_metrics": metrics_ablated,
        },
        "ablation_finding": (
            "Full model with heuristic evidence achieves F1="
            + str(metrics_full["f1"])
            + " vs Lexical-only F1="
            + str(metrics_ablated["f1"])
        ),
    }

    report_path = os.path.join(output_dir, "training_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return {"booster": booster_full, "report": report, "test_records": test_recs, "val_records": val_recs}


if __name__ == "__main__":
    csv_file = os.path.join(os.path.dirname(__file__), "..", "data", "dataset.csv")
    out_dir = os.path.join(os.path.dirname(__file__), "..", "results", "model_artifacts")
    res = run_training_pipeline(csv_file, out_dir)
    print("=== Training Pipeline Complete ===")
    print("Full Model Test F1:", res["report"]["full_model"]["test_metrics"]["f1"])
    print("Ablation Finding:", res["report"]["ablation_finding"])
