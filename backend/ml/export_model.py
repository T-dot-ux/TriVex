"""
export_model.py — Standalone Model Export Engine for Web Extensions.

Exports trained LightGBM model and calibration artifacts into a compact,
fully self-contained, JSON-serialized tree structure for client-side JavaScript execution.

Generates:
1. frontend/models/phishing_model.json
2. frontend/models/calibration.json
3. frontend/models/model_manifest.json
"""

import os
import json
import hashlib
import numpy as np
import lightgbm as lgb
from typing import Dict, Any, List

try:
    from backend.ml.feature_schema import FEATURE_NAMES, SCHEMA_VERSION, get_schema_dict
    from backend.ml.train_model import run_training_pipeline
    from backend.ml.calibrate_model import fit_platt_scaling, calibrate_and_evaluate
except ImportError:
    from feature_schema import FEATURE_NAMES, SCHEMA_VERSION, get_schema_dict
    from train_model import run_training_pipeline
    from calibrate_model import fit_platt_scaling, calibrate_and_evaluate


def serialize_node(node: Dict[str, Any], feature_names: List[str]) -> Dict[str, Any]:
    """
    Recursively simplifies LightGBM dump_model tree structure into compact JSON.
    Handles:
      - split_feature (name and index)
      - threshold (split threshold)
      - left_child / right_child
      - default_left (whether NaN/missing goes to left child)
      - leaf_value
    """
    if "leaf_value" in node:
        return {
            "is_leaf": True,
            "leaf_value": float(node["leaf_value"]),
        }

    feat_idx = node.get("split_feature")
    feat_name = feature_names[feat_idx] if feat_idx < len(feature_names) else f"f_{feat_idx}"

    return {
        "is_leaf": False,
        "feature_index": int(feat_idx),
        "feature_name": feat_name,
        "threshold": float(node.get("threshold", 0.0)),
        "default_left": bool(node.get("default_left", True)),
        "left": serialize_node(node["left_child"], feature_names),
        "right": serialize_node(node["right_child"], feature_names),
    }


def export_lightgbm_to_json(booster: lgb.Booster, feature_names: List[str]) -> Dict[str, Any]:
    """Serializes LightGBM booster dump into portable tree array."""
    dump = booster.dump_model()
    tree_info = dump.get("tree_info", [])

    serialized_trees = []
    for tree_dict in tree_info:
        tree_idx = tree_dict.get("tree_index", len(serialized_trees))
        root_node = tree_dict.get("tree_structure", {})
        shrinkage = float(tree_dict.get("shrinkage", 1.0))

        serialized_trees.append({
            "tree_index": tree_idx,
            "shrinkage": shrinkage,
            "root": serialize_node(root_node, feature_names),
        })

    return {
        "model_type": "lightgbm_gbdt",
        "num_trees": len(serialized_trees),
        "base_score": 0.0,  # LightGBM binary baseline log-odds default
        "trees": serialized_trees,
    }


def compute_checksum(filepath: str) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def export_all(
    csv_path: str,
    frontend_model_dir: str,
    backend_results_dir: str,
) -> Dict[str, Any]:
    """Runs complete train, calibrate, and export cycle."""
    os.makedirs(frontend_model_dir, exist_ok=True)
    os.makedirs(backend_results_dir, exist_ok=True)

    # 1. Train model
    res = run_training_pipeline(csv_path, backend_results_dir)
    booster = res["booster"]
    test_recs = res["test_records"]
    val_recs = res["val_records"]

    # 2. Extract raw margins for calibration
    X_val = np.array([r["features"] for r in val_recs], dtype=np.float32)
    y_val = np.array([r["label"] for r in val_recs], dtype=np.int32)
    raw_val_margins = booster.predict(X_val, raw_score=True)

    X_test = np.array([r["features"] for r in test_recs], dtype=np.float32)
    y_test = np.array([r["label"] for r in test_recs], dtype=np.int32)
    raw_test_margins = booster.predict(X_test, raw_score=True)

    # 3. Calibrate
    calib_artifact = calibrate_and_evaluate(raw_val_margins, y_val, raw_test_margins, y_test)

    # 4. Serialize model
    model_json = export_lightgbm_to_json(booster, FEATURE_NAMES)

    # Write frontend artifacts
    model_path = os.path.join(frontend_model_dir, "phishing_model.json")
    with open(model_path, "w", encoding="utf-8") as f:
        json.dump(model_json, f, indent=2)

    calib_path = os.path.join(frontend_model_dir, "calibration.json")
    with open(calib_path, "w", encoding="utf-8") as f:
        json.dump(calib_artifact, f, indent=2)

    # Compute checksums
    model_hash = compute_checksum(model_path)
    calib_hash = compute_checksum(calib_path)

    # Build manifest
    manifest = {
        "model_name": "TriVex System C v2 LightGBM",
        "model_version": "2.0.0",
        "schema_version": SCHEMA_VERSION,
        "model_type": "LightGBM Binary GBDT",
        "model_status": "EXPERIMENTAL",  # Honest readiness status based on 120-URL baseline dataset gate
        "dataset_version": "1.1.0",
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "calibration": {
            "method": calib_artifact["method"],
            "parameters": calib_artifact["parameters"]
        },
        "metrics_summary": {
            "test_accuracy": res["report"]["full_model"]["test_metrics"]["accuracy"],
            "test_f1": res["report"]["full_model"]["test_metrics"]["f1"],
            "test_roc_auc": res["report"]["full_model"]["test_metrics"]["roc_auc"],
            "test_brier_calibrated": calib_artifact["evaluation_on_test"]["calibrated_brier_score"]
        },
        "decision_thresholds": {
            "allow_max_prob": 0.20,
            "caution_max_prob": 0.70,
            "warning_max_prob": 0.95,
            "block_min_prob": 0.95
        },
        "checksums": {
            "phishing_model_sha256": model_hash,
            "calibration_sha256": calib_hash
        }
    }

    manifest_path = os.path.join(frontend_model_dir, "model_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Also mirror into backend results for tracking
    backend_manifest_path = os.path.join(backend_results_dir, "model_manifest.json")
    with open(backend_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return {
        "manifest": manifest,
        "model_path": model_path,
        "calib_path": calib_path,
        "manifest_path": manifest_path
    }


if __name__ == "__main__":
    csv_file = os.path.join(os.path.dirname(__file__), "..", "data", "dataset.csv")
    fe_dir = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "models")
    be_dir = os.path.join(os.path.dirname(__file__), "..", "results", "model_artifacts")
    res = export_all(csv_file, fe_dir, be_dir)
    print("=== Model Export Successfully Completed ===")
    print("Model manifest generated at:", res["manifest_path"])
    print("Model SHA-256:", res["manifest"]["checksums"]["phishing_model_sha256"])
