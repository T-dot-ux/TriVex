"""
explain_model.py — Explainability & SHAP Feature Contribution Analysis.

Computes exact TreeSHAP feature contributions for LightGBM models.
Analyzes global feature importance and generates per-URL feature impact reports.
"""

import os
import json
import numpy as np
import lightgbm as lgb
from typing import Dict, Any, List

try:
    from backend.ml.feature_schema import FEATURE_NAMES
    from backend.ml.feature_extractor import extract_feature_vector
except ImportError:
    from feature_schema import FEATURE_NAMES
    from feature_extractor import extract_feature_vector


def explain_prediction(booster: lgb.Booster, url: str) -> Dict[str, Any]:
    """
    Computes exact TreeSHAP contributions for a single URL prediction.
    Uses LightGBM built-in TreeSHAP: predict(..., pred_contrib=True).
    The last element of the returned vector is the expected base value.
    """
    vec = extract_feature_vector(url)
    X = np.array([vec], dtype=np.float32)

    # pred_contrib returns array of shape (1, num_features + 1)
    # where the last element is the baseline expected value
    contribs = booster.predict(X, pred_contrib=True)[0]
    base_val = float(contribs[-1])
    feature_contribs = contribs[:-1]

    # Pair with feature names and sort by absolute contribution
    ranked = []
    for name, val, impact in zip(FEATURE_NAMES, vec, feature_contribs):
        ranked.append({
            "feature": name,
            "value": round(float(val), 4),
            "shap_contribution": round(float(impact), 6),
            "abs_impact": abs(float(impact)),
        })

    ranked.sort(key=lambda x: x["abs_impact"], reverse=True)

    # Top positive contributors (push towards phishing)
    phish_drivers = [r for r in ranked if r["shap_contribution"] > 0][:5]
    # Top negative contributors (push towards benign)
    benign_drivers = [r for r in ranked if r["shap_contribution"] < 0][:5]

    return {
        "url": url,
        "base_value": round(base_val, 6),
        "total_margin": round(float(np.sum(contribs)), 6),
        "top_phishing_contributors": phish_drivers,
        "top_benign_contributors": benign_drivers,
        "all_contributions": ranked,
    }


def compute_global_feature_importance(booster: lgb.Booster) -> List[Dict[str, Any]]:
    """Computes global feature importance by split and gain."""
    split_imp = booster.feature_importance(importance_type="split")
    gain_imp = booster.feature_importance(importance_type="gain")

    summary = []
    for name, s, g in zip(FEATURE_NAMES, split_imp, gain_imp):
        summary.append({
            "feature": name,
            "split_count": int(s),
            "gain": round(float(g), 4),
        })

    summary.sort(key=lambda x: x["gain"], reverse=True)
    return summary


if __name__ == "__main__":
    model_path = os.path.join(os.path.dirname(__file__), "..", "results", "model_artifacts", "phishing_booster.txt")
    if os.path.exists(model_path):
        b = lgb.Booster(model_file=model_path)
        sample = "http://192.168.1.1/secure/login"
        exp = explain_prediction(b, sample)
        print("=== TreeSHAP Explanation for Sample ===")
        print("URL:", sample)
        print("Total margin:", exp["total_margin"])
        print("Top Phishing Drivers:")
        for d in exp["top_phishing_contributors"]:
            print(f"  {d['feature']} = {d['value']} (SHAP: +{d['shap_contribution']})")
