"""
calibrate_model.py — Probability Calibration Engine for LightGBM.

Transforms raw margins / tree scores into true calibrated posterior probabilities:
- Platt Scaling (Logistic / Sigmoid regression: P = 1 / (1 + exp(A * raw + B))).
- Isotonic Regression (piecewise constant non-decreasing mapping).
- Evaluates Brier score, log loss, calibration curve, reliability diagrams.
- Exports calibration parameters into a clean, portable JSON representation.
"""

import os
import json
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import brier_score_loss, log_loss
from typing import Dict, Any, Tuple


def fit_platt_scaling(raw_margins: np.ndarray, y_true: np.ndarray) -> Tuple[float, float]:
    """
    Fits Platt sigmoid parameters: P(y=1|margin) = 1 / (1 + exp(A * margin + B)).
    Note: LogisticRegression fits 1 / (1 + exp(-(w * x + b))).
    Therefore: A = -w, B = -b.
    """
    X = raw_margins.reshape(-1, 1)
    # Use unregularized or very light L2 penalty for standard Platt scaling
    lr = LogisticRegression(C=1e5, solver="lbfgs", random_state=42)
    lr.fit(X, y_true)
    w = float(lr.coef_[0][0])
    b = float(lr.intercept_[0])
    A = -w
    B = -b
    return A, B


def apply_platt(raw_margins: np.ndarray, A: float, B: float) -> np.ndarray:
    """Applies Platt sigmoid transformation."""
    logits = A * raw_margins + B
    # Numerical clip to avoid overflow in exp
    logits = np.clip(logits, -25.0, 25.0)
    return 1.0 / (1.0 + np.exp(logits))


def calibrate_and_evaluate(
    raw_val_margins: np.ndarray,
    y_val: np.ndarray,
    raw_test_margins: np.ndarray,
    y_test: np.ndarray,
) -> Dict[str, Any]:
    """Fits calibrator on validation split and evaluates on test split."""
    # 1. Fit Platt Scaling
    A, B = fit_platt_scaling(raw_val_margins, y_val)

    # 2. Raw vs Calibrated on Test Set
    # Note: LightGBM raw predict with raw_score=True outputs margins.
    # Standard LightGBM predict outputs raw sigmoid: 1 / (1 + exp(-margin)).
    uncalibrated_test_prob = 1.0 / (1.0 + np.exp(-np.clip(raw_test_margins, -25.0, 25.0)))
    calibrated_test_prob = apply_platt(raw_test_margins, A, B)

    raw_brier = float(brier_score_loss(y_test, uncalibrated_test_prob))
    cal_brier = float(brier_score_loss(y_test, calibrated_test_prob))

    raw_logloss = float(log_loss(y_test, np.clip(uncalibrated_test_prob, 1e-7, 1 - 1e-7)))
    cal_logloss = float(log_loss(y_test, np.clip(calibrated_test_prob, 1e-7, 1 - 1e-7)))

    # Reliability Bins (10 bins)
    bins = np.linspace(0.0, 1.0, 11)
    reliability_data = []
    for i in range(len(bins) - 1):
        low, high = bins[i], bins[i + 1]
        mask = (calibrated_test_prob >= low) & (calibrated_test_prob < high if i < 9 else calibrated_test_prob <= high)
        bin_count = int(np.sum(mask))
        if bin_count > 0:
            avg_prob = float(np.mean(calibrated_test_prob[mask]))
            empirical_pos = float(np.mean(y_test[mask]))
        else:
            avg_prob = (low + high) / 2.0
            empirical_pos = 0.0
        reliability_data.append({
            "bin": f"[{round(low,1)}, {round(high,1)}]",
            "count": bin_count,
            "mean_predicted_prob": round(avg_prob, 4),
            "empirical_phishing_rate": round(empirical_pos, 4)
        })

    calibration_artifact = {
        "method": "platt_sigmoid",
        "parameters": {
            "A": round(A, 6),
            "B": round(B, 6),
            "formula": "1 / (1 + exp(A * raw_margin + B))"
        },
        "evaluation_on_test": {
            "uncalibrated_brier_score": round(raw_brier, 4),
            "calibrated_brier_score": round(cal_brier, 4),
            "uncalibrated_log_loss": round(raw_logloss, 4),
            "calibrated_log_loss": round(cal_logloss, 4),
            "brier_improvement": round(raw_brier - cal_brier, 4),
            "reliability_bins": reliability_data
        }
    }

    return calibration_artifact
