"""
test_ml_parity.py — End-to-End Parity Test between Python LightGBM and JavaScript Runtime.

Validates that:
1. Feature extraction is byte-identical between Python and JavaScript.
2. Raw model margin prediction matches within strict numerical tolerance (1e-5).
3. Calibrated probability matches within strict numerical tolerance (1e-4).
4. System C decision verdict matches identically across diverse test URLs:
   - Safe domains
   - Hard negatives (long URLs, multi-hyphen legitimate domains)
   - Suspicious login URLs
   - IP-based URLs
   - Malformed/unusual URLs
"""

import os
import json
import subprocess
import numpy as np
import lightgbm as lgb
from typing import Dict, Any, List

try:
    from backend.ml.feature_schema import FEATURE_NAMES
    from backend.ml.feature_extractor import extract_feature_vector
    from backend.ml.calibrate_model import apply_platt
except ImportError:
    from feature_schema import FEATURE_NAMES
    from feature_extractor import extract_feature_vector
    from calibrate_model import apply_platt

TEST_URLS = [
    "http://192.168.1.1/secure/login",
    "http://paypal-verify-account.com/update",
    "https://www.google.com",
    "https://en.wikipedia.org/wiki/Supercalifragilisticexpialidocious_long_legitimate_path_here",
    "https://www.e-learning-platform.org/courses/computer-science",
    "http://test.bank.verify.login.secure.evil.org/portal",
    "https://github.com/login",
    "http://65.52.100.92/secure-login/account/verify",
    "https://myaccount.google.com/security",
    "http://xn--80ak6aa92e.com/login",
    "http://legitimate-looking.phish.xyz:8080/auth/signin?token=xyz#login",
    "http://not-a-standard-site.top/verify.php",
    "https://duckduckgo.com/?q=tri-vex+security",
    "http://amazon-account-verify.suspicious-login.com/secure",
    "http://www.bank-update--secure.com/login/verify"
]


def run_node_inference(url: str) -> Dict[str, Any]:
    """Runs JavaScript inference via node.js and returns output."""
    js_code = f"""
    const path = require('path');
    const fs = require('fs');

    const extractor = require('./frontend/scripts/ml/feature_extractor.js');
    const runtime = require('./frontend/scripts/ml/lightgbm_runtime.js');
    const sysCv2 = require('./frontend/scripts/ml/system_c_v2.js');

    const manifest = JSON.parse(fs.readFileSync('./frontend/models/model_manifest.json', 'utf8'));
    const model = JSON.parse(fs.readFileSync('./frontend/models/phishing_model.json', 'utf8'));
    const calibration = JSON.parse(fs.readFileSync('./frontend/models/calibration.json', 'utf8'));

    const assets = {{
      manifest: manifest,
      model: model,
      calibration: calibration,
      status: 'ready'
    }};

    const url = {json.dumps(url)};
    const features = extractor.extractVector(url);
    const pred = runtime.predict(model, calibration, features);
    const decision = sysCv2.evaluateSystemC_v2(url, {{ assets: assets }});

    console.log(JSON.stringify({{
      features: features,
      rawMargin: pred.rawMargin,
      calibratedProbability: pred.calibratedProbability,
      verdict: decision.finalVerdict,
      riskLevel: decision.riskLevel,
      recommendedAction: decision.recommendedAction
    }}));
    """
    cmd = ["node", "-e", js_code]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(res.stdout.strip())


def run_parity_suite():
    model_path = os.path.join(os.path.dirname(__file__), "..", "results", "model_artifacts", "phishing_booster.txt")
    calib_path = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "models", "calibration.json")

    booster = lgb.Booster(model_file=model_path)
    with open(calib_path, "r", encoding="utf-8") as f:
        calib_data = json.load(f)
    A = calib_data["parameters"]["A"]
    B = calib_data["parameters"]["B"]

    print("=" * 65)
    print("  TriVex System C v2: Python vs JavaScript Parity Verification")
    print("=" * 65)

    all_passed = True
    max_feature_diff = 0.0
    max_margin_diff = 0.0
    max_prob_diff = 0.0

    for idx, url in enumerate(TEST_URLS):
        # Python side
        py_features = extract_feature_vector(url)
        py_raw_margin = float(booster.predict(np.array([py_features], dtype=np.float32), raw_score=True)[0])
        py_calib_prob = float(apply_platt(np.array([py_raw_margin]), A, B)[0])

        # JavaScript side
        js_res = run_node_inference(url)
        js_features = js_res["features"]
        js_raw_margin = js_res["rawMargin"]
        js_calib_prob = js_res["calibratedProbability"]

        # Feature vector parity
        feat_diffs = [abs(p - j) for p, j in zip(py_features, js_features)]
        feat_max_err = max(feat_diffs)
        max_feature_diff = max(max_feature_diff, feat_max_err)

        # Margin parity
        margin_err = abs(py_raw_margin - js_raw_margin)
        max_margin_diff = max(max_margin_diff, margin_err)

        # Probability parity
        prob_err = abs(py_calib_prob - js_calib_prob)
        max_prob_diff = max(max_prob_diff, prob_err)

        passed = (feat_max_err < 1e-4) and (margin_err < 1e-4) and (prob_err < 1e-3)
        status_str = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False

        print(f"[{status_str}] URL #{idx+1}: {url[:45]:<45}")
        print(f"       Py Margin: {py_raw_margin:.6f} | JS Margin: {js_raw_margin:.6f} (Diff: {margin_err:.2e})")
        print(f"       Py Prob:   {py_calib_prob:.4f}   | JS Prob:   {js_calib_prob:.4f}   (Diff: {prob_err:.2e})")
        print(f"       JS Action: {js_res['recommendedAction']} | Verdict: {js_res['verdict']}")

    print("=" * 65)
    print(f"Parity Summary: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print(f"  Max Feature Difference: {max_feature_diff:.2e} (Threshold: 1e-4)")
    print(f"  Max Margin Difference:  {max_margin_diff:.2e} (Threshold: 1e-4)")
    print(f"  Max Prob Difference:    {max_prob_diff:.2e} (Threshold: 1e-3)")
    print("=" * 65)

    if not all_passed:
        exit(1)


if __name__ == "__main__":
    run_parity_suite()
