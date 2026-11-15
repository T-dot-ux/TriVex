# Backend / Offline Evaluation Pipeline

This directory provides the **Python reference implementation and offline evaluation pipeline** for TriVex. A hosted cloud API server is intentionally not required: all live detection in the Chrome extension runs locally in JavaScript.

---

## 1. Directory Structure

```text
backend/
├── trivex_detector.py      # Python reference detection engine (mirrors detector.js)
├── evaluate.py             # Evaluation runner computing confusion matrix & 6 metrics
├── sanity_check.py         # 5-URL smoke test verification
├── parity_test.py          # Cross-language JS/Python execution parity test
├── requirements.txt        # Minimal dependency definitions (Python stdlib only)
├── data/
│   ├── dataset.csv         # 120-row labelled dataset (60 phishing, 60 benign)
│   └── DATASET_PROVENANCE.md # Dataset documentation, sources, and class methodology
└── results/
    ├── latest.json         # Latest evaluation output JSON
    └── evaluation_*.json   # Timestamped evaluation run outputs
```

---

## 2. Running Evaluation & Tests

TriVex requires Python 3.9+ and relies exclusively on the **Python standard library** (`urllib.parse`, `dataclasses`, `csv`, `json`, `pathlib`, `re`, `datetime`). No external packages are required for the base test suite.

```bash
cd backend

# Quick smoke test
python sanity_check.py

# Cross-language JavaScript/Python parity test
python parity_test.py

# Full offline evaluation suite
python evaluate.py
```

---

## 3. Latest Benchmark Results (Dataset v1.1.0, 120 URLs)

Evaluated across 60 ground-truth phishing URLs and 60 ground-truth benign URLs (including hard negatives: legitimate long URLs > 75 chars, multi-hyphen domains, deep subdomains, and HTTPS login portals):

| System | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|---|---|
| **System A (Rule-Based)** | 60 | 17 | 43 | 0 | 85.8% | 77.9% | 100.0% | 0.8759 | 28.3% | 0.0% |
| **System B (Weighted Score, >=45)** | 59 | 2 | 58 | 1 | 97.5% | 96.7% | 98.3% | 0.9752 | 3.3% | 1.7% |
| **System C (High-Confidence Phishing)** | 60 | 2 | 58 | 0 | **98.3%** | **96.8%** | **100.0%** | **0.9836** | **3.3%** | **0.0%** |
| **System C (Composite Warning / Caution)** | 60 | 17 | 43 | 0 | 85.8% | 77.9% | 100.0% | 0.8759 | 28.3% | 0.0% |

> **Key Finding:** System A exhibits a high False Positive Rate (28.3%) because it flags any single trigger (e.g. length > 75 on legitimate Wikipedia articles). System C resolves this by requiring cumulative risk or severe indicators for hard blocks, reducing the False Positive Rate to 3.3% while maintaining 100% recall on genuine attacks.
