# TriVex

**TriVex — Explainable Phishing URL Detection Browser Extension**

A Chrome Manifest V3 extension for local, explainable phishing-URL detection with optional Family Shield content filtering. All analysis runs locally in the browser — no external server required.

> **Status:** Phases 0–9 complete. Core detector, offline evaluation, phishing blocking, page monitoring, and Family Shield are all implemented.

---

## Features

- **System A — Rule-based detector:** Flags on IP hostname, URL length >75, deep subdomains, suspicious symbols (`@` / multiple hyphens), or phishing keywords without HTTPS.
- **System B — Weighted score:** Six features scored (max 120); flagged at 45+.
- **System C — Hybrid judge:** A wins if it flags; otherwise B's verdict; disagreements reported.
- **Phishing blocking:** Background service worker intercepts navigation to phishing URLs and redirects to a local warning page.
- **Page monitoring:** Debounced content script reads structural signals (title, form actions, link counts) — never reads form values or passwords.
- **Family Shield:** Separate adult-content and gambling policy with local block page and approved educational alternatives.
- **Offline evaluation:** Python reference implementation + 60-row labelled dataset + confusion matrix, accuracy, precision, recall, F1, FPR metrics.

---

## Repository layout

```text
TriVex/
├── frontend/                        # Chrome extension (load this folder)
│   ├── icons/                       # Extension icons (16/32/48/128 px)
│   ├── scripts/
│   │   ├── detector.js              # Detection engine (Systems A, B, C)
│   │   ├── popup.js                 # Popup UI logic + Family Shield toggle
│   │   ├── background.js            # Service worker — phishing blocking
│   │   ├── content.js               # Page monitoring content script
│   │   └── family_shield.js        # Content-category classifier
│   ├── styles/
│   │   └── popup.css                # Popup styles (light + dark mode)
│   ├── manifest.json                # MV3 manifest
│   ├── popup.html                   # Extension popup
│   ├── block.html                   # Local phishing block page
│   └── family_shield.html          # Family Shield filtered-content page
│
├── backend/                         # Offline Python evaluation (no server needed)
│   ├── trivex_detector.py           # Python mirror of detector.js
│   ├── evaluate.py                  # Evaluation runner (confusion matrix + metrics)
│   ├── sanity_check.py              # Quick 5-URL smoke test
│   ├── data/
│   │   └── dataset.csv              # 60-row labelled dataset (30 phishing, 30 benign)
│   ├── results/
│   │   └── latest.json              # Most recent evaluation output
│   ├── requirements.txt
│   └── README.md
│
├── er_diag_code                     # Mermaid ER diagram source
├── mermaid-diagram.png
├── trivex_backend_family_shield_dev_playbook.md
└── README.md
```

---

## Load the extension

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `frontend/` folder

---

## Python evaluation setup

```bash
# Create a virtual environment
python -m venv .venv

# Activate (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Activate (macOS / Linux)
source .venv/bin/activate

# Run evaluation (no pip installs needed — stdlib only)
cd backend
python evaluate.py
```

### Latest evaluation results (60-URL dataset, 30 phishing / 30 benign)

| System | Accuracy | Precision | Recall | F1 | FPR |
|--------|----------|-----------|--------|----|-----|
| A — Rule-based | 100% | 1.00 | 1.00 | 1.00 | 0.00 |
| B — Weighted   | 100% | 1.00 | 1.00 | 1.00 | 0.00 |
| C — Hybrid     | 100% | 1.00 | 1.00 | 1.00 | 0.00 |

> **Note:** These results reflect the labelled dataset included in this repository.
> The dataset was constructed to cover the feature space defined in the playbook.
> Real-world performance will differ; do not present these figures as general benchmarks.

---

## Safety and scope

- URL text is analyzed locally — the extension never visits or fetches suspicious URLs.
- "Not flagged" does not mean "guaranteed safe."
- Gemini integration is not implemented in this version.
- Version 1 does not require accounts, a hosted backend, or a database.
- Family Shield adult-content filtering is keyword/domain-based; it is not a trained classifier.
- The extension cannot prevent its own removal or permission revocation.

---

## Development phases completed

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Repository audit | ✅ |
| 1 | URL parsing & feature extraction (JS + Python) | ✅ |
| 2 | System A — rule-based detector | ✅ |
| 3 | System B — weighted scoring | ✅ |
| 4 | System C — hybrid decision | ✅ |
| 5 | Popup integration | ✅ |
| 6 | Offline evaluation (dataset + metrics) | ✅ |
| 7 | Phishing blocking + local block page | ✅ |
| 8 | Continuous page monitoring | ✅ |
| 9 | Family Shield | ✅ |
| 10 | Accounts / Gemini (optional) | ⏳ Deferred |
| 11 | Incognito + release review | ⏳ Pending |

---

## Team

| Member | Responsibility |
|--------|----------------|
| Saksham Kakar | Browser extension UI and integration |
| Tanish | Detection engine |
| Youganter Kumar Singh | Dataset and offline evaluation |

---

## License

No license has been selected yet. Until one is added, all rights are reserved by the project authors.
