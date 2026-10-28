# TriVex

**TriVex — Explainable Phishing URL Detection Browser Extension**

A student project exploring explainable, local-first phishing URL analysis through a Chrome extension. The initial version is planned to analyze URL structure locally, explain suspicious indicators, and support offline evaluation with Python.

> **Status:** Initial scaffold only. Detection logic and evaluation results are not implemented yet.

## Planned features
- Chrome Extension using Manifest V3.
- User-triggered current-tab analysis and manual URL input.
- Local URL parsing and feature extraction.
- Rule-based, manually weighted scoring, and proposed hybrid approaches.
- Human-readable explanations.
- Offline Python evaluation on a labelled dataset.

## Repository layout
```text
TriVex/
├── frontend/       # Chrome extension UI and client-side detection
├── backend/        # Offline Python evaluation utilities (no server required for v1)
├── README.md
└── .gitignore
```

## Technology
HTML, CSS, JavaScript, Chrome Extensions Manifest V3, JavaScript `URL` API, Python, pandas, and optionally scikit-learn metrics.

## Load the extension (once implemented)
1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `frontend/` directory.

The scaffold is not yet a complete working detector.

## Python evaluation setup
```bash
python -m venv .venv
```
Windows PowerShell: `\.venv\Scripts\Activate.ps1`
macOS/Linux: `source .venv/bin/activate`
Then run: `pip install -r backend/requirements.txt`

## Safety and scope
- Analyze URL text locally where practical.
- Never automatically open or fetch suspicious URLs.
- Use minimal browser permissions.
- “Not flagged” does not mean “guaranteed safe.”
- Version 1 does not require a hosted backend, database, accounts, or automatic blocking.

## Team
| Member | Responsibility |
|---|---|
| Saksham Kakar | Browser extension UI and integration |
| Tanish | Detection engine |
| Youganter Kumar Singh | Dataset and offline evaluation |

## Project status
This repository contains starter scaffolding only. Do not report performance metrics until evaluation has been run on a verified labelled dataset.

## License
No license has been selected yet. Until one is added, all rights are reserved by the project authors.
