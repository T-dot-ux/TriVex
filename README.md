# TriVex — PhishGuard AI

**Explainable Phishing URL Detection & Family Shield Browser Extension**

TriVex is a Chrome Manifest V3 extension designed for local-first, explainable phishing URL analysis with integrated Family Shield protection. All detection and classification runs inside the user's browser without external cloud dependencies, API keys, or privacy leakage.

---

## 1. Core Capabilities

- **Three-Tier Detection Engine:**
  - **System A (Rule-Based):** Deterministic heuristics checking raw IP hostnames, URL length, excessive subdomain depth, user-info obfuscation (`@`), and credential keywords on unencrypted connections.
  - **System B (Weighted Scoring):** Risk-weighted accumulation across six distinct feature categories with a threshold of 45/120 points.
  - **System C (Hybrid Decision Engine):** Combines rule confidence and weighted score to resolve false positives (e.g. preventing legitimate long URLs or multi-subdomain cloud links from triggering hard phishing blocks).
- **Phishing Protection & Redirection:**
  - Background service worker actively monitors tab navigations.
  - Intercepts high-confidence phishing navigations and displays a local warning page (`block.html`) with explanation details and a safe return button.
- **Family Shield Content Policy:**
  - Content classification engine for adult and gambling domains/keywords.
  - User-controlled toggle switch with persistent local storage.
  - Filters restricted destinations to `family_shield.html` featuring parent-approved educational alternatives (Khan Academy, National Geographic Kids, NASA Kids' Club, Britannica Kids, PBS LearningMedia).
- **Continuous Page Context Monitoring:**
  - Content script observes DOM mutations with debouncing (1000ms).
  - Summarizes structural page signals (password field count, form action URLs, external links) without accessing form input values or passwords.
- **Accessible & Transparent Interface:**
  - Full screen-reader announcements (`aria-live="polite"`).
  - Responsive design supporting dark mode and reduced-motion preferences.
  - Local privacy disclosure page (`privacy.html`).

---

## 2. Repository Layout

```text
TriVex/
├── frontend/                        # Chrome extension (Load this folder in chrome://extensions)
│   ├── manifest.json                # Manifest V3 (activeTab, tabs, storage)
│   ├── popup.html                   # Accessible popup interface
│   ├── block.html                   # Phishing warning block page (XSS-safe textContent)
│   ├── family_shield.html           # Family Shield filtered page (educational links)
│   ├── privacy.html                 # Privacy policy & permissions disclosure
│   ├── icons/                       # Extension icons (16, 32, 48, 128 px)
│   ├── scripts/
│   │   ├── detector.js              # Canonical detection engine (Systems A, B, C)
│   │   ├── popup.js                 # Popup UI controller & state machine
│   │   ├── background.js            # MV3 service worker (navigation interception & messaging)
│   │   ├── content.js               # Debounced DOM monitor (structural signals)
│   │   └── family_shield.js         # Content category classifier
│   └── styles/
│       └── popup.css                # Responsive styles (light/dark mode, accessible focus)
│
├── backend/                         # Offline Python evaluation (standard library only)
│   ├── trivex_detector.py           # Python reference implementation (exact parity with JS)
│   ├── evaluate.py                  # Evaluation runner computing confusion matrix & 6 metrics
│   ├── sanity_check.py              # 5-URL smoke test verification
│   ├── parity_test.py               # Cross-language JS/Python execution parity test
│   ├── requirements.txt             # Python requirements (stdlib only)
│   ├── data/
│   │   ├── dataset.csv              # 120-row labelled dataset (60 phishing, 60 benign)
│   │   └── DATASET_PROVENANCE.md    # Methodology, sources, and edge-case documentation
│   └── results/
│       ├── latest.json              # Latest evaluation output JSON
│       └── evaluation_*.json        # Historical timestamped evaluation outputs
│
├── er_diag_code                     # Mermaid ER diagram source (11 domain entities)
├── mermaid-diagram.png              # Rendered ER diagram visualization
├── trivex_backend_family_shield_dev_playbook.md # Technical specification & playbook
├── TRIVEX_PROJECT_AUDIT_AND_TODO.md # Codebase audit and implementation roadmap
└── README.md
```

---

## 3. Installation & Usage in Google Chrome

1. Open Google Chrome and go to `chrome://extensions/`.
2. Turn **ON** the **Developer mode** toggle in the top-right corner.
3. Click the **Load unpacked** button in the top-left corner.
4. Select the `frontend/` folder in this repository.
5. Click the TriVex shield icon in the browser toolbar:
   - Click **Analyze current page** to evaluate the active tab.
   - Or paste any address into the input field and click **Analyze URL**.
   - Toggle **Family Shield** on or off at the bottom of the popup.

---

## 4. Offline Python Evaluation

The offline evaluation suite runs independently using the Python standard library (no pip dependencies required):

```bash
cd backend

# 1. Run basic smoke test
python sanity_check.py

# 2. Run cross-language parity test (verifies identical JS and Python behavior)
python parity_test.py

# 3. Run complete evaluation benchmark
python evaluate.py
```

### Benchmark Results (Dataset v1.1.0 — 120 URLs: 60 Phishing, 60 Benign)

Evaluated with real-world hard negatives including legitimate long URLs (>75 chars), multi-hyphen domains, and corporate/cloud subdomains:

| System | TP | FP | TN | FN | Accuracy | Precision | Recall | F1-Score | FPR |
|---|---|---|---|---|---|---|---|---|---|
| **System A (Rule-Based)** | 60 | 17 | 43 | 0 | 85.8% | 77.9% | 100.0% | 0.8759 | 28.3% |
| **System B (Weighted Score, >=45)** | 59 | 2 | 58 | 1 | 97.5% | 96.7% | 98.3% | 0.9752 | 3.3% |
| **System C (High-Confidence Phishing)** | 60 | 2 | 58 | 0 | **98.3%** | **96.8%** | **100.0%** | **0.9836** | **3.3%** |
| **System C (Composite Warning / Caution)** | 60 | 17 | 43 | 0 | 85.8% | 77.9% | 100.0% | 0.8759 | 28.3% |

- **Key Result:** System A flags any single anomaly, generating a 28.3% False Positive Rate on safe sites. System C integrates weighted risk scoring to filter out benign single-indicator anomalies, lowering the False Positive Rate to 3.3% while maintaining 100% recall on genuine attacks.

---

## 5. Team Responsibilities

| Member | Focus Area | Contributions |
|---|---|---|
| **Saksham Kakar (Member 1)** | Extension UI & Accessibility | Accessible UI states, screen-reader live regions, responsive popup styling, privacy disclosure page. |
| **Tanish (Member 2)** | Detection Engine & Architecture | Dual-language detector parity, false-positive mitigation, background service worker, navigation blocking, Family Shield classifier. |
| **Youganter Kumar Singh (Member 3)** | Evaluation & Testing | Dataset curation (v1.1.0), provenance methodology, cross-language parity testing suite, metrics reporting. |

---

## 6. Security & Privacy Guarantees

- **No Remote Processing:** Zero URLs or page content are transmitted externally.
- **No Password Reading:** The content monitor counts password fields but never inspects their values.
- **Safe Rendering:** All dynamic URL display is done via `textContent` to prevent DOM XSS vulnerabilities.
- **Least Privilege:** Unused permissions (such as `declarativeNetRequest`) have been excised from the manifest.
