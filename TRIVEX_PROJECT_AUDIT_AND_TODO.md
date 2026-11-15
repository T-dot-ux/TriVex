# TriVex – Project Audit & Engineering TODO Roadmap

**Repository:** `https://github.com/T-dot-ux/TriVex`  
**Working Directory:** `c:\Users\Dell\Documents\TriVex_GitHub_Starter\TriVex`  
**Audit Date:** November 15, 2026  
**Git Synchronization Status:** Synchronized with `origin/main` (`e85d4c6`)  
**Safety & Compliance:** Read-only inspection; no application code rewritten, refactored, or deleted during this audit.

---

## 1. Executive Summary & Synchronization Status

### 1.1 Synchronization Audit
- **Remote URL:** `https://github.com/T-dot-ux/TriVex.git` (fetch & push verified)
- **Active Branch:** `main`
- **Backup Created:** `backup-pre-sync-20261115` (preserves local commit `c3d5a27` state prior to pull)
- **Fast-forward Merged:** Successfully fast-forwarded to `origin/main` commit `e85d4c6` (`Update detector.js`).
- **Working Tree:** Clean (`git status` reports nothing to commit, working tree clean).

### 1.2 High-Level Audit Findings
1. **Directory Fragmentation (Major Architectural Gap):** The extension currently exists in two parallel, desynchronized directories:
   - `frontend/` contains the Manifest V3 background service worker (`scripts/background.js`), continuous page monitor (`scripts/content.js`), Family Shield content filter (`scripts/family_shield.js`), local block pages (`block.html`, `family_shield.html`), and the canonical detector (`scripts/detector.js`).
   - `frontend/extension/` was committed via GitHub web upload by Member 1 (Saksham Kakar) containing an upgraded accessible UI (`popup.html`, `popup.js`, `popup.css`, `privacy.html`), but relies on the **stand-in detector** and completely lacks background navigation interception, content scripts, Family Shield, and block pages.
2. **Detection Logic & Parity:** The core 6-feature extraction and 3-tier detection engine (System A, System B, System C) is fully implemented with exact cross-language parity in `frontend/scripts/detector.js` (JavaScript) and `backend/trivex_detector.py` (Python).
3. **Orphaned Continuous Monitoring:** `content.js` successfully extracts DOM structural indicators and sends them to `background.js` via `PAGE_SIGNALS`, which stores them into `chrome.storage.local.pageSignals`. However, **no UI component or detection engine consumes or displays these signals**.
4. **Synthetic Evaluation Metrics:** `backend/evaluate.py` runs cleanly and reports 100% accuracy, precision, recall, and F1 across all three systems. However, this is an artifact of a 60-row synthetic dataset (`backend/data/dataset.csv`) that lacks borderline edge cases, real-world URLs, and examples that test System A vs. System B disagreement.
5. **AI / LLM Integration Status:** Unstarted. Optional Gemini integration (Phase 10) is deferred by design and has no code implementation.

---

## 2. Current Project Architecture & Workspace Layout

```text
TriVex/
├── .gitignore                                    # Git ignore rules for Python, OS, and local results
├── README.md                                     # Project overview, team roles, and phase tracker
├── er_diag_code                                  # Mermaid domain ER diagram (11 conceptual entities)
├── mermaid-diagram.png                           # Rendered ER diagram image
├── trivex_backend_family_shield_dev_playbook.md  # 12-phase technical specification playbook
│
├── backend/                                      # Offline evaluation & reference implementation
│   ├── README.md                                 # Backend documentation
│   ├── requirements.txt                          # Dependencies (stdlib only; pandas/scikit-learn optional)
│   ├── trivex_detector.py                        # Python reference detection engine (Systems A, B, C)
│   ├── evaluate.py                               # Offline evaluation script (confusion matrix + 5 metrics)
│   ├── sanity_check.py                           # 5-URL smoke test verification script
│   ├── data/
│   │   └── dataset.csv                           # 60-row labelled dataset (30 phishing, 30 benign)
│   └── results/
│       ├── .gitkeep                              # Output directory placeholder
│       ├── evaluation_*.json                     # Timestamped evaluation run outputs
│       └── latest.json                           # Symlink/copy of the most recent evaluation output
│
├── frontend/                                     # Extension root #1 (Feature-complete engine + services)
│   ├── README.md                                 # Frontend documentation
│   ├── manifest.json                             # MV3 manifest with service worker, content scripts, permissions
│   ├── popup.html                                # Baseline UI with Family Shield toggle
│   ├── block.html                                # Standalone phishing block page (red theme, XSS-safe)
│   ├── family_shield.html                        # Standalone Family Shield block page (5 educational links)
│   ├── icons/                                    # Extension icons (16, 32, 48, 128 px)
│   ├── scripts/
│   │   ├── detector.js                           # Canonical detector (Systems A, B, C; canonical keys)
│   │   ├── popup.js                              # Baseline popup script supporting Family Shield toggle
│   │   ├── background.js                         # MV3 service worker (tabs.onUpdated navigation interceptor)
│   │   ├── content.js                            # Debounced page monitor (structural DOM signals)
│   │   └── family_shield.js                      # Content classification module (adult/gambling)
│   └── styles/
│       └── popup.css                             # Baseline popup styles
│
└── frontend/extension/                           # Extension root #2 (Member 1 UI refresh from GitHub)
    ├── manifest.json                             # Minimal MV3 manifest (activeTab only, no background/content)
    ├── detector.js                               # Stand-in detector implementation (legacy feature keys)
    ├── popup.html                                # Redesigned accessible UI (aria-live, statusBox, headline, nextSteps)
    ├── popup.js                                  # Redesigned state machine UI script (loading/error/result states)
    ├── popup.css                                 # Refactored CSS (responsive, dark mode, reduced motion)
    ├── privacy.html                              # Standalone privacy disclosure page
    └── icons/                                    # Extension icons duplicate (16, 32, 48, 128 px)
```

---

## 3. Subsystem Breakdown: Verified Implementation vs. Source Code References

### 3.1 URL Parsing & Feature Extraction (Phase 1)
- **Status:** **Implemented & Verified**
- **Source Files:**
  - JavaScript: `frontend/scripts/detector.js` (lines 82–123)
  - Python: `backend/trivex_detector.py` (lines 138–170)
- **Verified Behavior:**
  Extracts the six required shared features:
  1. `hostname_is_ip`: Detects IPv4 (4 dotted octets) and IPv6 literals (bracketed in JS `[::1]`, colon-tested in Python `::1`).
  2. `suspicious_symbols`: Returns true if `@` is anywhere in the URL OR hostname contains 2+ hyphens.
  3. `hostname_dot_count`: Returns true if hostname contains > 3 dots (counting dots in hostname only, excluding path/query).
  4. `keyword_match`: Case-insensitive substring match against `["secure", "login", "verify", "update", "account", "banking"]`.
  5. `url_length`: Returns true if the full URL string length > 75 characters.
  6. `uses_https`: Returns true when HTTPS is **absent** (plain `http:`), aligning directly with positive risk scoring.

### 3.2 System A — Rule-Based Detector (Phase 2)
- **Status:** **Implemented & Verified**
- **Source Files:**
  - JavaScript: `frontend/scripts/detector.js` (lines 136–153)
  - Python: `backend/trivex_detector.py` (lines 175–199)
- **Verified Behavior:**
  Flags as `"phishing"` if **any** of the following conditions trigger:
  - Hostname is an IP address
  - URL length > 75 characters
  - Hostname has > 3 dots
  - Contains `@` or multiple hyphens
  - Contains targeted keyword **and** HTTPS is absent (plain HTTP)
  If no rules fire, returns `"not_flagged"`. Provides human-readable triggered reasons.

### 3.3 System B — Weighted Risk Scoring (Phase 3)
- **Status:** **Implemented & Verified**
- **Source Files:**
  - JavaScript: `frontend/scripts/detector.js` (lines 165–193)
  - Python: `backend/trivex_detector.py` (lines 216–237)
- **Verified Behavior:**
  Weights strictly match playbook specification (single contribution per category):
  - IP address in hostname: 35
  - Suspicious symbols (`@` or 2+ hyphens): 30
  - More than 3 hostname dots: 20
  - Targeted keyword: 15
  - URL length > 75: 10
  - HTTPS absent: 10
  - **Threshold:** 45 (out of maximum 120 points).
  Returns `score`, `maxScore: 120`, `threshold: 45`, `verdict` (`"phishing"` if `score >= 45` else `"not_flagged"`), and itemized points breakdown.

### 3.4 System C — Hybrid Decision Engine (Phase 4)
- **Status:** **Implemented & Verified (With Policy Caveats Noted in Section 5.4)**
- **Source Files:**
  - JavaScript: `frontend/scripts/detector.js` (lines 207–239)
  - Python: `backend/trivex_detector.py` (lines 243–277)
- **Verified Behavior:**
  1. Runs System A and System B independently.
  2. If System A flags -> verdict is `"phishing"`.
  3. If System A does not flag -> adopts System B's verdict.
  4. Flags `disagreement: true` whenever `systemA.verdict !== systemB.verdict`.
  5. Preserves all sub-system verdicts and reasons in the return contract.

### 3.5 Offline Evaluation Pipeline (Phase 6)
- **Status:** **Implemented & Verified**
- **Source Files:**
  - Runner: `backend/evaluate.py`
  - Reference Engine: `backend/trivex_detector.py`
  - Dataset: `backend/data/dataset.csv`
  - Results Output: `backend/results/evaluation_*.json`, `backend/results/latest.json`
- **Execution Evidence:**
  Running `python backend/evaluate.py` processes 60 records and computes confusion matrix (TP, FP, TN, FN), accuracy, precision, recall, F1-score, and false-positive rate (FPR). Output saved to `backend/results/latest.json`.

### 3.6 Phishing Blocking & Local Block Page (Phase 7)
- **Status:** **Implemented in `frontend/`, Missing in `frontend/extension/`**
- **Source Files:**
  - Background Service Worker: `frontend/scripts/background.js` (lines 178–208)
  - Block Page: `frontend/block.html`
  - Manifest Configuration: `frontend/manifest.json` (lines 24–38)
- **Verified Behavior:**
  - `chrome.tabs.onUpdated` intercepts tab loading.
  - Skips internal schemas (`chrome://`, `about:`, `chrome-extension://`, `data:`, `javascript:`) and own block pages (prevents redirect loops).
  - Redirects phishing navigations to `chrome-extension://<id>/block.html?url=<encoded>&reason=<encoded>`.
  - `block.html` renders URL strictly via `textContent` (XSS immune) and provides a `history.back()` escape button.

### 3.7 Continuous Webpage Monitoring (Phase 8)
- **Status:** **Partially Implemented (Collection Active, Display/Action Missing)**
- **Source Files:**
  - Content Script: `frontend/scripts/content.js`
  - Background Receiver: `frontend/scripts/background.js` (lines 214–230)
- **Verified Behavior:**
  - Debounced (1000ms) `MutationObserver` on `document.documentElement`.
  - Filters for meaningful changes (`title`, number of forms, presence of meta description).
  - Collects only structural signals: title (capped 200 chars), meta description (capped 300 chars), form action URLs (capped 10), count of password inputs (count only, values never read), and external link count.
  - Sends message `PAGE_SIGNALS` to background service worker.
  - Background stores a rolling 5-entry history in `chrome.storage.local.pageSignals`.
- **Gap:** No UI or detector logic consumes `pageSignals`.

### 3.8 Family Shield Content Policy (Phase 9)
- **Status:** **Partially Implemented (Classifier & Page Ready, UI Integration Broken by Extension Split)**
- **Source Files:**
  - Category Classifier: `frontend/scripts/family_shield.js`
  - Block Page: `frontend/family_shield.html`
  - Interceptor: `frontend/scripts/background.js` (lines 198–207)
  - Toggle UI: `frontend/popup.html` (lines 157–171), `frontend/scripts/popup.js` (lines 71–92)
- **Verified Behavior:**
  - URL-based classification into `"adult"`, `"gambling"`, or `"safe"` with confidence scores.
  - Background worker checks `familyShieldEnabled` in `chrome.storage.local`; if enabled and matched, redirects to `family_shield.html`.
  - `family_shield.html` displays filtered URL safely via `textContent` and provides 5 parent-approved educational destinations (Khan Academy, National Geographic Kids, NASA Kids' Club, Britannica Kids, PBS LearningMedia).
- **Gap:** Missing entirely from `frontend/extension/`.

---

## 4. Teammate Contributions & Commit Breakdown

### Member 1: Saksham Kakar (UI & Extension Integration)
- **Commits:**
  - `44743a2` (2026-10-29): Created `frontend/extension/` subfolder via web upload.
  - `f55915e` (2026-10-30): Refactored `popup.css` (responsive design down to 320px, dark mode support, accessible focus outlines, reduced motion rules).
  - `4e9f838` (2026-10-30): Updated `popup.html` (added screen-reader live region `#announce`, `#statusBox` for 4 UI states, `#headline` card, `#hostName` with toggleable short/full URL display, `#nextSteps` advice card, and link to `privacy.html`).
  - `691c8e2` (2026-10-30): Updated `popup.js` (full state machine: `initial`, `loading`, `invalid`, `unavailable`, `result`; screen-reader announcements; safe shortening; actionable next steps).
  - `452d1d6` (2026-10-30): Added `privacy.html` (local-first data disclosure, permissions transparency).
  - `e85d4c6` (2026-10-30): Updated `detector.js` in `frontend/extension/` with minor string updates.
- **Teammate Work Status:** Saksham delivered a high-quality, accessible UI, but isolated his work in `frontend/extension/` without integrating Member 2's backend services (service worker, content script, Family Shield, production detector).

### Member 2: Tanish (Detection Engine & Backend Architecture)
- **Commits:**
  - `46bf5fa` (2026-10-28): Initial project scaffold.
  - `f13f66a` (2026-10-29): Implemented canonical `detector.js`, `background.js`, `content.js`, `family_shield.js`, `block.html`, `family_shield.html`, `trivex_detector.py`, `evaluate.py`, and initial dataset.
  - `c3d5a27` (2026-10-29): Merged remote changes.

### Member 3: Youganter Kumar Singh (Dataset & Offline Evaluation)
- **Current Status:** Starter evaluation runner and 60-row synthetic dataset exist in `backend/data/dataset.csv`. Provenance documentation, multi-source benchmarks (e.g. PhishTank, Tranco), train/test splits, and hard boundary cases remain pending.

---

## 5. Incomplete Features, Bugs & Critical Deficiencies

### 5.1 [Defect 1 — High] Dual Directory Structure Fragmentation
- **Location:** `frontend/` vs. `frontend/extension/`
- **Issue:** Loading `frontend/` in Chrome runs the background blocker and Family Shield, but shows the older UI. Loading `frontend/extension/` shows the new accessible UI, but has no background worker, no content monitoring, no Family Shield, and runs the old stand-in detector.
- **Impact:** The repository cannot be loaded cleanly as an unpacked extension without choosing between UI features and backend protection features.

### 5.2 [Defect 2 — High] Logic Duplication in Background Service Worker
- **Location:** `frontend/scripts/background.js` (lines 24–105, 146–172)
- **Issue:** `background.js` inlines its own copy of the detector and Family Shield adult domain lists rather than importing or sharing `scripts/detector.js` and `scripts/family_shield.js`.
- **Impact:** Any rule updates or bug fixes made to `detector.js` will not take effect during automatic tab navigation blocking.

### 5.3 [Defect 3 — Medium] Disconnected Continuous Page Monitoring
- **Location:** `frontend/scripts/content.js` and `frontend/scripts/background.js`
- **Issue:** `content.js` observes DOM changes and transmits `PAGE_SIGNALS`, which `background.js` saves to `chrome.storage.local.pageSignals`. However, `pageSignals` is never retrieved, rendered in the popup, or passed to System C.
- **Impact:** Continuous monitoring is running in the background and consuming browser CPU without providing any visible value or protection enhancement to the user.

### 5.4 [Defect 4 — Medium] Mathematical Asymmetry in System C Hybrid Policy
- **Location:** `frontend/scripts/detector.js` (lines 214–230), `backend/trivex_detector.py` (lines 256–270)
- **Issue:** System A flags on any single indicator (e.g. `http://` with `login`). System B requires 45 points, which is mathematically impossible to achieve without triggering at least one of System A's rules. System C's baseline rule states: "If System A flags -> phishing; else adopt System B".
- **Impact:**
  - System C's final verdict is mathematically identical to System A in 100% of cases. System B never gets to override or contribute an affirmative decision that System A didn't already make.
  - False positives in System A (such as legitimate Wikipedia pages with URLs > 75 chars or legitimate corporate intranets with multiple subdomains) automatically become false positives in System C, even though System B correctly rates them with safe scores (10–20 points).

### 5.5 [Defect 5 — Medium] Synthetic Dataset & Artificial Metrics
- **Location:** `backend/data/dataset.csv`
- **Issue:** All 30 phishing URLs trigger multiple high-weight features simultaneously, while all 30 benign URLs trigger zero features. There are zero instances of System A/B disagreement in the dataset.
- **Impact:** Reported 100% accuracy, precision, and recall are non-representative of real-world performance. Boundary conditions are untested in the evaluation suite.

### 5.6 [Defect 6 — Low] Unused Chrome Permission
- **Location:** `frontend/manifest.json` (line 6)
- **Issue:** `declarativeNetRequest` is declared in permissions, but never called anywhere in the codebase.
- **Impact:** Violates Chrome Web Store least-privilege review guidelines and playbook Section 3.4.

---

## 6. Integration Gaps Matrix

| Component 1 | Component 2 | Expected Integration | Actual Status | Gap Severity |
|---|---|---|---|---|
| `frontend/extension/popup.html` | `frontend/scripts/family_shield.js` | Popup provides Family Shield toggle switch & status badge | Completely omitted from `frontend/extension/` | **High** |
| `frontend/extension/popup.js` | `frontend/scripts/detector.js` | Popup invokes canonical `analyzeUrl()` with full result contract | Invokes stand-in `detector.js` with legacy keys | **High** |
| `frontend/scripts/background.js` | `frontend/scripts/detector.js` | Background worker shares detection engine logic | Background inlines duplicated, diverged logic | **High** |
| `frontend/scripts/content.js` | `frontend/scripts/popup.js` | Popup displays page signals (forms, external links, password fields) | Signals stored in storage but never read by popup | **Medium** |
| `frontend/manifest.json` | `frontend/extension/privacy.html` | Extension packages and links to privacy policy | `privacy.html` exists only in `frontend/extension/` | **Medium** |
| `frontend/manifest.json` | Chrome Permissions API | Only request used permissions | Requests unused `declarativeNetRequest` | **Low** |

---

## 7. Prioritised Development TODO List

### Priority 0: Architectural Reconciliation (Unifying Frontend & Extension)
- [ ] **Task 0.1: Reconcile Directory Structure**
  - Consolidate `frontend/extension/` into `frontend/` as the single canonical extension root.
  - Port Member 1's accessible popup UI (`popup.html`, `popup.css`, `popup.js`, `privacy.html`) into `frontend/`.
  - Update `frontend/manifest.json` to include `privacy.html` and clean icon paths.
  - Delete redundant `frontend/extension/` folder once verified.
- [ ] **Task 0.2: Eliminate Duplicate Detector & Connect Canonical Engine**
  - Ensure the consolidated popup loads the canonical `frontend/scripts/detector.js`.
  - Refactor `background.js` to eliminate duplicated detector and domain lists (use `importScripts`).
- [ ] **Task 0.3: Remove Unused Permissions**
  - Remove `declarativeNetRequest` from `manifest.json`.

### Priority 1: Feature & Subsystem Wiring
- [ ] **Task 1.1: Integrate Family Shield into the Redesigned UI**
  - Add Member 2's Family Shield toggle section and status badge into Member 1's redesigned `popup.html`.
  - Wire toggle state in `popup.js` to `chrome.storage.local.familyShieldEnabled`.
  - Ensure `family_shield.html` is registered in `web_accessible_resources`.
- [ ] **Task 1.2: Connect Page Monitoring Signals to Popup**
  - Update `popup.js` to read `chrome.storage.local.pageSignals` for the current active tab.
  - Render an expandable "Page Context" section in `popup.html` displaying observed form action count, external links count, and password field count.
- [ ] **Task 1.3: Refine System C Hybrid Decision Policy**
  - Address the false-positive inheritance flaw where System A single-rule hits override System B's low scores.
  - Define explicit handling for the three disagreement classes:
    - *Class 1:* Rule triggers length > 75 only (SysB <= 10) -> Classify as `caution / review needed` instead of immediate hard phishing.
    - *Class 2:* Rule triggers hostname dots > 3 only (SysB <= 20) -> Classify as `caution / deep subdomain` instead of hard phishing.
    - *Class 3:* Rule triggers HTTP + Keyword (SysB = 25) -> High-risk warning.
  - Sync updated policy to both `frontend/scripts/detector.js` and `backend/trivex_detector.py`.

### Priority 2: Offline Evaluation & Dataset Hardening
- [ ] **Task 2.1: Expand Dataset with Hard Negatives & Boundary Conditions**
  - Expand `backend/data/dataset.csv` from 60 to at least 120 URLs.
  - Include legitimate long URLs (>75 chars, e.g. Wikipedia articles, cloud storage links).
  - Include legitimate multi-hyphenated brand domains (e.g. `e-learning-platform.org`).
  - Include legitimate login portals on HTTPS (e.g. `https://github.com/login`).
  - Include legitimate subdomains (>3 dots).
- [ ] **Task 2.2: Document Dataset Provenance**
  - Add `backend/data/DATASET_PROVENANCE.md` detailing source origins (e.g. Tranco top 10k, PhishTank verified samples, synthetic boundary tests).
  - Add versioning tags (`dataset_v1.0.0`).
- [ ] **Task 2.3: Re-run Evaluation Suite & Record Baseline Metrics**
  - Execute `evaluate.py` on the expanded dataset and commit realistic confusion matrices and metrics.

### Priority 3: Security, Incognito & Release Review (Phases 10–11)
- [ ] **Task 3.1: Incognito Mode Compatibility Audit**
  - Verify behavior when "Allow in incognito" is toggled on/off in `chrome://extensions`.
  - Ensure no incognito browsing URLs are persisted to permanent local history.
- [ ] **Task 3.2: AI / Gemini Integration Assessment (Optional Phase 10)**
  - Keep Gemini disabled by default per security requirements.
  - If enabled, ensure strict key handling via `chrome.storage.session` and external data transmission disclosures.
- [ ] **Task 3.3: Release Readiness Checklist**
  - Review Manifest V3 service worker lifecycle and restart persistence.
  - Validate all text injections continue to use `textContent` (zero `innerHTML` on untrusted URLs).

---

## 8. Dependencies, Prerequisites & Ownership Matrix

| Task ID | Task Description | Dependencies / Prerequisites | Suggested Owner |
|---|---|---|---|
| **0.1** | Reconcile dual directory structure (`frontend/` vs `frontend/extension/`) | Git synchronization complete | Member 1 (Saksham) & Member 2 (Tanish) |
| **0.2** | Eliminate inlined detector duplication in `background.js` | Task 0.1 completed | Member 2 (Tanish) |
| **0.3** | Clean up manifest permissions (`declarativeNetRequest`) | Task 0.1 completed | Member 1 (Saksham) |
| **1.1** | Add Family Shield toggle to redesigned popup | Task 0.1 completed | Member 1 (Saksham) |
| **1.2** | Connect continuous page monitoring signals to popup UI | Task 0.1 completed | Member 1 & Member 2 |
| **1.3** | Refine System C hybrid policy to resolve false-positive inheritance | Core engine test suite in place | Member 2 (Tanish) |
| **2.1** | Expand dataset with hard negatives and boundary edge cases | Parity verified in Task 1.3 | Member 3 (Youganter) |
| **2.2** | Document dataset provenance & train/test splits | Dataset expansion in Task 2.1 | Member 3 (Youganter) |
| **2.3** | Execute offline evaluation and publish honest benchmark results | Task 2.1 & 2.2 completed | Member 3 (Youganter) |
| **3.1** | Incognito mode compliance testing & storage hygiene | Extension packaging completed | Member 1 (Saksham) |
| **3.2** | Privacy review & release packaging (zip artifact) | All Priority 0–2 tasks complete | All Members |

---

## 9. Testing Requirements & Acceptance Criteria

### Test 1: Extension Unification & Navigation Blocking
- **Procedure:**
  1. Load unified `frontend/` directory into Chrome (`chrome://extensions` -> Load Unpacked).
  2. Navigate to `http://192.168.1.1/secure/login`.
- **Acceptance Criteria:**
  - Browser immediately halts navigation and displays `block.html`.
  - Block page displays `http://192.168.1.1/secure/login` inside `#blockedUrl` via text rendering.
  - Clicking "Go Back" successfully returns to previous tab history.
  - Console shows no background service worker crashes or infinite redirect loops.

### Test 2: Family Shield Content Policy & Educational Fallbacks
- **Procedure:**
  1. Open TriVex popup, toggle "Family Shield" to ON.
  2. Verify green `🛡️ ON` badge appears in header.
  3. Navigate to a test adult domain (e.g. `http://pornhub.com` or URL containing `explicit-content`).
- **Acceptance Criteria:**
  - Tab navigates to `family_shield.html`.
  - Filter reason is clearly stated without explicit imagery or terms.
  - All 5 educational destination links (Khan Academy, NatGeo Kids, NASA Kids, Britannica, PBS) are clickable and open in new tabs with `rel="noopener noreferrer"`.

### Test 3: System C Disagreement & Boundary Testing
- **Procedure:**
  Run the automated test suite against the following three boundary cases:
  - `Case A:` `https://en.wikipedia.org/wiki/Phishing_investigation_and_forensic_techniques_in_cybercrime` (length > 75, safe site).
  - `Case B:` `http://example.com/login` (plain HTTP, keyword `login`).
  - `Case C:` `https://my-legit-bank.com/account` (hyphenated domain, keyword on HTTPS).
- **Acceptance Criteria:**
  - Case A: System A flags (`length > 75`), System B does not flag (`score = 10`), System C marks `disagreement: true` and renders cautious guidance rather than a false-positive hard block.
  - Case B: System A flags, System B scores 25, System C marks `disagreement: true`.
  - Case C: Both System A and System B evaluate cleanly without false-positive tripping.

### Test 4: Offline Evaluation Reproducibility
- **Procedure:**
  Execute `python backend/evaluate.py` from repository root.
- **Acceptance Criteria:**
  - Script exits with code 0 without requiring third-party pip dependencies.
  - Computes and prints complete confusion matrix (TP, FP, TN, FN) for Systems A, B, and C.
  - Generates valid JSON output in `backend/results/latest.json`.
  - Metrics accurately reflect the dataset without hardcoded numbers.

