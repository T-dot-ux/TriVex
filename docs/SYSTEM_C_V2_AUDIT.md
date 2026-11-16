# TriVex System C v2: Comprehensive Architecture & Integration Audit

**Date:** November 16, 2026  
**Author:** Senior Machine Learning & Cybersecurity Architect  
**Project:** TriVex Browser Extension (Manifest V3)  
**Task:** System C v2 Local Machine Learning Engine Upgrade  

---

## 1. Executive Summary

TriVex is an explainable phishing detection and Family Shield protection browser extension running under Chrome/Edge Manifest V3. The extension is strictly privacy-centric and local-first: URL analysis is executed entirely on the client, with zero remote telemetry or external API calls.

This audit documents the existing repository state, defines the target state for **System C v2** (a genuine, locally trained and locally executed LightGBM tree ensemble model with calibrated probabilities), and establishes the non-destructive integration roadmap.

---

## 2. Existing Repository Architecture

### 2.1 Front-End Component Analysis

1. **`frontend/manifest.json` (MV3):**
   - Background service worker: `scripts/background.js`.
   - Permissions: `activeTab`, `tabs`, `storage`, `declarativeNetRequest`.
   - Host permissions: `http://*/*`, `https://*/*`.
   - Content scripts running at `document_start`:
     - `scripts/blocklist.js` (Dictionary for Family Shield & gambling terms).
     - `scripts/detector.js` (PhishGuard: Systems A, B, and C v1).
     - `scripts/family_shield.js` (Content classification).
     - `scripts/content.js` (DOM structural signals observer & passive telemetry).
   - Web accessible resources: `block.html`, `family_shield.html`, `privacy.html`, `scripts/block.js`, `scripts/family_shield_page.js`.

2. **`frontend/scripts/detector.js` (Core PhishGuard Engine):**
   - **Feature Extraction (6 baseline features):**
     - `hostname_is_ip` (IPv4 or IPv6 hostname).
     - `suspicious_symbols` (`@` symbol or >= 2 hyphens in hostname).
     - `hostname_dot_count` (> 3 dots in hostname).
     - `keyword_match` (any match of `["secure", "login", "verify", "update", "account", "banking"]`).
     - `url_length` (> 75 chars).
     - `uses_https` (`true` when HTTP / no HTTPS).
   - **System A (Rule-Based):**
     - Flags if ANY feature is active (keyword requires HTTP absence to trigger).
   - **System B (Weighted Scoring):**
     - Weights: IP (35), Symbols (30), Dots (20), Keyword (15), Length (10), No HTTPS (10). Max: 120. Threshold: 45.
   - **System C v1 (Hybrid Decision Layer):**
     - High confidence phishing if score >= 45, or IP hostname, or `@` symbol, or keyword without HTTPS.
     - Suspicious if System A triggers single weak rule or score in [30, 44].
     - Low risk / not flagged otherwise.

3. **`frontend/scripts/background.js` (Service Worker):**
   - Imports `blocklist.js`, `detector.js`, `family_shield.js`.
   - Dynamically registers DNR rules for high-confidence adult/gambling blocking.
   - Listens to `chrome.tabs.onUpdated`, `chrome.tabs.onActivated`, and `chrome.runtime.onMessage`.
   - Handles navigation blocking via `chrome.tabs.update` redirecting to `block.html` or `family_shield.html`.
   - Manages extension action badge (`!` or `FS`).

4. **`frontend/scripts/content.js` (DOM & Page Structural Observer):**
   - Runs on web pages at `document_start` and `DOMContentLoaded`.
   - Extracts structural signals:
     - `passwordInputs` (count only, never reads values).
     - `totalInputs`, `formCount`.
     - `crossOriginForms` (count of forms posting to differing origin).
     - `externalLinks`, `totalLinks`.
     - `hiddenInputs`, `iframeCount`.
   - Transmits page signals to background via `PAGE_SIGNALS` for storage in `chrome.storage.local`.

5. **`frontend/popup.html` and `frontend/scripts/popup.js`:**
   - Displays real-time analysis of the active tab or user-entered URL.
   - Renders System A status, System B score progress bar, System C final verdict, and active risk indicator chips.

### 2.2 Python Backend Analysis

1. **`backend/trivex_detector.py`:**
   - Exact Python parity mirror of `frontend/scripts/detector.js`.
   - Provides identical `extract_features`, `run_system_a`, `run_system_b`, and `run_system_c`.
2. **`backend/parity_test.py`:**
   - Evaluates test cases across Node.js detector and Python detector ensuring identical outputs.
3. **`backend/evaluate.py`:**
   - Evaluates dataset (`backend/data/dataset.csv`) producing metrics and confusion matrices.
4. **`backend/data/dataset.csv`:**
   - 120 records (60 phishing, 60 benign controls and hard negatives).

---

## 3. System C v2 Architecture Design

### 3.1 Principles
1. **Local-First & Zero-Network Inference:** No external requests, no cloud LLMs, no remote inference endpoints.
2. **True Machine Learning:** A trained LightGBM gradient boosted decision tree ensemble running directly inside Chrome MV3 JavaScript via an optimized, deterministic tree traversal runtime.
3. **Calibrated Probabilities:** Raw log-odds margins from LightGBM are passed through a Platt (sigmoid) or isotonic calibration layer so probabilities represent genuine statistical likelihoods.
4. **Surgical Integration:** System A, System B, and Family Shield remain fully operational. System C v2 fuses the calibrated ML prediction with deterministic structural evidence.

### 3.2 Feature Schema (Target: 36 Numerical Features)

| Group | Features | Description |
|---|---|---|
| **A. URL Lexical** | `url_length`, `host_length`, `path_length`, `query_length`, `num_query_params`, `special_char_count`, `has_at_symbol`, `hyphen_count_total`, `hyphen_count_host`, `percent_encoding_count`, `digit_ratio_url`, `digit_ratio_host` | Structural lengths, distributions, and encoding properties |
| **B. Hostname** | `is_ip_host`, `dot_count_host`, `subdomain_depth`, `host_entropy`, `is_punycode`, `has_suspicious_port`, `is_tld_suspicious` | Domain architecture, Shannon entropy, character distribution |
| **C. Token Lexical** | `has_kw_login`, `has_kw_verify`, `has_kw_account`, `has_kw_update`, `has_kw_banking`, `has_kw_secure`, `has_kw_password`, `has_kw_auth`, `total_phish_token_count` | Keyword presence across URL components |
| **D. Statistical & Entropy** | `path_entropy`, `query_entropy`, `token_density`, `has_file_extension`, `has_fragment`, `no_https` | Information density and protocol security |
| **E. Page Structural Signals** | `has_page_signals`, `password_input_count`, `form_count`, `cross_origin_form_count`, `iframe_count`, `hidden_input_count`, `external_link_ratio` | DOM architecture (represented with default/imputation when offline/pre-navigation) |
| **F. Detector Evidence** | `sys_a_score_norm`, `sys_b_score_norm` | Normalized scores from deterministic heuristics |

### 3.3 Model Artifacts & JSON Serialization

The trained LightGBM model will be exported into a standardized portable JSON bundle:
- `phishing_model.json`: Tree-by-tree representation with split features, thresholds, left/right child nodes, default directions, and leaf values.
- `calibration.json`: Calibrator type (sigmoid / Platt scaling parameters `A` and `B` or isotonic step thresholds).
- `model_manifest.json`: Schema version, feature list in exact array order, sha256 checksums, and model metadata.

### 3.4 JavaScript Inference Engine
Located in `frontend/scripts/ml/`:
- `feature_extractor.js`: Shared 36-feature extractor matching Python implementation down to floating-point precision.
- `lightgbm_runtime.js`: Pure JavaScript tree traversal evaluating leaves and summing base margins.
- `model_loader.js`: Loads local JSON assets using `chrome.runtime.getURL()` with internal in-memory caching.
- `system_c_v2.js`: Integrates ML probability with heuristic fusion, explaining decision factors and returning structured results.

---

## 4. Preservation & Safety Commitments
- Git branch state preserved before any file modification.
- Existing tests (`parity_test.py`, `evaluate.py`) remain completely passing.
- Family Shield DNR and domain matching untouched.
- Clean backward compatibility maintained for all `analyzeUrl()` callers.
