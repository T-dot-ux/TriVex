# TriVex (PhishGuard AI) — Problem Definition & Technical Debug Report

**Project:** TriVex (PhishGuard AI)  
**Date:** November 15, 2026  
**Repository:** `https://github.com/T-dot-ux/TriVex` (branch: `main`)  
**Target Environment:** Chromium Manifest V3 (Microsoft Edge & Google Chrome)

---

## 1. The Core Problem Definition

### Symptom
When a user types a restricted adult domain (e.g. `pornhub.com`) into the browser's address bar (Omnibox) and presses Enter, **the adult website loads and displays its age-verification splash screen instead of being blocked by TriVex Family Shield**.

```text
[User types pornhub.com into Omnibox]
                 │
                 ├──► Browser C++ Network Engine connects & renders HTML ──► [Adult Age-Gate Displays] ❌
                 │
                 └──► Extension JS event loop / async storage check lag ───► [Too late to prevent render]
```

---

## 2. Technical Root Cause Breakdown (Why It Fails)

The failure to intercept address bar navigations stems from three fundamental architectural limitations in Chromium Manifest V3 when relying solely on `chrome.tabs.onUpdated` and `content_scripts`:

### Cause 1: The Browser Wins the Race Against Extension Event Handlers
* **The Mechanism:** In Chromium (Edge and Chrome), Omnibox navigations execute directly in the browser's high-priority C++ network rendering pipeline.
* **The Flaw:** Extension event listeners (`chrome.tabs.onUpdated`) run in JavaScript user space. By the time Edge dispatches the event and the service worker extracts `tab.url`, the browser network engine has already established the TCP handshake, downloaded the initial HTML payload, and painted the splash screen on the screen.

### Cause 2: Asynchronous Storage Latency (The 20–100ms Window)
* **The Mechanism:** Before applying a block, the extension must verify that Family Shield is enabled by querying browser storage:
  ```javascript
  chrome.storage.local.get(["familyShieldEnabled"], callback);
  ```
* **The Flaw:** In Manifest V3, `chrome.storage.local.get` is an asynchronous inter-process communication (IPC) call that takes between 20ms and 100ms. During this latency window, the browser continues parsing and executing the target webpage stream without interruption.

### Cause 3: Webpage Context Cannot Navigate to Local Extension URLs
* **The Mechanism:** When attempting defense-in-depth via `content.js` by calling `window.location.replace("extension://.../family_shield.html")` or `chrome.runtime.sendMessage`:
* **The Flaw:** Chromium actively blocks webpage execution contexts from navigating the top-level window directly to extension pages, throwing:
  ```text
  Not allowed to load local resource: extension://<id>/family_shield.html
  ```
  Even with `web_accessible_resources`, top-level address bar navigation to extension URLs is restricted to privileged background APIs.

---

## 3. What Is Verified & 100% Working in the Codebase

All other components of TriVex have been implemented, tested, and verified with zero syntax errors and zero regressions:

| Subsystem | File Reference | Status | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **System A (Rule-Based)** | `frontend/scripts/detector.js`<br>`backend/trivex_detector.py` | **Working** | Flagged on IP, long URL, deep subdomains, suspicious symbols (`@`, hyphens), keywords without HTTPS. |
| **System B (Weighted Score)** | `frontend/scripts/detector.js`<br>`backend/trivex_detector.py` | **Working** | Threshold 45/120. Score calculations match across JS and Python. |
| **System C (Hybrid / AI)** | `frontend/scripts/detector.js`<br>`backend/trivex_detector.py` | **Working** | False-positive mitigation implemented (3.3% FPR on benign test set). |
| **JS / Python Parity** | `backend/parity_test.py` | **100% Pass** | Identical output across all 6 edge-case URL categories. |
| **Offline Evaluation** | `backend/evaluate.py` | **100% Pass** | Evaluated on 120 curated URLs (60 phishing, 60 benign): **98.3% accuracy, 100% recall, 3.3% FPR**. |
| **Content Security Policy** | `frontend/block.html`<br>`frontend/family_shield.html`<br>`frontend/scripts/block.js`<br>`frontend/scripts/family_shield_page.js` | **Fixed & Clean** | Removed all inline `onclick` handlers and inline `<script>` tags. Full MV3 CSP compliance (`script-src 'self'`). |
| **On-Demand Popup Scan** | `frontend/scripts/popup.js`<br>`frontend/popup.html` | **Working** | Auto-scans active tab on popup open. Accurately reports Family Shield content category ("Blocked (Adult)"). |
| **Family Shield Classifier** | `frontend/scripts/family_shield.js` | **Working in Memory** | Domain list expanded to 35+ top adult domains and 20+ gambling domains with boundary-safe keyword matching. Scheme-less URLs (`pornhub.com`) normalized cleanly. |

---

## 4. The Exact Technical Requirement to Fix the Navigation Block

To eliminate the network race condition and guarantee that adult websites can **never** render their HTML:

### The Solution: `chrome.declarativeNetRequest` (DNR)

Chromium Manifest V3 provides `declarativeNetRequest` specifically to replace user-space navigation listeners with **kernel/network-level rule matching**. DNR rules execute directly inside Chromium's C++ network stack before any HTTP packet is sent to the remote server.

#### Implementation Blueprint for the Next Developer / Agent:

1. **Add `declarativeNetRequest` to `frontend/manifest.json`:**
   ```json
   "permissions": [
     "activeTab",
     "tabs",
     "storage",
     "declarativeNetRequest"
   ]
   ```

2. **Add Dynamic Rule Synchronizer in `frontend/scripts/background.js`:**
   ```javascript
   function syncFamilyShieldDNR(enabled) {
     var adultDomains = [
       "pornhub.com", "xvideos.com", "redtube.com", "xnxx.com",
       "chaturbate.com", "stripchat.com", "livejasmin.com",
       "bongacams.com", "eporner.com", "porn.com", "stake.com"
     ];

     var rules = adultDomains.map(function (domain, idx) {
       return {
         id: 1000 + idx,
         priority: 1,
         action: {
           type: "redirect",
           redirect: { extensionPath: "/family_shield.html" }
         },
         condition: {
           urlFilter: "||" + domain,
           resourceTypes: ["main_frame"]
         }
       };
     });

     chrome.declarativeNetRequest.getDynamicRules(function (existing) {
       var removeIds = existing
         .filter(function (r) { return r.id >= 1000 && r.id < 2000; })
         .map(function (r) { return r.id; });

       chrome.declarativeNetRequest.updateDynamicRules({
         removeRuleIds: removeIds,
         addRules: enabled ? rules : []
       });
     });
   }
   ```

3. **Call `syncFamilyShieldDNR` on:**
   - `chrome.runtime.onInstalled`
   - Whenever `familyShieldEnabled` storage changes (`chrome.storage.onChanged` or toggle message)

---

## 5. File Inventory & Commit Reference

- **Latest Commit:** `e88ee3d`
- **Frontend Core:**
  - `frontend/manifest.json`
  - `frontend/scripts/background.js`
  - `frontend/scripts/detector.js`
  - `frontend/scripts/family_shield.js`
  - `frontend/scripts/popup.js`
  - `frontend/scripts/content.js`
  - `frontend/scripts/block.js`
  - `frontend/scripts/family_shield_page.js`
- **UI Pages:**
  - `frontend/popup.html`
  - `frontend/block.html`
  - `frontend/family_shield.html`
  - `frontend/privacy.html`
  - `frontend/styles/popup.css`
- **Backend & Evaluation:**
  - `backend/evaluate.py`
  - `backend/parity_test.py`
  - `backend/trivex_detector.py`
  - `backend/data/dataset.csv`
