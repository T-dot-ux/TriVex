# Frontend — TriVex Chrome Extension (Manifest V3)

This directory is the **canonical Chrome extension source** for TriVex. All real-time browser protection, URL feature analysis, continuous DOM monitoring, and Family Shield filtering run locally inside this extension.

---

## 1. Directory Structure

```text
frontend/
├── manifest.json            # Manifest V3 configuration (permissions: activeTab, tabs, storage)
├── popup.html               # Accessible popup UI (screen-reader live region, state boxes)
├── block.html               # Standalone phishing warning page (red theme, XSS-safe textContent)
├── family_shield.html       # Family Shield filtered-content page (5 approved educational links)
├── privacy.html             # Standalone privacy disclosure page
├── icons/                   # Extension icons (16, 32, 48, 128 px)
├── scripts/
│   ├── detector.js          # Canonical detection engine (Systems A, B, C; canonical features)
│   ├── popup.js             # UI state controller, screen-reader announcer, settings manager
│   ├── background.js        # MV3 service worker (tabs.onUpdated interceptor & message router)
│   ├── content.js           # Debounced DOM monitor (counts form actions, password inputs, links)
│   └── family_shield.js     # Content category classifier (adult / gambling domain & keyword lists)
└── styles/
    └── popup.css            # Responsive styles (light/dark mode, reduced-motion, access focus)
```

---

## 2. Loading the Extension in Google Chrome

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable the **Developer mode** toggle in the top-right corner.
3. Click **Load unpacked** in the top-left toolbar.
4. Select the `frontend/` folder in this repository.
5. The **TriVex** extension icon will appear in your browser toolbar. Click the pin icon to keep it visible.

---

## 3. Extension Capabilities

- **Manual URL Analysis:** Paste any web address or click **Analyze current page** to extract six URL features and inspect decisions from System A, System B, and System C.
- **Real-Time Phishing Blocking:** Background service worker intercepts navigation to high-confidence phishing sites (such as IP hostnames or credential harvesting over unencrypted HTTP) and displays `block.html`.
- **Family Shield Content Policy:** Toggle Family Shield in the popup to filter adult and gambling content, redirecting to `family_shield.html` with safe educational alternative destinations.
- **Continuous Page Monitoring:** Content script debounces DOM observations to track form destinations and password field counts without reading user input.
- **Privacy First:** Zero data leaves your browser. No external APIs or servers are contacted.
