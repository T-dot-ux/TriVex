/*
 * content.js — TriVex page monitoring content script (Phase 8).
 *
 * Reads only structural/metadata signals from the page:
 *   - document title
 *   - meta description content
 *   - form action URLs (never form values or passwords)
 *   - count of password-type inputs (count only, never reads values)
 *   - count of external links
 *
 * Signals are sent to the background service worker via chrome.runtime.sendMessage.
 * A debounced MutationObserver fires only on meaningful DOM changes.
 *
 * NEVER reads:
 *   - Form field values
 *   - Password inputs
 *   - Any user-entered data
 */

(function () {
  "use strict";

  /* Skip extension pages and about: pages */
  var pageUrl = location.href || "";
  if (!pageUrl.startsWith("http://") && !pageUrl.startsWith("https://")) {
    return;
  }

  /* ------------------------------------------------------------------ */
  /* REAL-TIME CLIENT-SIDE BLOCK ENFORCEMENT                             */
  /* ------------------------------------------------------------------ */

  function renderBlockScreen(type, blockedUrl, reasonText) {
    try {
      window.stop();
    } catch (e) {}

    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        chrome.runtime.sendMessage({
          type: "PAGE_BLOCKED",
          blockType: type,
          url: blockedUrl
        });
      } catch (e) {}
    }

    var isFS = type === "family_shield";
    var bgGrad = isFS ? "linear-gradient(135deg, #0d3b5c 0%, #1a6b3c 100%)" : "#1a0000";
    var cardBg = isFS ? "rgba(255,255,255,0.08)" : "#2d0000";
    var cardBorder = isFS ? "2px solid rgba(255,255,255,0.25)" : "2px solid #c0392b";
    var textColor = isFS ? "#e8f5e9" : "#f8d7da";
    var titleColor = isFS ? "#a5d6a7" : "#ff6b6b";
    var icon = isFS ? "🛡️" : "⚠️";
    var titleText = isFS ? "TriVex Family Shield" : "TriVex Blocked This Page";
    var subText = isFS
      ? "TriVex Family Shield has restricted access to this address."
      : "This page was flagged as a potential phishing site.";

    document.title = isFS ? "TriVex Family Shield" : "TriVex — Phishing Warning";

    var html =
      '<!DOCTYPE html>' +
      '<html lang="en">' +
      '<head>' +
      '<meta charset="UTF-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>' + (isFS ? "TriVex Family Shield" : "TriVex — Phishing Warning") + '</title>' +
      '<style>' +
      '*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }' +
      'body {' +
      '  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;' +
      '  background: ' + bgGrad + ';' +
      '  color: ' + textColor + ';' +
      '  min-height: 100vh;' +
      '  display: flex; align-items: center; justify-content: center; padding: 24px;' +
      '}' +
      '.card {' +
      '  background: ' + cardBg + ';' +
      '  border: ' + cardBorder + ';' +
      '  border-radius: 14px; max-width: 640px; width: 100%; padding: 36px 32px;' +
      '  box-shadow: 0 8px 40px rgba(0,0,0,0.4);' +
      '}' +
      '.icon { font-size: 64px; text-align: center; display: block; margin-bottom: 12px; line-height: 1; }' +
      'h1 { font-size: 1.6rem; font-weight: 700; color: ' + titleColor + '; text-align: center; margin-bottom: 6px; }' +
      '.sub { text-align: center; font-size: 0.95rem; opacity: 0.85; margin-bottom: 24px; }' +
      '.box {' +
      '  background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.15);' +
      '  border-radius: 6px; padding: 10px 14px; margin-bottom: 18px; word-break: break-all; font-size: 0.88rem;' +
      '}' +
      '.box-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; opacity: 0.7; margin-bottom: 4px; }' +
      '.reason-box {' +
      '  background: ' + (isFS ? "rgba(0,0,0,0.25)" : "#3d0000") + ';' +
      '  border-left: 4px solid ' + (isFS ? "#4db6ac" : "#e74c3c") + ';' +
      '  padding: 10px 14px; margin-bottom: 24px; font-size: 0.9rem; border-radius: 4px;' +
      '}' +
      '.btn {' +
      '  display: inline-block; background: ' + (isFS ? "#2e7d32" : "#444") + '; color: #fff;' +
      '  padding: 10px 20px; border: none; border-radius: 6px; font-weight: 600; font-size: 0.95rem;' +
      '  cursor: pointer; transition: opacity 0.15s;' +
      '}' +
      '.btn:hover { opacity: 0.9; }' +
      '.res-title { font-size: 0.9rem; font-weight: 600; margin-bottom: 10px; color: #80cbc4; }' +
      '.res-list { list-style: none; margin-bottom: 24px; }' +
      '.res-list li { margin: 6px 0; }' +
      '.res-list a { color: #b2dfdb; text-decoration: none; font-size: 0.88rem; }' +
      '.res-list a:hover { text-decoration: underline; }' +
      '</style>' +
      '</head>' +
      '<body>' +
      '<div class="card">' +
      '<span class="icon">' + icon + '</span>' +
      '<h1>' + titleText + '</h1>' +
      '<p class="sub">' + subText + '</p>' +
      '<div class="box">' +
      '<div class="box-label">Blocked Address</div>' +
      '<div id="trivexBlockedUrl"></div>' +
      '</div>' +
      '<div class="reason-box" id="trivexBlockedReason"></div>' +
      (isFS
        ? '<div class="res-title">Parent-Approved Safe Resources:</div>' +
          '<ul class="res-list">' +
          '<li>🚀 <a href="https://www.nasa.gov/kidsclub/index.html" target="_blank" rel="noopener">NASA Kids Club</a> — Space exploration and activities</li>' +
          '<li>🦁 <a href="https://kids.nationalgeographic.com" target="_blank" rel="noopener">National Geographic Kids</a> — Animals and science</li>' +
          '<li>📖 <a href="https://kids.britannica.com" target="_blank" rel="noopener">Britannica Kids</a> — Safe encyclopedia for students</li>' +
          '<li>📺 <a href="https://pbslearningmedia.org" target="_blank" rel="noopener">PBS LearningMedia</a> — Educational lessons and videos</li>' +
          '</ul>'
        : '') +
      '<div>' +
      '<button class="btn" id="trivexBtnBack" type="button">← Go Back</button>' +
      '</div>' +
      '</div>' +
      '</body>' +
      '</html>';

    document.documentElement.innerHTML = html;

    var urlEl = document.getElementById("trivexBlockedUrl");
    if (urlEl) urlEl.textContent = blockedUrl;

    var reasonEl = document.getElementById("trivexBlockedReason");
    if (reasonEl) reasonEl.textContent = "Reason: " + reasonText;

    var btnBack = document.getElementById("trivexBtnBack");
    if (btnBack) {
      btnBack.addEventListener("click", function () {
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.location.href = "https://www.google.com";
        }
      });
    }
  }

  // Active check on page start
  function checkUrlOnLoad() {
    var detector = (window.PhishGuard && window.PhishGuard.analyzeUrl) || window.analyzeUrl;
    var classifier = (window.FamilyShield && window.FamilyShield.classifyUrl) || window.classifyUrl;

    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(["familyShieldEnabled"], function (res) {
        var fsEnabled = res.familyShieldEnabled !== undefined ? !!res.familyShieldEnabled : true;

        // Phishing check
        if (detector) {
          try {
            var pRes = detector(pageUrl);
            if (pRes && !pRes.error && pRes.finalVerdict === "phishing") {
              var pReason =
                (pRes.systemC && pRes.systemC.reasons && pRes.systemC.reasons[0]) ||
                "High-risk phishing indicators detected";
              renderBlockScreen("phishing", pageUrl, pReason);
              return;
            }
          } catch (e) {}
        }

        // Family Shield check
        if (fsEnabled && classifier) {
          try {
            var fRes = classifier(pageUrl);
            if (
              fRes &&
              (fRes.category === "adult" || fRes.category === "gambling") &&
              (fRes.confidence === "high" || fRes.confidence === "medium")
            ) {
              var fReason =
                (fRes.evidence && fRes.evidence[0]) ||
                ("Filtered by Family Shield (" + fRes.category + ")");
              renderBlockScreen("family_shield", pageUrl, fReason);
              return;
            }
          } catch (e) {}
        }
      });
    }
  }

  checkUrlOnLoad();

  /* ------------------------------------------------------------------ */
  /* Signal collection                                                    */
  /* ------------------------------------------------------------------ */

  /**
   * Collect structural page signals.
   * Returns a plain object safe to JSON-serialize and send.
   */
  function collectSignals() {
    var title = document.title || "";

    // Meta description
    var metaDesc = "";
    var metaEl = document.querySelector("meta[name='description']");
    if (metaEl) metaDesc = metaEl.getAttribute("content") || "";

    // Form action URLs (not values)
    var formActions = [];
    var forms = document.querySelectorAll("form[action]");
    forms.forEach(function (form) {
      var action = form.getAttribute("action") || "";
      if (action && formActions.indexOf(action) === -1) {
        formActions.push(action);
      }
    });

    // Password field count (count only — never read values)
    var passwordFieldCount = document.querySelectorAll("input[type='password']").length;

    // External link count
    var currentHost = location.hostname;
    var externalLinkCount = 0;
    var anchors = document.querySelectorAll("a[href]");
    anchors.forEach(function (a) {
      var href = a.getAttribute("href") || "";
      if (href.startsWith("http://") || href.startsWith("https://")) {
        try {
          var linkHost = new URL(href).hostname;
          if (linkHost && linkHost !== currentHost) {
            externalLinkCount++;
          }
        } catch (e) { /* ignore malformed href */ }
      }
    });

    return {
      title:              title.slice(0, 200),      // cap length
      metaDescription:    metaDesc.slice(0, 300),
      formActions:        formActions.slice(0, 10),  // cap count
      passwordFieldCount: passwordFieldCount,
      externalLinkCount:  externalLinkCount,
      url:                location.href,
      collectedAt:        Date.now(),
    };
  }

  /* ------------------------------------------------------------------ */
  /* Send signals to background                                           */
  /* ------------------------------------------------------------------ */

  function sendSignals(signals) {
    try {
      chrome.runtime.sendMessage({ type: "PAGE_SIGNALS", signals: signals });
    } catch (e) {
      /* Extension context may be invalidated during navigation — ignore */
    }
  }

  /* ------------------------------------------------------------------ */
  /* Debounce helper                                                      */
  /* ------------------------------------------------------------------ */

  function debounce(fn, delayMs) {
    var timer = null;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(fn, delayMs);
    };
  }

  /* ------------------------------------------------------------------ */
  /* Meaningful-change detector                                           */
  /* Avoids firing on every small DOM mutation (ads, animations, etc.)   */
  /* ------------------------------------------------------------------ */

  var lastTitle    = "";
  var lastNumForms = 0;
  var lastNumMeta  = 0;

  function isMeaningfulChange() {
    var title    = document.title;
    var numForms = document.querySelectorAll("form").length;
    var metaEl   = document.querySelector("meta[name='description']");
    var numMeta  = metaEl ? 1 : 0;

    if (title !== lastTitle || numForms !== lastNumForms || numMeta !== lastNumMeta) {
      lastTitle    = title;
      lastNumForms = numForms;
      lastNumMeta  = numMeta;
      return true;
    }
    return false;
  }

  /* ------------------------------------------------------------------ */
  /* Observer setup                                                       */
  /* ------------------------------------------------------------------ */

  var debouncedCheck = debounce(function () {
    if (isMeaningfulChange()) {
      sendSignals(collectSignals());
    }
  }, 1000);

  // Send initial signals after DOM is ready
  function sendInitialSignals() {
    lastTitle    = document.title;
    lastNumForms = document.querySelectorAll("form").length;
    var metaEl   = document.querySelector("meta[name='description']");
    lastNumMeta  = metaEl ? 1 : 0;
    sendSignals(collectSignals());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", sendInitialSignals);
  } else {
    sendInitialSignals();
  }

  // Watch for meaningful DOM mutations
  var observer = new MutationObserver(debouncedCheck);
  observer.observe(document.documentElement, {
    childList: true,
    subtree:   true,
    // Do NOT observe attribute or character data — too noisy
  });

  // Direct query listener for instant popup response
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
      if (message && message.type === "GET_LIVE_PAGE_SIGNALS") {
        sendResponse(collectSignals());
      }
      return false;
    });
  }

})();
