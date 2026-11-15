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
  if (!location.href.startsWith("http://") && !location.href.startsWith("https://")) {
    return;
  }

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
