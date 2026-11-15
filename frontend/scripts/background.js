/*
 * background.js — TriVex MV3 Service Worker.
 *
 * Responsibilities:
 *   1. Intercepts tab navigations to block high-confidence phishing & adult content (Family Shield).
 *   2. Receives and buffers continuous page monitoring signals from content.js.
 *   3. Provides a structured message API for the popup and content scripts.
 *
 * Rule: Service workers cannot use DOM APIs. Core detection and category classification
 * are imported via importScripts from detector.js and family_shield.js.
 */

"use strict";

// Import canonical detector and Family Shield classifier
try {
  importScripts("detector.js", "family_shield.js");
} catch (e) {
  console.error("TriVex: Failed to importScripts in service worker:", e);
}

/* ================================================================
   DETECTOR & CLASSIFIER ACCESSORS
   ================================================================ */

function getDetector() {
  if (typeof self.analyzeUrl === "function") return self.analyzeUrl;
  if (self.PhishGuard && typeof self.PhishGuard.analyzeUrl === "function") {
    return self.PhishGuard.analyzeUrl;
  }
  return null;
}

function getClassifier() {
  if (self.FamilyShield && typeof self.FamilyShield.classifyUrl === "function") {
    return self.FamilyShield.classifyUrl;
  }
  return null;
}

/* ================================================================
   URL HELPERS
   ================================================================ */

function makeBlockUrl(blockedUrl, reason) {
  var base = chrome.runtime.getURL("block.html");
  return (
    base +
    "?url=" +
    encodeURIComponent(blockedUrl) +
    "&reason=" +
    encodeURIComponent(reason || "High-risk phishing indicators detected")
  );
}

function makeFamilyShieldUrl(blockedUrl, reason) {
  var base = chrome.runtime.getURL("family_shield.html");
  return (
    base +
    "?url=" +
    encodeURIComponent(blockedUrl) +
    "&reason=" +
    encodeURIComponent(reason || "Filtered content")
  );
}

function shouldSkip(url) {
  if (!url || typeof url !== "string") return true;
  var lower = url.toLowerCase();
  if (
    lower.startsWith("chrome://") ||
    lower.startsWith("chrome-extension://") ||
    lower.startsWith("about:") ||
    lower.startsWith("data:") ||
    lower.startsWith("javascript:") ||
    lower.startsWith("edge://") ||
    lower.startsWith("brave://")
  ) {
    return true;
  }
  // Prevent redirect loops
  var blockHtml = chrome.runtime.getURL("block.html");
  var familyShieldHtml = chrome.runtime.getURL("family_shield.html");
  if (url.startsWith(blockHtml) || url.startsWith(familyShieldHtml)) {
    return true;
  }
  return false;
}

var lastRedirectedUrl = {};

chrome.tabs.onRemoved.addListener(function (tabId) {
  delete lastRedirectedUrl[tabId];
});

/* ================================================================
   TOOLBAR BADGE CONTROLLER (VIRUSTOTAL-STYLE SECURITY STATUS)
   ================================================================ */

function updateBadge(tabId, verdict, isFamilyShield) {
  if (typeof chrome === "undefined" || !chrome.action || !chrome.action.setBadgeText) return;
  try {
    if (isFamilyShield) {
      chrome.action.setBadgeText({ tabId: tabId, text: "FS" });
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#d9534f" });
    } else if (verdict === "phishing") {
      chrome.action.setBadgeText({ tabId: tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#d9534f" });
    } else if (verdict === "suspicious") {
      chrome.action.setBadgeText({ tabId: tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#f0ad4e" });
    } else {
      chrome.action.setBadgeText({ tabId: tabId, text: "" });
    }
  } catch (e) {
    // Ignore closed/unsupported tabs
  }
}

chrome.tabs.onActivated.addListener(function (activeInfo) {
  chrome.tabs.get(activeInfo.tabId, function (tab) {
    if (chrome.runtime.lastError || !tab || !tab.url || shouldSkip(tab.url)) {
      updateBadge(activeInfo.tabId, "clean", false);
      return;
    }
    chrome.storage.local.get(["familyShieldEnabled"], function (stored) {
      var fsEnabled = stored.familyShieldEnabled !== undefined ? !!stored.familyShieldEnabled : true;
      if (fsEnabled) {
        var classifier = getClassifier();
        if (classifier) {
          var classification = classifier(tab.url);
          if (
            classification &&
            (classification.category === "adult" || classification.category === "gambling") &&
            (classification.confidence === "high" || classification.confidence === "medium")
          ) {
            updateBadge(activeInfo.tabId, "phishing", true);
            return;
          }
        }
      }
      var detector = getDetector();
      if (detector) {
        var analysis = detector(tab.url);
        if (analysis && analysis.finalVerdict) {
          updateBadge(activeInfo.tabId, analysis.finalVerdict, false);
          return;
        }
      }
      updateBadge(activeInfo.tabId, "clean", false);
    });
  });
});

/* ================================================================
   TAB NAVIGATION INTERCEPTION (PHISHING & FAMILY SHIELD)
   ================================================================ */

chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  if (changeInfo.status !== "loading" && !changeInfo.url) return;
  var url = changeInfo.url || tab.pendingUrl || (changeInfo.status === "loading" ? tab.url : null);
  if (!url || shouldSkip(url)) return;
  if (lastRedirectedUrl[tabId] === url) return;

  chrome.storage.local.get(["familyShieldEnabled"], function (stored) {
    var fsEnabled = stored.familyShieldEnabled !== undefined ? !!stored.familyShieldEnabled : true;

    // 1. Phishing check (Always active)
    var detector = getDetector();
    if (detector) {
      try {
        var analysis = detector(url);
        // Only trigger hard block on high-confidence "phishing" (not on "suspicious" or "not_flagged")
        if (
          analysis &&
          !analysis.error &&
          analysis.finalVerdict === "phishing"
        ) {
          var reason =
            (analysis.systemC && analysis.systemC.reasons && analysis.systemC.reasons[0]) ||
            "High-risk phishing indicators detected";
          lastRedirectedUrl[tabId] = url;
          updateBadge(tabId, "phishing", false);
          chrome.tabs.update(tabId, { url: makeBlockUrl(url, reason) });
          return;
        } else if (analysis && analysis.finalVerdict === "suspicious") {
          updateBadge(tabId, "suspicious", false);
        } else {
          updateBadge(tabId, "not_flagged", false);
        }
      } catch (err) {
        console.error("TriVex: Analysis error during navigation:", err);
      }
    }

    // 2. Family Shield check (Active when enabled)
    if (fsEnabled) {
      var classifier = getClassifier();
      if (classifier) {
        try {
          var classification = classifier(url);
          if (
            classification &&
            (classification.category === "adult" || classification.category === "gambling") &&
            (classification.confidence === "high" || classification.confidence === "medium")
          ) {
            var fsReason =
              (classification.evidence && classification.evidence[0]) ||
              "Filtered by Family Shield (" + classification.category + ")";
            lastRedirectedUrl[tabId] = url;
            updateBadge(tabId, "phishing", true);
            chrome.tabs.update(tabId, {
              url: makeFamilyShieldUrl(url, fsReason),
            });
            return;
          }
        } catch (err) {
          console.error("TriVex: Classifier error during navigation:", err);
        }
      }
    }

    if (lastRedirectedUrl[tabId] && lastRedirectedUrl[tabId] !== url) {
      delete lastRedirectedUrl[tabId];
    }
  });
});

/* ================================================================
   STRUCTURED MESSAGE API
   ================================================================ */

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (!message || typeof message !== "object") return false;

  switch (message.type) {
    case "ANALYZE_URL": {
      var targetUrl = message.url || "";
      var detector = getDetector();
      if (!detector) {
        sendResponse({ ok: false, error: "Detection engine unavailable" });
        return false;
      }
      try {
        var result = detector(targetUrl);
        sendResponse({ ok: true, result: result });
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
      return false;
    }

    case "PAGE_SIGNALS": {
      var signals = message.signals || {};
      var tabUrl = (sender.tab && sender.tab.url) || signals.url || "";
      chrome.storage.local.get(["pageSignals"], function (res) {
        var history = Array.isArray(res.pageSignals) ? res.pageSignals : [];
        history.unshift({
          url: tabUrl,
          signals: signals,
          timestamp: Date.now(),
        });
        if (history.length > 10) history.length = 10;
        chrome.storage.local.set({ pageSignals: history });
      });
      sendResponse({ ok: true });
      return false;
    }

    case "GET_PAGE_SIGNALS": {
      var reqUrl = message.url || "";
      chrome.storage.local.get(["pageSignals"], function (res) {
        var history = Array.isArray(res.pageSignals) ? res.pageSignals : [];
        var match = null;
        if (reqUrl) {
          match = history.find(function (item) {
            return item.url === reqUrl;
          });
        }
        sendResponse({ ok: true, signals: match ? match.signals : (history[0] ? history[0].signals : null) });
      });
      return true; // Keep message port open for async response
    }

    case "TOGGLE_FAMILY_SHIELD": {
      var newSetting = !!message.enabled;
      chrome.storage.local.set({ familyShieldEnabled: newSetting }, function () {
        sendResponse({ ok: true, enabled: newSetting });
      });
      return true;
    }

    case "GET_FAMILY_SHIELD_STATUS": {
      chrome.storage.local.get(["familyShieldEnabled"], function (res) {
        var isEnabled = res.familyShieldEnabled !== undefined ? !!res.familyShieldEnabled : true;
        sendResponse({ ok: true, enabled: isEnabled });
      });
      return true;
    }

    default:
      return false;
  }
});
