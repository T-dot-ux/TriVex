/*
 * background.js — TriVex MV3 Service Worker.
 */

"use strict";

try {
  importScripts("blocklist.js", "detector.js", "family_shield.js");
} catch (e) {
  console.error("TriVex: importScripts failed:", e);
}

/* ------------------------------------------------------------------ */
/* Accessors                                                            */
/* ------------------------------------------------------------------ */
function getDetector() {
  if (typeof self.analyzeUrl === "function") return self.analyzeUrl;
  if (self.PhishGuard && typeof self.PhishGuard.analyzeUrl === "function") return self.PhishGuard.analyzeUrl;
  return null;
}

function getClassifier() {
  if (self.FamilyShield && typeof self.FamilyShield.classifyUrl === "function") return self.FamilyShield.classifyUrl;
  return null;
}

/* ------------------------------------------------------------------ */
/* URL helpers                                                          */
/* ------------------------------------------------------------------ */
function makeBlockUrl(blockedUrl, reason) {
  return chrome.runtime.getURL("block.html")
    + "?url=" + encodeURIComponent(blockedUrl)
    + "&reason=" + encodeURIComponent(reason || "High-risk phishing indicators detected");
}

function makeFamilyShieldUrl(blockedUrl, reason) {
  return chrome.runtime.getURL("family_shield.html")
    + "?url=" + encodeURIComponent(blockedUrl)
    + "&reason=" + encodeURIComponent(reason || "Filtered by Family Shield");
}

function shouldSkip(url) {
  if (!url || typeof url !== "string") return true;
  var l = url.toLowerCase();
  if (l.startsWith("chrome://") || l.startsWith("chrome-extension://") ||
      l.startsWith("extension://") || l.startsWith("about:") ||
      l.startsWith("data:") || l.startsWith("javascript:") ||
      l.startsWith("edge://") || l.startsWith("brave://") ||
      l.startsWith("opera://") || l.startsWith("devtools://") ||
      l.startsWith("view-source:")) return true;
  if (url.startsWith(chrome.runtime.getURL("block.html"))) return true;
  if (url.startsWith(chrome.runtime.getURL("family_shield.html"))) return true;
  return false;
}

var lastRedirectedUrl = {};
chrome.tabs.onRemoved.addListener(function (tabId) { delete lastRedirectedUrl[tabId]; });

/* ------------------------------------------------------------------ */
/* Declarative Net Request — built from blocklist.js dictionary         */
/*                                                                      */
/* One urlFilter rule per keyword (Chrome DNR has a ~1000 char regex   */
/* limit so regexFilter with 50+ keywords would fail).                 */
/* One requestDomains rule covers all known adult/gambling domains.     */
/* IDs start at 3000 for keywords, 2999 for the domain rule.           */
/* Add to blocklist.js only — no other file needs to change.           */
/* ------------------------------------------------------------------ */

var DNR_DOMAIN_RULE_ID  = 2999;
var DNR_KEYWORD_ID_BASE = 3000;  // keyword rules: 3000, 3001, 3002 …

function buildFamilyShieldRules() {
  var bl = (typeof self !== "undefined" && self.TriVexBlocklist) ? self.TriVexBlocklist : {};
  var keywords = (bl.ADULT_KEYWORDS    || []).concat(bl.GAMBLING_KEYWORDS || []);
  var domains  = (bl.ADULT_DOMAINS     || []).concat(bl.GAMBLING_DOMAINS  || []);
  var fsUrl    = chrome.runtime.getURL("family_shield.html");
  var rules    = [];

  /* One urlFilter rule per keyword — simple, proven to work */
  keywords.forEach(function (kw, i) {
    rules.push({
      id: DNR_KEYWORD_ID_BASE + i,
      priority: 1,
      action: { type: "redirect", redirect: { url: fsUrl } },
      condition: { urlFilter: "*" + kw + "*", resourceTypes: ["main_frame"] }
    });
  });

  /* Single domain rule — most precise, highest priority */
  if (domains.length > 0) {
    rules.push({
      id: DNR_DOMAIN_RULE_ID,
      priority: 2,
      action: { type: "redirect", redirect: { url: fsUrl } },
      condition: { requestDomains: domains, resourceTypes: ["main_frame"] }
    });
  }

  return rules;
}

function getAllDNRIds() {
  var bl = (typeof self !== "undefined" && self.TriVexBlocklist) ? self.TriVexBlocklist : {};
  var keywords = (bl.ADULT_KEYWORDS || []).concat(bl.GAMBLING_KEYWORDS || []);
  var ids = keywords.map(function (_, i) { return DNR_KEYWORD_ID_BASE + i; });
  ids.push(DNR_DOMAIN_RULE_ID);
  return ids;
}

function syncFamilyShieldDNR(enabled) {
  var allIds = getAllDNRIds();
  if (enabled) {
    var rules = buildFamilyShieldRules();
    chrome.declarativeNetRequest.updateDynamicRules(
      { addRules: rules, removeRuleIds: allIds },
      function () {
        if (chrome.runtime.lastError) {
          console.error("TriVex DNR error:", chrome.runtime.lastError.message);
        } else {
          console.log("TriVex: Family Shield active — " + rules.length + " DNR rules loaded.");
        }
      }
    );
  } else {
    chrome.declarativeNetRequest.updateDynamicRules(
      { addRules: [], removeRuleIds: allIds },
      function () {
        if (chrome.runtime.lastError) console.error("TriVex DNR remove error:", chrome.runtime.lastError.message);
        else console.log("TriVex: Family Shield DNR rules removed.");
      }
    );
  }
}

chrome.runtime.onInstalled.addListener(function () {
  chrome.storage.local.get(["familyShieldEnabled"], function (res) {
    var enabled = res.familyShieldEnabled !== undefined ? !!res.familyShieldEnabled : true;
    syncFamilyShieldDNR(enabled);
  });
});

chrome.storage.onChanged.addListener(function (changes, area) {
  if (area === "local" && "familyShieldEnabled" in changes) {
    syncFamilyShieldDNR(!!changes.familyShieldEnabled.newValue);
  }
});

/* ------------------------------------------------------------------ */
/* Badge controller                                                     */
/* ------------------------------------------------------------------ */
function updateBadge(tabId, verdict, isFamilyShield) {
  if (!chrome.action) return;
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
  } catch (e) { /* ignore closed-tab errors */ }
}

/* ------------------------------------------------------------------ */
/* Tab activation — refresh badge                                       */
/* ------------------------------------------------------------------ */
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
          var c = classifier(tab.url);
          if (c && (c.category === "adult" || c.category === "gambling") &&
              (c.confidence === "high" || c.confidence === "medium")) {
            updateBadge(activeInfo.tabId, "phishing", true);
            return;
          }
        }
      }
      var detector = getDetector();
      if (detector) {
        var a = detector(tab.url);
        if (a && a.finalVerdict) { updateBadge(activeInfo.tabId, a.finalVerdict, false); return; }
      }
      updateBadge(activeInfo.tabId, "clean", false);
    });
  });
});

/* ------------------------------------------------------------------ */
/* Navigation interception fallback (catches what DNR may miss)         */
/* ------------------------------------------------------------------ */
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  var url = changeInfo.url || tab.pendingUrl || tab.url;
  if (!url || shouldSkip(url) || lastRedirectedUrl[tabId] === url) return;

  chrome.storage.local.get(["familyShieldEnabled"], function (stored) {
    var fsEnabled = stored.familyShieldEnabled !== undefined ? !!stored.familyShieldEnabled : true;

    // Phishing check
    var detector = getDetector();
    if (detector) {
      try {
        var a = detector(url);
        if (a && !a.error && a.finalVerdict === "phishing") {
          var reason = (a.systemC && a.systemC.reasons && a.systemC.reasons[0]) || "High-risk phishing indicators detected";
          lastRedirectedUrl[tabId] = url;
          updateBadge(tabId, "phishing", false);
          chrome.tabs.update(tabId, { url: makeBlockUrl(url, reason) });
          return;
        } else if (a && a.finalVerdict === "suspicious") {
          updateBadge(tabId, "suspicious", false);
        } else {
          updateBadge(tabId, "not_flagged", false);
        }
      } catch (e) { console.error("TriVex: analysis error:", e); }
    }

    // Family Shield fallback check (secondary to DNR)
    if (fsEnabled) {
      var classifier = getClassifier();
      if (classifier) {
        try {
          var c = classifier(url);
          if (c && (c.category === "adult" || c.category === "gambling") &&
              (c.confidence === "high" || c.confidence === "medium")) {
            var fsReason = (c.evidence && c.evidence[0]) || "Filtered by Family Shield (" + c.category + ")";
            lastRedirectedUrl[tabId] = url;
            updateBadge(tabId, "phishing", true);
            chrome.tabs.update(tabId, { url: makeFamilyShieldUrl(url, fsReason) });
            return;
          }
        } catch (e) { console.error("TriVex: classifier error:", e); }
      }
    }

    if (lastRedirectedUrl[tabId] && lastRedirectedUrl[tabId] !== url) delete lastRedirectedUrl[tabId];
  });
});

/* ------------------------------------------------------------------ */
/* Message API                                                          */
/* ------------------------------------------------------------------ */
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (!message || typeof message !== "object") return false;

  switch (message.type) {

    case "PAGE_BLOCKED": {
      if (sender.tab && sender.tab.id) {
        var isFS = message.blockType === "family_shield";
        lastRedirectedUrl[sender.tab.id] = message.url;
        updateBadge(sender.tab.id, "phishing", isFS);
      }
      sendResponse({ ok: true });
      return false;
    }

    case "NAVIGATED_URL": {
      var navUrl = message.url || "";
      if (!navUrl || shouldSkip(navUrl)) { sendResponse({ redirectUrl: null }); return false; }
      chrome.storage.local.get(["familyShieldEnabled"], function (stored) {
        var fsEnabled = stored.familyShieldEnabled !== undefined ? !!stored.familyShieldEnabled : true;
        var detector = getDetector();
        if (detector) {
          try {
            var a = detector(navUrl);
            if (a && !a.error && a.finalVerdict === "phishing") {
              var reason = (a.systemC && a.systemC.reasons && a.systemC.reasons[0]) || "High-risk phishing indicators detected";
              var target = makeBlockUrl(navUrl, reason);
              if (sender.tab && sender.tab.id) {
                lastRedirectedUrl[sender.tab.id] = navUrl;
                updateBadge(sender.tab.id, "phishing", false);
                chrome.tabs.update(sender.tab.id, { url: target });
              }
              sendResponse({ redirectUrl: target });
              return;
            }
          } catch (e) { console.error(e); }
        }
        if (fsEnabled) {
          var classifier = getClassifier();
          if (classifier) {
            try {
              var c = classifier(navUrl);
              if (c && (c.category === "adult" || c.category === "gambling") &&
                  (c.confidence === "high" || c.confidence === "medium")) {
                var fsReason = (c.evidence && c.evidence[0]) || "Filtered by Family Shield (" + c.category + ")";
                var fsTarget = makeFamilyShieldUrl(navUrl, fsReason);
                if (sender.tab && sender.tab.id) {
                  lastRedirectedUrl[sender.tab.id] = navUrl;
                  updateBadge(sender.tab.id, "phishing", true);
                  chrome.tabs.update(sender.tab.id, { url: fsTarget });
                }
                sendResponse({ redirectUrl: fsTarget });
                return;
              }
            } catch (e) { console.error(e); }
          }
        }
        sendResponse({ redirectUrl: null });
      });
      return true;
    }

    case "ANALYZE_URL": {
      var targetUrl = message.url || "";
      var det = getDetector();
      if (!det) { sendResponse({ ok: false, error: "Detection engine unavailable" }); return false; }
      try {
        sendResponse({ ok: true, result: det(targetUrl) });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
      return false;
    }

    case "PAGE_SIGNALS": {
      var signals = message.signals || {};
      var tabUrl = (sender.tab && sender.tab.url) || signals.url || "";
      chrome.storage.local.get(["pageSignals"], function (res) {
        var history = Array.isArray(res.pageSignals) ? res.pageSignals : [];
        history.unshift({ url: tabUrl, signals: signals, timestamp: Date.now() });
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
        var match = reqUrl ? history.find(function (i) { return i.url === reqUrl; }) : null;
        sendResponse({ ok: true, signals: match ? match.signals : (history[0] ? history[0].signals : null) });
      });
      return true;
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
