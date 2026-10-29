/*
 * background.js — TriVex MV3 service worker (Phase 7: Phishing Blocking).
 *
 * Intercepts tab navigations, analyzes the URL with the detector logic,
 * and redirects phishing URLs to the local block page.
 *
 * IMPORTANT: Service workers cannot use DOM APIs.
 * The core detector logic is inlined below (kept in sync with detector.js).
 *
 * Rules:
 *   - Only intercept http:// and https:// navigations
 *   - Never intercept extension pages (chrome-extension://)
 *   - Never intercept the block page itself (prevent redirect loops)
 *   - Redirect phishing URLs to block.html?url=<encoded>
 *   - Also forward PAGE_SIGNALS messages from content.js
 */

"use strict";

/* ================================================================
   INLINED DETECTOR LOGIC (must stay in sync with detector.js)
   ================================================================ */

var THRESHOLD = 45;
var KEYWORDS  = ["secure", "login", "verify", "update", "account", "banking"];

function isIpHostname(hostname) {
  if (!hostname) return false;
  if (hostname.charAt(0) === "[") return true;   // IPv6
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname); // IPv4
}

function extractFeatures(rawUrl, parsed) {
  var hostname   = parsed.hostname;
  var lowerUrl   = rawUrl.toLowerCase();
  var hyphenCount = (hostname.match(/-/g) || []).length;
  var dotCount    = (hostname.match(/\./g) || []).length;

  var matched = KEYWORDS.filter(function (kw) {
    return lowerUrl.indexOf(kw) !== -1;
  });

  var noHttps = parsed.protocol === "http:";

  return {
    features: {
      hostname_is_ip:     isIpHostname(hostname),
      suspicious_symbols: rawUrl.indexOf("@") !== -1 || hyphenCount >= 2,
      hostname_dot_count: dotCount > 3,
      keyword_match:      matched.length > 0,
      url_length:         rawUrl.length > 75,
      uses_https:         noHttps,
    },
    matchedKeywords: matched,
  };
}

function runSystemA(f) {
  var reasons = [];
  if (f.hostname_is_ip)     reasons.push("IP address detected in hostname");
  if (f.url_length)         reasons.push("URL length exceeds 75 characters");
  if (f.hostname_dot_count) reasons.push("Hostname has more than 3 dots (deep subdomains)");
  if (f.suspicious_symbols) reasons.push("URL contains '@' or hostname has 2+ hyphens");
  if (f.keyword_match && f.uses_https) reasons.push("Targeted keyword found AND HTTPS is absent");
  return { verdict: reasons.length > 0 ? "phishing" : "not_flagged", reasons: reasons };
}

function runSystemB(f) {
  var weights = { hostname_is_ip: 35, suspicious_symbols: 30, hostname_dot_count: 20,
                  keyword_match: 15, url_length: 10, uses_https: 10 };
  var labels  = { hostname_is_ip: "IP address", suspicious_symbols: "Suspicious symbols",
                  hostname_dot_count: "Deep subdomains", keyword_match: "Phishing keyword",
                  url_length: "Long URL", uses_https: "No HTTPS" };
  var score   = 0;
  var reasons = [];
  Object.keys(weights).forEach(function (k) {
    if (f[k]) {
      score += weights[k];
      reasons.push(labels[k] + " (+" + weights[k] + ")");
    }
  });
  return { score: score, maxScore: 120, threshold: THRESHOLD,
           verdict: score >= THRESHOLD ? "phishing" : "not_flagged", reasons: reasons };
}

function runSystemC(sysA, sysB) {
  var disagree = sysA.verdict !== sysB.verdict;
  var verdict  = sysA.verdict === "phishing" ? "phishing" : sysB.verdict;
  var reasons  = sysA.verdict === "phishing" ? sysA.reasons.slice() : sysB.reasons.slice();
  if (disagree) reasons.push("Detectors disagree: A=" + sysA.verdict + " B=" + sysB.verdict);
  return { verdict: verdict, reasons: reasons, disagreement: disagree };
}

function analyzeUrlInline(raw) {
  if (!raw) return null;
  var parsed;
  try { parsed = new URL(raw); } catch (e) { return null; }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  if (!parsed.hostname) return null;
  var ex   = extractFeatures(raw, parsed);
  var sysA = runSystemA(ex.features);
  var sysB = runSystemB(ex.features);
  var sysC = runSystemC(sysA, sysB);
  return { url: raw, systemC: sysC, systemA: sysA, systemB: sysB };
}

/* ================================================================
   BLOCK-PAGE URL HELPER
   ================================================================ */

function makeBlockUrl(blockedUrl, reason) {
  var base = chrome.runtime.getURL("block.html");
  return base + "?url=" + encodeURIComponent(blockedUrl) +
         "&reason=" + encodeURIComponent(reason || "phishing");
}

function makeFamilyShieldUrl(blockedUrl, reason) {
  var base = chrome.runtime.getURL("family_shield.html");
  return base + "?url=" + encodeURIComponent(blockedUrl) +
         "&reason=" + encodeURIComponent(reason || "filtered");
}

/* ================================================================
   SKIP-LIST — never intercept these URLs
   ================================================================ */

function shouldSkip(url) {
  if (!url) return true;
  if (url.startsWith("chrome://"))          return true;
  if (url.startsWith("chrome-extension://")) return true;
  if (url.startsWith("about:"))             return true;
  if (url.startsWith("data:"))              return true;
  if (url.startsWith("javascript:"))        return true;
  // Prevent redirect loops — skip our own block pages
  var blockHtml         = chrome.runtime.getURL("block.html");
  var familyShieldHtml  = chrome.runtime.getURL("family_shield.html");
  if (url.startsWith(blockHtml))        return true;
  if (url.startsWith(familyShieldHtml)) return true;
  return false;
}

/* ================================================================
   FAMILY SHIELD CONTENT CHECK (basic keyword / domain based)
   ================================================================ */

var ADULT_DOMAINS = [
  "pornhub.com", "xvideos.com", "redtube.com", "xnxx.com",
  "brazzers.com", "playboy.com", "hustler.com", "penthouse.com",
  "xxx.com", "sex.com"
];

var ADULT_KEYWORDS = [
  "pornography", "explicit-content", "adult-content", "xxx",
  "erotic", "nudity", "onlyfans"
];

function checkFamilyShield(url) {
  var lc = url.toLowerCase();
  var hostname;
  try {
    hostname = new URL(url).hostname.replace(/^www\./, "");
  } catch (e) {
    return null;
  }
  if (ADULT_DOMAINS.some(function (d) { return hostname === d || hostname.endsWith("." + d); })) {
    return { category: "adult", confidence: "high", reason: "Known adult content domain" };
  }
  if (ADULT_KEYWORDS.some(function (kw) { return lc.indexOf(kw) !== -1; })) {
    return { category: "adult", confidence: "medium", reason: "Adult content keyword in URL" };
  }
  return null;
}

/* ================================================================
   TAB NAVIGATION LISTENER
   ================================================================ */

chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
  // Only act on committed navigations with a real URL
  if (changeInfo.status !== "loading") return;
  var url = changeInfo.url || tab.url;
  if (!url) return;
  if (shouldSkip(url)) return;

  // Read Family Shield setting from storage (async)
  chrome.storage.local.get(["familyShieldEnabled"], function (result) {
    var fsEnabled = !!result.familyShieldEnabled;

    // --- Phishing check (always on) ---
    var analysis = analyzeUrlInline(url);
    if (analysis && analysis.systemC.verdict === "phishing") {
      var reason = analysis.systemC.reasons[0] || "Flagged as phishing";
      chrome.tabs.update(tabId, { url: makeBlockUrl(url, reason) });
      return;
    }

    // --- Family Shield check (only when enabled) ---
    if (fsEnabled) {
      var fsResult = checkFamilyShield(url);
      if (fsResult) {
        chrome.tabs.update(tabId, {
          url: makeFamilyShieldUrl(url, fsResult.reason)
        });
        return;
      }
    }
  });
});

/* ================================================================
   MESSAGE LISTENER (from content.js)
   ================================================================ */

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (!message || message.type !== "PAGE_SIGNALS") return false;

  var signals = message.signals || {};
  var tabUrl  = sender.tab && sender.tab.url;

  // Log signals to storage for popup display (ring-buffer of last 5)
  chrome.storage.local.get(["pageSignals"], function (res) {
    var history = Array.isArray(res.pageSignals) ? res.pageSignals : [];
    history.unshift({ url: tabUrl, signals: signals, ts: Date.now() });
    if (history.length > 5) history.length = 5;
    chrome.storage.local.set({ pageSignals: history });
  });

  sendResponse({ ok: true });
  return true; // keep channel open for async
});
