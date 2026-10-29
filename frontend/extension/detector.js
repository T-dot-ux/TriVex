/*
 * detector.js - detection module (Member 2 owns this file).
 *
 * STAND-IN IMPLEMENTATION written by Member 1 so the popup works end to end.
 * It follows the interface agreed in the team README:  analyzeUrl(url)
 * Member 2: replace the body of this file with the final, tested version,
 * but keep the shape of the returned object so the popup keeps working.
 *
 * Works in the browser (global `analyzeUrl`) and in Node (module.exports).
 */
(function (root) {
  "use strict";

  var THRESHOLD = 45;
  var WEIGHTS = {
    hasIp: 35,
    suspiciousSymbols: 30,
    deepSubdomains: 20,
    targetedKeyword: 15,
    longUrl: 10,
    noHttps: 10,
  };
  var KEYWORDS = ["login", "secure", "verify", "update", "account", "banking"];

  var LABELS = {
    hasIp: "IP address used as hostname",
    suspiciousSymbols: "Suspicious symbols (@ or multiple hyphens)",
    deepSubdomains: "Excessive subdomain depth (more than 3 dots)",
    targetedKeyword: "Targeted keyword in URL",
    longUrl: "URL longer than 75 characters",
    noHttps: "HTTPS absent (plain HTTP)",
  };

  // ---- Feature extraction (definitions to be confirmed by Member 2) ----
  function isIpHost(hostname) {
    // IPv6 literals are wrapped in [] by the URL parser.
    if (hostname.charAt(0) === "[") return true;
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  }

  function extractFeatures(rawUrl, parsed) {
    var host = parsed.hostname;
    var lower = rawUrl.toLowerCase();
    var hyphenCount = (host.match(/-/g) || []).length;
    var dotCount = (host.match(/\./g) || []).length;
    var found = KEYWORDS.filter(function (k) {
      return lower.indexOf(k) !== -1;
    });
    return {
      features: {
        hasIp: isIpHost(host),
        longUrl: rawUrl.length > 75,
        deepSubdomains: dotCount > 3,
        suspiciousSymbols: rawUrl.indexOf("@") !== -1 || hyphenCount >= 2,
        targetedKeyword: found.length > 0,
        noHttps: parsed.protocol === "http:",
      },
      matchedKeywords: found,
    };
  }

  // ---- System A: rule-based (the paper's rules as written) ----
  function runRuleBased(f) {
    var reasons = [];
    if (f.hasIp) reasons.push("IP address detected in hostname");
    if (f.longUrl) reasons.push("URL length is greater than 75 characters");
    if (f.deepSubdomains) reasons.push("Hostname has more than 3 dots");
    if (f.suspiciousSymbols) reasons.push("Contains @ or multiple hyphens");
    if (f.targetedKeyword && f.noHttps)
      reasons.push("Targeted keyword combined with missing HTTPS");
    return {
      verdict: reasons.length ? "phishing" : "not_flagged",
      reasons: reasons,
    };
  }

  // ---- System B: manually weighted scoring (not a trained model) ----
  function runWeighted(f) {
    var score = 0;
    var reasons = [];
    Object.keys(WEIGHTS).forEach(function (k) {
      if (f[k]) {
        score += WEIGHTS[k];
        reasons.push(LABELS[k] + " (+" + WEIGHTS[k] + ")");
      }
    });
    return {
      score: score,
      maxScore: 120,
      threshold: THRESHOLD,
      verdict: score >= THRESHOLD ? "phishing" : "not_flagged",
      reasons: reasons,
    };
  }

  // ---- System C: hybrid (PLACEHOLDER policy - Member 2 must finalise) ----
  // 1. High-confidence rules (IP hostname, or '@' in the URL) decide directly.
  // 2. Otherwise the weighted score decides.
  // 3. Disagreement between A and B is reported.
  function runHybrid(f, rawUrl, a, b) {
    var reasons = [];
    var verdict;
    if (f.hasIp) {
      verdict = "phishing";
      reasons.push("High-confidence rule: IP address used as hostname");
    } else if (rawUrl.indexOf("@") !== -1) {
      verdict = "phishing";
      reasons.push("High-confidence rule: '@' present in URL");
    } else {
      verdict = b.verdict;
      reasons.push(
        "Decided by weighted score: " + b.score + " / " + b.threshold + " threshold"
      );
    }
    var disagree = a.verdict !== b.verdict;
    if (disagree) {
      reasons.push(
        "Detectors disagree: rule-based says " + a.verdict +
          ", weighted score says " + b.verdict
      );
    }
    return { verdict: verdict, reasons: reasons, disagreement: disagree };
  }

  function emptyFeatures() {
    return {
      hasIp: false, longUrl: false, deepSubdomains: false,
      suspiciousSymbols: false, targetedKeyword: false, noHttps: false,
    };
  }

  function analyzeUrl(input) {
    var raw = typeof input === "string" ? input.trim() : "";
    if (!raw) {
      return { url: raw, error: "Please enter a URL." };
    }
    var parsed;
    try {
      parsed = new URL(raw);
    } catch (e) {
      return {
        url: raw,
        error: "Could not parse that URL. Include the full address, e.g. https://example.com/",
      };
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        url: raw,
        error: "Only http and https URLs can be analyzed (got " + parsed.protocol + ").",
      };
    }
    if (!parsed.hostname) {
      return { url: raw, error: "The URL has no hostname." };
    }

    var ex = extractFeatures(raw, parsed);
    var a = runRuleBased(ex.features);
    var b = runWeighted(ex.features);
    var c = runHybrid(ex.features, raw, a, b);

    return {
      url: raw,
      hostname: parsed.hostname,
      features: ex.features,
      matchedKeywords: ex.matchedKeywords,
      ruleBased: a,
      weighted: b,
      hybrid: c,
    };
  }

  var api = {
    analyzeUrl: analyzeUrl,
    FEATURE_LABELS: LABELS,
    FEATURE_WEIGHTS: WEIGHTS,
    emptyFeatures: emptyFeatures,
  };
  root.PhishGuard = api;
  root.analyzeUrl = analyzeUrl;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : this);
