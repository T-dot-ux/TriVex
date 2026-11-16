/*
 * detector.js — TriVex phishing-URL detection engine (Member 2).
 *
 * Implements three detection systems:
 *   System A — Rule-based   (flag if ANY rule triggers)
 *   System B — Weighted     (flag if total score >= THRESHOLD)
 *   System C — Hybrid       (A wins if it flags; otherwise B decides; disagreements reported)
 *
 * Public API (unchanged from stand-in so popup.js keeps working):
 *   analyzeUrl(url)   → result object (see JSDoc below)
 *   PhishGuard        → { analyzeUrl, FEATURE_LABELS, FEATURE_WEIGHTS, emptyFeatures }
 *   FEATURE_LABELS    → { [featureKey]: humanLabel }
 *   FEATURE_WEIGHTS   → { [featureKey]: number }
 *   emptyFeatures()   → all-false feature object
 *
 * Backward-compat aliases in result:
 *   ruleBased  = systemA
 *   weighted   = systemB
 *   hybrid     = systemC
 *
 * Works in browser (sets window.PhishGuard / window.analyzeUrl)
 * and in Node/service-worker (module.exports / self export).
 */
(function (root) {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* Constants                                                            */
  /* ------------------------------------------------------------------ */

  var THRESHOLD = 45;

  /**
   * Feature weights for System B (weighted scoring).
   * Keys match the feature object returned by extractFeatures().
   */
  var FEATURE_WEIGHTS = {
    hostname_is_ip: 35,
    suspicious_symbols: 30,
    hostname_dot_count: 20,
    keyword_match: 15,
    url_length: 10,
    uses_https: 10,   // weight is for the ABSENCE of https (noHttps flag)
  };

  /**
   * Human-readable labels for each feature (used in popup and reports).
   */
  var FEATURE_LABELS = {
    hostname_is_ip: "IP address used as hostname",
    suspicious_symbols: "Suspicious symbols (@ or multiple hyphens)",
    hostname_dot_count: "Excessive subdomain depth (more than 3 dots)",
    keyword_match: "Targeted keyword in URL",
    url_length: "URL longer than 75 characters",
    uses_https: "HTTPS absent (plain HTTP)",
  };

  /** Phishing-related keywords to match anywhere in the full URL. */
  var KEYWORDS = ["secure", "login", "verify", "update", "account", "banking"];

  /* ------------------------------------------------------------------ */
  /* Helpers                                                              */
  /* ------------------------------------------------------------------ */

  /**
   * Detect whether a hostname is a raw IP address (IPv4 or IPv6).
   * The WHATWG URL parser wraps IPv6 literals in brackets, e.g. "[::1]".
   * @param {string} hostname  Parsed hostname from new URL().
   * @returns {boolean}
   */
  function isIpHostname(hostname) {
    if (!hostname) return false;
    // IPv6 — URL API produces "[<address>]" for IPv6 literals
    if (hostname.charAt(0) === "[") return true;
    // IPv4 — four dotted decimal octets
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  }

  /* ------------------------------------------------------------------ */
  /* Feature extraction                                                   */
  /* ------------------------------------------------------------------ */

  /**
   * Extract the six URL features defined in the TriVex playbook.
   *
   * Feature semantics (true = the suspicious condition holds):
   *   hostname_is_ip      — hostname is an IPv4 or IPv6 literal
   *   suspicious_symbols  — '@' anywhere in the URL OR 2+ hyphens in hostname
   *   hostname_dot_count  — more than 3 dots in the hostname
   *   keyword_match       — at least one KEYWORD found in the full URL (case-insensitive)
   *   url_length          — URL length exceeds 75 characters
   *   uses_https          — TRUE when HTTPS is ABSENT (noHttps); consistent with weight table
   *
   * @param {string} rawUrl   The original URL string as entered.
   * @param {URL}    parsed   The parsed URL object.
   * @returns {{ features: object, matchedKeywords: string[] }}
   */
  function extractFeatures(rawUrl, parsed) {
    var hostname = parsed.hostname;
    var lowerUrl = rawUrl.toLowerCase();

    // Count hyphens and dots only in the hostname (not in the path / query)
    var hyphenCount = (hostname.match(/-/g) || []).length;
    var dotCount = (hostname.match(/\./g) || []).length;

    var matched = KEYWORDS.filter(function (kw) {
      return lowerUrl.indexOf(kw) !== -1;
    });

    var noHttps = parsed.protocol === "http:";

    return {
      features: {
        hostname_is_ip: isIpHostname(hostname),
        suspicious_symbols: rawUrl.indexOf("@") !== -1 || hyphenCount >= 2,
        hostname_dot_count: dotCount > 3,
        keyword_match: matched.length > 0,
        url_length: rawUrl.length > 75,
        uses_https: noHttps,          // true = suspicious (no HTTPS)
      },
      matchedKeywords: matched,
    };
  }

  /* ------------------------------------------------------------------ */
  /* System A — Rule-based                                                */
  /* ------------------------------------------------------------------ */

  /**
   * Flag the URL if ANY of the five rules fire.
   * Rule for keyword: triggers only when keyword is present AND HTTPS is absent.
   *
   * @param {object} f  Feature object from extractFeatures().
   * @returns {{ verdict: string, reasons: string[] }}
   */
  function runSystemA(f) {
    var reasons = [];
    if (f.hostname_is_ip)
      reasons.push("IP address detected in hostname");
    if (f.url_length)
      reasons.push("URL length exceeds 75 characters");
    if (f.hostname_dot_count)
      reasons.push("Hostname has more than 3 dots (deep subdomains)");
    if (f.suspicious_symbols)
      reasons.push("URL contains '@' or hostname has 2+ hyphens");
    if (f.keyword_match && f.uses_https)
      reasons.push("Targeted keyword found AND HTTPS is absent");
    return {
      verdict: reasons.length > 0 ? "phishing" : "not_flagged",
      reasons: reasons,
    };
  }

  /* ------------------------------------------------------------------ */
  /* System B — Weighted score                                            */
  /* ------------------------------------------------------------------ */

  /**
   * Compute a weighted risk score.  Flag if score >= THRESHOLD (45).
   * The 'uses_https' weight is added when HTTPS is ABSENT (feature = true).
   *
   * @param {object} f  Feature object from extractFeatures().
   * @returns {{ score, maxScore, threshold, verdict, reasons }}
   */
  function runSystemB(f) {
    var score = 0;
    var reasons = [];

    var featureWeightMap = [
      { key: "hostname_is_ip", label: "IP address in hostname", weight: FEATURE_WEIGHTS.hostname_is_ip },
      { key: "suspicious_symbols", label: "Suspicious symbols (@ or 2+ hyphens)", weight: FEATURE_WEIGHTS.suspicious_symbols },
      { key: "hostname_dot_count", label: "Deep subdomains (>3 dots in hostname)", weight: FEATURE_WEIGHTS.hostname_dot_count },
      { key: "keyword_match", label: "Targeted phishing keyword", weight: FEATURE_WEIGHTS.keyword_match },
      { key: "url_length", label: "Long URL (>75 chars)", weight: FEATURE_WEIGHTS.url_length },
      { key: "uses_https", label: "HTTPS absent", weight: FEATURE_WEIGHTS.uses_https },
    ];

    featureWeightMap.forEach(function (item) {
      if (f[item.key]) {
        score += item.weight;
        reasons.push(item.label + " (+" + item.weight + ")");
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

  /* ------------------------------------------------------------------ */
  /* System C — Hybrid                                                    */
  /* ------------------------------------------------------------------ */

  /**
   * Hybrid decision engine:
   *   1. Runs System A and System B independently.
   *   2. Flags high-confidence "phishing" if:
   *      - Weighted risk score >= THRESHOLD (45+), OR
   *      - Critical high-confidence rule fires: IP hostname, '@' user-info,
   *        or phishing keyword combined with plain HTTP.
   *   3. Classifies as "suspicious" (caution / review needed) if:
   *      - System A flagged a single moderate/weak rule (e.g. length > 75 or >3 dots)
   *        while System B score is low, preventing false-positive hard blocking.
   *      - Or System B has a moderate cumulative score (30 <= score < 45).
   *   4. Classifies as "not_flagged" (low risk) if neither system flagged.
   *   5. Explicitly records disagreement and uncertainty.
   *
   * @param {object} f      Feature object from extractFeatures().
   * @param {string} rawUrl Full input URL string.
   * @param {object} sysA   System A result.
   * @param {object} sysB   System B result.
   * @returns {{ verdict: string, riskLevel: string, riskScore: number, reasons: string[], disagreement: boolean }}
   */
  function runSystemC(f, rawUrl, sysA, sysB) {
    var reasons = [];
    var verdict;
    var riskLevel;
    var urlStr = typeof rawUrl === "string" ? rawUrl : "";

    var hasIp = !!f.hostname_is_ip;
    var hasAt = urlStr.indexOf("@") !== -1;
    var hasKeywordNoHttps = !!(f.keyword_match && f.uses_https);
    var hasScoreThreshold = sysB.score >= sysB.threshold;

    var disagree = sysA.verdict !== sysB.verdict;

    if (hasScoreThreshold || hasIp || hasAt || hasKeywordNoHttps) {
      verdict = "phishing";
      riskLevel = "high";
      if (hasScoreThreshold) {
        reasons.push("Cumulative weighted risk score (" + sysB.score + ") exceeds threshold (" + sysB.threshold + ")");
      }
      if (hasIp) {
        reasons.push("Critical indicator: raw IP address used as hostname");
      }
      if (hasAt) {
        reasons.push("Critical indicator: '@' symbol in URL indicates user-info spoofing");
      }
      if (hasKeywordNoHttps) {
        reasons.push("Critical indicator: credential/banking keyword on insecure HTTP connection");
      }
      sysA.reasons.forEach(function (r) {
        var formatted = "  A: " + r;
        if (reasons.indexOf(formatted) === -1) reasons.push(formatted);
      });
    } else if (sysA.verdict === "phishing") {
      // System A flagged on a moderate rule, but cumulative score is low (< 45)
      verdict = "suspicious";
      riskLevel = "medium";
      reasons.push(
        "Moderate indicators detected (" + sysA.reasons.join(", ") +
        "), but cumulative risk score (" + sysB.score + "/" + sysB.threshold +
        ") is below critical threshold. Treat with caution."
      );
      disagree = true;
    } else if (sysB.score >= 30) {
      // Moderate score near threshold
      verdict = "suspicious";
      riskLevel = "medium";
      reasons.push(
        "Moderate cumulative risk score (" + sysB.score + "/" + sysB.threshold +
        " threshold). Verify site credentials."
      );
      disagree = true;
    } else {
      verdict = "not_flagged";
      riskLevel = "low";
      reasons.push(
        "No high-risk indicators detected (score " + sysB.score + "/" + sysB.threshold +
        " threshold)."
      );
    }

    if (disagree) {
      reasons.push(
        "Disagreement: System A says \"" + sysA.verdict +
        "\" and System B says \"" + sysB.verdict + "\"."
      );
    }

    return {
      verdict: verdict,
      riskLevel: riskLevel,
      riskScore: sysB.score,
      reasons: reasons,
      disagreement: disagree
    };
  }

  /* ------------------------------------------------------------------ */
  /* Public API                                                           */
  /* ------------------------------------------------------------------ */

  /**
   * Return a fresh all-false feature object (useful for resetting UI state).
   * @returns {object}
   */
  function emptyFeatures() {
    return {
      hostname_is_ip: false,
      suspicious_symbols: false,
      hostname_dot_count: false,
      keyword_match: false,
      url_length: false,
      uses_https: false,
    };
  }

  /**
   * Analyze a URL string with all three detection systems.
   *
   * @param {string} input  Raw URL string (may be untrimmed).
   * @returns {object}  Analysis result.  On error the object contains { url, error }.
   *
   * Success shape:
   * {
   *   url, hostname, validationStatus,
   *   features: { hostname_is_ip, suspicious_symbols, hostname_dot_count,
   *               keyword_match, url_length, uses_https },
   *   matchedKeywords: string[],
   *   systemA: { verdict, reasons },
   *   systemB: { score, maxScore, threshold, verdict, reasons },
   *   systemC: { verdict, reasons, disagreement },
   *   finalVerdict: string,
   *   explanation: string,
   *   // backward-compat aliases:
   *   ruleBased: <systemA>,
   *   weighted:  <systemB>,
   *   hybrid:    <systemC>,
   * }
   */
  function analyzeUrl(input) {
    var raw = (typeof input === "string" ? input : "").trim();

    if (!raw) {
      return { url: raw, validationStatus: "empty", error: "Please enter a URL." };
    }

    // Auto-normalize bare domain names without protocol scheme
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
      raw = "https://" + raw;
    }

    var parsed;
    try {
      parsed = new URL(raw);
    } catch (e) {
      return {
        url: raw,
        validationStatus: "parse_error",
        error: "Could not parse that URL. Include the full address, e.g. https://example.com/",
      };
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        url: raw,
        validationStatus: "unsupported_scheme",
        error: "Only http and https URLs can be analyzed (got " + parsed.protocol + ").",
      };
    }

    if (!parsed.hostname) {
      return { url: raw, validationStatus: "no_hostname", error: "The URL has no hostname." };
    }

    var ex = extractFeatures(raw, parsed);
    var sysA = runSystemA(ex.features);
    var sysB = runSystemB(ex.features);
    var sysC = runSystemC(ex.features, raw, sysA, sysB);

    // System C v2: If local ML engine is present, execute LightGBM prediction and fusion
    var sysCv2 = null;
    if (root.TriVexSystemCv2 && typeof root.TriVexSystemCv2.evaluateSystemC_v2 === "function") {
      try {
        sysCv2 = root.TriVexSystemCv2.evaluateSystemC_v2(raw, {
          systemA: sysA,
          systemB: sysB,
        });
      } catch (err) {
        console.warn("TriVex: System C v2 evaluation failed, using v1 fallback:", err);
      }
    }

    var finalVerdict = (sysCv2 && sysCv2.finalVerdict) ? sysCv2.finalVerdict : sysC.verdict;
    var riskLevel = (sysCv2 && sysCv2.riskLevel) ? sysCv2.riskLevel : sysC.riskLevel;
    var riskScore = sysC.riskScore;

    var explanation;
    var flagCount = [sysA, sysB, sysC].filter(function (s) {
      return s.verdict === "phishing";
    }).length;
    if (flagCount === 0) {
      explanation =
        "None of the three detectors flagged this URL. " +
        "That only means these six URL features did not look suspicious — " +
        "it is not a guarantee that the site is safe.";
    } else if (flagCount === 3) {
      explanation =
        "All three detectors flagged this URL. " +
        "Check the triggered features above and avoid entering passwords " +
        "or personal details unless you are certain of the site.";
    } else {
      explanation =
        "The detectors disagree (" + flagCount + " of 3 flagged). " +
        "Treat this URL with caution and review the triggered features.";
    }

    return {
      url: raw,
      hostname: parsed.hostname,
      validationStatus: "ok",
      features: ex.features,
      matchedKeywords: ex.matchedKeywords,
      systemA: sysA,
      systemB: sysB,
      systemC: sysC,
      systemCv2: sysCv2,
      finalVerdict: finalVerdict,
      riskLevel: riskLevel,
      riskScore: riskScore,
      explanation: explanation,
      // Backward-compat aliases so existing popup.js keeps working unchanged
      ruleBased: sysA,
      weighted: sysB,
      hybrid: sysC,
    };
  }

  /* ------------------------------------------------------------------ */
  /* Export                                                               */
  /* ------------------------------------------------------------------ */

  var api = {
    analyzeUrl: analyzeUrl,
    FEATURE_LABELS: FEATURE_LABELS,
    FEATURE_WEIGHTS: FEATURE_WEIGHTS,
    emptyFeatures: emptyFeatures,
  };

  // Browser global (popup.html script tag)
  root.PhishGuard = api;
  root.analyzeUrl = analyzeUrl;

  // Node / CommonJS (evaluate.py interop via node runner, or Jest tests)
  if (typeof module !== "undefined" && module.exports) module.exports = api;

})(typeof self !== "undefined" ? self : this);
