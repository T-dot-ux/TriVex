/*
 * feature_extractor.js — TriVex System C v2 Client Feature Extractor.
 *
 * Implements the identical 38-feature numerical extraction schema defined
 * in backend/ml/feature_schema.py and backend/ml/feature_extractor.py.
 *
 * Runs locally in browser environments (content script, popup, background service worker)
 * and Node.js testing environments without any external dependencies.
 */

(function (root) {
  "use strict";

  var SCHEMA_VERSION = "2.0.0";

  var FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "num_query_params",
    "special_char_count",
    "has_at_symbol",
    "hyphen_count_total",
    "hyphen_count_host",
    "percent_encoding_count",
    "digit_ratio_url",
    "digit_ratio_host",
    "is_ip_host",
    "dot_count_host",
    "subdomain_depth",
    "host_entropy",
    "is_punycode",
    "has_suspicious_port",
    "is_suspicious_tld",
    "has_kw_login",
    "has_kw_verify",
    "has_kw_account",
    "has_kw_update",
    "has_kw_banking",
    "has_kw_secure",
    "has_kw_password",
    "has_kw_auth",
    "total_phish_token_count",
    "path_entropy",
    "has_file_extension",
    "has_fragment",
    "no_https",
    "has_page_signals",
    "password_input_count",
    "cross_origin_form_count",
    "external_link_ratio",
    "sys_a_score_norm",
    "sys_b_score_norm",
  ];

  var SPECIAL_CHARS = ["?", "=", "&", "%", "#", "+", "_", "~", "-"];

  var SUSPICIOUS_TLDS = {
    xyz: true, top: true, work: true, click: true, fit: true, buzz: true,
    gq: true, ml: true, cf: true, ga: true, tk: true, icu: true, cam: true,
    rest: true, surf: true, monster: true, bar: true, live: true, link: true,
  };

  var SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".zip", ".rar", ".7z", ".apk", ".php", ".asp", ".aspx",
    ".jsp", ".cgi", ".bin", ".bat", ".cmd", ".vbs", ".ps1", ".jar",
  ];

  var TOKEN_REGEXES = {
    login:    /(?:login|log-in|signin|sign-in)/i,
    verify:   /(?:verify|verification|validation)/i,
    account:  /(?:account|acct|myaccount)/i,
    update:   /(?:update|upgrade|renew)/i,
    banking:  /(?:bank|banking|paypal|chase|wellsfargo|citi)/i,
    secure:   /(?:secure|security|safelogin)/i,
    password: /(?:password|passwd|passcode)/i,
    auth:     /(?:auth|oauth|authenticate|authorization)/i,
  };

  function calculateEntropy(text) {
    if (!text || typeof text !== "string") return 0.0;
    var len = text.length;
    if (len === 0) return 0.0;
    var counts = {};
    for (var i = 0; i < len; i++) {
      var c = text.charAt(i);
      counts[c] = (counts[c] || 0) + 1;
    }
    var entropy = 0.0;
    for (var char in counts) {
      if (Object.prototype.hasOwnProperty.call(counts, char)) {
        var p = counts[char] / len;
        entropy -= p * (Math.log(p) / Math.LN2);
      }
    }
    return Math.round(entropy * 10000) / 10000;
  }

  function isIpHostname(hostname) {
    if (!hostname) return false;
    if (hostname.charAt(0) === "[" && hostname.charAt(hostname.length - 1) === "]") return true;
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  }

  function countDigits(str) {
    var count = 0;
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      if (code >= 48 && code <= 57) count++;
    }
    return count;
  }

  function extractFeatures(rawUrl, pageSignals, sysAResult, sysBResult) {
    var raw = (rawUrl || "").trim();
    if (!raw) {
      var zeroObj = {};
      FEATURE_NAMES.forEach(function (n) { zeroObj[n] = 0.0; });
      return zeroObj;
    }

    var parseTarget = raw;
    if (!/^https?:\/\//i.test(parseTarget)) {
      parseTarget = "http://" + parseTarget;
    }

    var parsed;
    try {
      parsed = new URL(parseTarget);
    } catch (e) {
      var fallbackObj = {};
      FEATURE_NAMES.forEach(function (n) { fallbackObj[n] = 0.0; });
      return fallbackObj;
    }

    var hostname = (parsed.hostname || "").toLowerCase();
    var path = parsed.pathname || "";
    // Parity with Python urlparse: if original URL had no trailing slash or path, path_length is 0
    if (path === "/" && !/\/$/.test(raw.split("?")[0].split("#")[0])) {
      path = "";
    }
    var query = parsed.search ? parsed.search.replace(/^\?/, "") : "";
    var fragment = parsed.hash ? parsed.hash.replace(/^#/, "") : "";
    var port = parsed.port;
    var scheme = (parsed.protocol || "").replace(/:$/, "").toLowerCase();

    var lowerUrl = raw.toLowerCase();
    var urlLen = raw.length;
    var hostLen = hostname.length;

    // 1. Lexical features
    var url_length = urlLen * 1.0;
    var host_length = hostLen * 1.0;
    var path_length = path.length * 1.0;
    var query_length = query.length * 1.0;

    var num_query_params = 0.0;
    if (query) {
      var qParts = query.split("&").filter(Boolean);
      num_query_params = qParts.length * 1.0;
    }

    var special_char_count = 0.0;
    for (var i = 0; i < raw.length; i++) {
      if (SPECIAL_CHARS.indexOf(raw.charAt(i)) !== -1) special_char_count += 1.0;
    }

    var has_at_symbol = raw.indexOf("@") !== -1 ? 1.0 : 0.0;
    var hyphen_count_total = (raw.match(/-/g) || []).length * 1.0;
    var hyphen_count_host = (hostname.match(/-/g) || []).length * 1.0;

    var percentMatches = raw.match(/%[0-9a-fA-F]{2}/g);
    var percent_encoding_count = percentMatches ? percentMatches.length * 1.0 : 0.0;

    var digit_ratio_url = urlLen > 0 ? Math.round((countDigits(raw) / urlLen) * 10000) / 10000 : 0.0;
    var digit_ratio_host = hostLen > 0 ? Math.round((countDigits(hostname) / hostLen) * 10000) / 10000 : 0.0;

    // 2. Hostname features
    var is_ip_host = isIpHostname(hostname) ? 1.0 : 0.0;
    var dots = (hostname.match(/\./g) || []).length;
    var dot_count_host = dots * 1.0;
    var subdomain_depth = is_ip_host ? 0.0 : Math.max(0, dots - 1) * 1.0;
    var host_entropy = calculateEntropy(hostname);
    var is_punycode = hostname.indexOf("xn--") !== -1 ? 1.0 : 0.0;

    var has_suspicious_port = 0.0;
    if (port && port !== "80" && port !== "443" && port !== "8080") {
      has_suspicious_port = 1.0;
    }

    var is_suspicious_tld = 0.0;
    if (hostname.indexOf(".") !== -1 && !is_ip_host) {
      var hParts = hostname.split(".");
      var tld = hParts[hParts.length - 1];
      if (SUSPICIOUS_TLDS[tld]) is_suspicious_tld = 1.0;
    }

    // 3. Token Lexical features
    var kw_hits = {};
    var total_phish_token_count = 0.0;
    for (var token in TOKEN_REGEXES) {
      if (TOKEN_REGEXES[token].test(lowerUrl)) {
        kw_hits[token] = 1.0;
        total_phish_token_count += 1.0;
      } else {
        kw_hits[token] = 0.0;
      }
    }

    // 4. Statistical & Structural features
    var path_entropy = calculateEntropy(path);

    var has_file_extension = 0.0;
    var lowerPath = path.toLowerCase();
    for (var eIdx = 0; eIdx < SUSPICIOUS_EXTENSIONS.length; eIdx++) {
      if (lowerPath.endsWith(SUSPICIOUS_EXTENSIONS[eIdx])) {
        has_file_extension = 1.0;
        break;
      }
    }

    var has_fragment = fragment ? 1.0 : 0.0;
    var no_https = scheme === "http" ? 1.0 : 0.0;

    // 5. Page Structural Signals
    var has_page_signals = 0.0;
    var password_input_count = 0.0;
    var cross_origin_form_count = 0.0;
    var external_link_ratio = 0.0;

    if (pageSignals && (pageSignals.available || pageSignals.hasSignals)) {
      has_page_signals = 1.0;
      password_input_count = (pageSignals.passwordInputs || 0) * 1.0;
      cross_origin_form_count = (pageSignals.crossOriginForms || 0) * 1.0;
      var tLinks = pageSignals.totalLinks || 0;
      var eLinks = pageSignals.externalLinks || 0;
      external_link_ratio = tLinks > 0 ? Math.round((eLinks / tLinks) * 10000) / 10000 : 0.0;
    }

    // 6. Heuristic Detector Evidence
    var sys_a_score_norm = 0.0;
    if (sysAResult && sysAResult.verdict) {
      sys_a_score_norm = sysAResult.verdict === "phishing" ? 1.0 : 0.0;
    } else {
      var aTrigger = is_ip_host || (url_length > 75) || (dot_count_host > 3) ||
                     (has_at_symbol === 1.0 || hyphen_count_host >= 2) ||
                     (total_phish_token_count > 0 && no_https === 1.0);
      sys_a_score_norm = aTrigger ? 1.0 : 0.0;
    }

    var sys_b_score_norm = 0.0;
    if (sysBResult && typeof sysBResult.score === "number") {
      sys_b_score_norm = Math.round(Math.min(1.0, Math.max(0.0, sysBResult.score / 120.0)) * 10000) / 10000;
    } else {
      var bScore = 0.0;
      if (is_ip_host) bScore += 35.0;
      if (has_at_symbol === 1.0 || hyphen_count_host >= 2) bScore += 30.0;
      if (dot_count_host > 3) bScore += 20.0;
      if (total_phish_token_count > 0) bScore += 15.0;
      if (url_length > 75) bScore += 10.0;
      if (no_https === 1.0) bScore += 10.0;
      sys_b_score_norm = Math.round(Math.min(1.0, Math.max(0.0, bScore / 120.0)) * 10000) / 10000;
    }

    return {
      url_length: url_length,
      host_length: host_length,
      path_length: path_length,
      query_length: query_length,
      num_query_params: num_query_params,
      special_char_count: special_char_count,
      has_at_symbol: has_at_symbol,
      hyphen_count_total: hyphen_count_total,
      hyphen_count_host: hyphen_count_host,
      percent_encoding_count: percent_encoding_count,
      digit_ratio_url: digit_ratio_url,
      digit_ratio_host: digit_ratio_host,
      is_ip_host: is_ip_host,
      dot_count_host: dot_count_host,
      subdomain_depth: subdomain_depth,
      host_entropy: host_entropy,
      is_punycode: is_punycode,
      has_suspicious_port: has_suspicious_port,
      is_suspicious_tld: is_suspicious_tld,
      has_kw_login: kw_hits.login,
      has_kw_verify: kw_hits.verify,
      has_kw_account: kw_hits.account,
      has_kw_update: kw_hits.update,
      has_kw_banking: kw_hits.banking,
      has_kw_secure: kw_hits.secure,
      has_kw_password: kw_hits.password,
      has_kw_auth: kw_hits.auth,
      total_phish_token_count: total_phish_token_count,
      path_entropy: path_entropy,
      has_file_extension: has_file_extension,
      has_fragment: has_fragment,
      no_https: no_https,
      has_page_signals: has_page_signals,
      password_input_count: password_input_count,
      cross_origin_form_count: cross_origin_form_count,
      external_link_ratio: external_link_ratio,
      sys_a_score_norm: sys_a_score_norm,
      sys_b_score_norm: sys_b_score_norm,
    };
  }

  function extractVector(rawUrl, pageSignals, sysAResult, sysBResult) {
    var dict = extractFeatures(rawUrl, pageSignals, sysAResult, sysBResult);
    return FEATURE_NAMES.map(function (n) {
      return dict[n];
    });
  }

  var api = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    FEATURE_NAMES: FEATURE_NAMES,
    extractFeatures: extractFeatures,
    extractVector: extractVector,
  };

  root.TriVexFeatureExtractor = api;
  if (typeof window !== "undefined") window.TriVexFeatureExtractor = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;

})(typeof self !== "undefined" ? self : this);
