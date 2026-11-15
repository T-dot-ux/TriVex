/*
 * family_shield.js — TriVex Family Shield classifier.
 *
 * Reads domain and keyword lists from blocklist.js (must be loaded first).
 * Classification is based solely on the URL string — no network requests.
 */

(function (root) {
  "use strict";

  /* Pull lists from the master dictionary loaded by blocklist.js */
  function getList(key, fallback) {
    var bl = root.TriVexBlocklist;
    return (bl && Array.isArray(bl[key])) ? bl[key] : fallback;
  }

  function normalizeHostname(hostname) {
    return (hostname || "").toLowerCase().replace(/^www\./, "");
  }

  function matchesDomain(hostname, domainList) {
    return domainList.some(function (d) {
      return hostname === d || hostname.endsWith("." + d);
    });
  }

  function matchesKeyword(lowerUrl, keywords) {
    for (var i = 0; i < keywords.length; i++) {
      var kw = keywords[i];
      /* Use word-boundary-like check: keyword must not be surrounded by [a-z0-9] */
      var pattern = "(?:^|[^a-z0-9])" + kw.replace(/-/g, "[-_ ]") + "(?:[^a-z0-9]|$)";
      if (new RegExp(pattern, "i").test(lowerUrl)) return kw;
    }
    return null;
  }

  function classifyUrl(url) {
    if (!url || typeof url !== "string") {
      return { category: "safe", confidence: "low", evidence: ["No URL provided"] };
    }

    var raw = url.trim();
    if (!/^https?:\/\//i.test(raw)) raw = "http://" + raw;

    var parsed;
    try { parsed = new URL(raw); }
    catch (e) { return { category: "safe", confidence: "low", evidence: ["Unparseable URL"] }; }

    var hostname  = normalizeHostname(parsed.hostname);
    var lowerUrl  = raw.toLowerCase();
    var evidence  = [];

    var ADULT_DOMAINS    = getList("ADULT_DOMAINS",    []);
    var ADULT_KEYWORDS   = getList("ADULT_KEYWORDS",   []);
    var GAMBLING_DOMAINS = getList("GAMBLING_DOMAINS", []);
    var GAMBLING_KEYWORDS= getList("GAMBLING_KEYWORDS",[]);

    /* Adult — domain match (high confidence) */
    if (matchesDomain(hostname, ADULT_DOMAINS)) {
      evidence.push("Known adult domain: " + hostname);
      return { category: "adult", confidence: "high", evidence: evidence };
    }

    /* Adult — keyword match (medium confidence) */
    var adultKw = matchesKeyword(lowerUrl, ADULT_KEYWORDS);
    if (adultKw) {
      evidence.push("Adult keyword in URL: " + adultKw);
      return { category: "adult", confidence: "medium", evidence: evidence };
    }

    /* Gambling — domain match */
    if (matchesDomain(hostname, GAMBLING_DOMAINS)) {
      evidence.push("Known gambling domain: " + hostname);
      return { category: "gambling", confidence: "high", evidence: evidence };
    }

    /* Gambling — keyword match */
    var gamblingKw = matchesKeyword(lowerUrl, GAMBLING_KEYWORDS);
    if (gamblingKw) {
      evidence.push("Gambling keyword in URL: " + gamblingKw);
      return { category: "gambling", confidence: "medium", evidence: evidence };
    }

    return { category: "safe", confidence: "high", evidence: [] };
  }

  var api = { classifyUrl: classifyUrl };
  root.FamilyShield = api;
  root.classifyUrl  = classifyUrl;
  if (typeof window !== "undefined") { window.FamilyShield = api; window.classifyUrl = classifyUrl; }
  if (typeof module !== "undefined" && module.exports) module.exports = api;

})(typeof self !== "undefined" ? self : this);
