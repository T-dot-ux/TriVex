/*
 * family_shield.js — TriVex Family Shield content-category classifier.
 *
 * Provides domain and keyword-based content classification separate from
 * phishing detection.  Returns a category verdict for a given URL.
 *
 * Categories:
 *   "adult"     — adult or explicit content
 *   "gambling"  — gambling or betting sites
 *   "safe"      — no restricted content detected
 *
 * Confidence levels: "high" | "medium" | "low"
 *
 * This module never fetches the URL or reads page content.
 * Classification is based solely on the URL string (hostname + path).
 */

(function (root) {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* Category definitions                                                 */
  /* ------------------------------------------------------------------ */

  /**
   * Known adult-content domains (hostname, without www prefix).
   * These are well-known domains used as examples; not an exhaustive list.
   */
  var ADULT_DOMAINS = [
    "pornhub.com", "xvideos.com", "redtube.com", "xnxx.com",
    "brazzers.com", "playboy.com", "hustler.com", "penthouse.com",
    "xxx.com", "sex.com", "youporn.com", "tube8.com",
    "spankbang.com", "xhamster.com", "beeg.com", "chaturbate.com",
    "stripchat.com", "livejasmin.com", "bongacams.com", "cam4.com",
    "eporner.com", "hqporner.com", "tnaflix.com", "porn.com",
    "motherless.com", "heavy-r.com", "fapello.com", "erome.com",
    "porntrex.com", "txxx.com", "thumbzilla.com", "fuq.com",
    "camwhores.tv", "spankwire.com", "gotporn.com", "daftsex.com"
  ];

  /**
   * Adult-content keywords found in URL paths/subdomains.
   */
  var ADULT_URL_KEYWORDS = [
    "porn",
    "pornography",
    "adult-content",
    "explicit-content",
    "xxx",
    "erotic",
    "nudity",
    "onlyfans",
    "hentai",
    "nsfw",
    "stripchat",
    "chaturbate",
    "camgirl",
    "escort"
  ];

  /**
   * Known gambling / betting domains.
   */
  var GAMBLING_DOMAINS = [
    "bet365.com", "draftkings.com", "fanduel.com", "pokerstars.com",
    "williamhill.com", "betway.com", "888casino.com", "bovada.lv",
    "betfair.com", "ladbrokes.com", "coral.co.uk", "unibet.com",
    "stake.com", "roobet.com", "rollbit.com", "duelbits.com",
    "bc.game", "1xbet.com", "parimatch.com", "bwin.com",
    "betonline.ag", "ggpoker.com", "partypoker.com"
  ];

  /**
   * Gambling-related keywords in URLs.
   */
  var GAMBLING_URL_KEYWORDS = [
    "casino",
    "betting",
    "gambling",
    "poker",
    "sports-bet",
    "online-slots",
    "jackpot-casino",
    "roulette",
    "blackjack",
    "sportsbook"
  ];

  /* ------------------------------------------------------------------ */
  /* Helpers                                                              */
  /* ------------------------------------------------------------------ */

  /**
   * Normalize a hostname: strip www. prefix and lower-case.
   * @param {string} hostname
   * @returns {string}
   */
  function normalizeHostname(hostname) {
    return (hostname || "").toLowerCase().replace(/^www\./, "");
  }

  /**
   * Check whether a hostname matches a domain in the list (exact or subdomain).
   * @param {string}   hostname    Normalized hostname.
   * @param {string[]} domainList
   * @returns {boolean}
   */
  function matchesDomain(hostname, domainList) {
    return domainList.some(function (d) {
      return hostname === d || hostname.endsWith("." + d);
    });
  }

  /**
   * Check whether a lower-cased URL string contains any keyword from a list.
   * Uses non-alphanumeric word boundaries to prevent substring false-positives.
   * @param {string}   lowerUrl
   * @param {string[]} keywords
   * @returns {string|null}  Matched keyword, or null.
   */
  function matchesKeyword(lowerUrl, keywords) {
    for (var i = 0; i < keywords.length; i++) {
      var kw = keywords[i];
      var pattern = "(?:^|[^a-z0-9])" + kw.replace(/-/g, "[-_ ]") + "(?:[^a-z0-9]|$)";
      var re = new RegExp(pattern, "i");
      if (re.test(lowerUrl)) return kw;
    }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* Main classifier                                                      */
  /* ------------------------------------------------------------------ */

  /**
   * Classify a URL by content category.
   *
   * @param {string} url  Raw URL string.
   * @returns {{
   *   category:   "adult" | "gambling" | "safe",
   *   confidence: "high"  | "medium"   | "low",
   *   evidence:   string[]
   * }}
   */
  function classifyUrl(url) {
    if (!url || typeof url !== "string") {
      return { category: "safe", confidence: "low", evidence: ["No URL provided"] };
    }

    var raw = url.trim();
    if (!/^https?:\/\//i.test(raw)) {
      raw = "http://" + raw;
    }

    var parsed;
    try {
      parsed = new URL(raw);
    } catch (e) {
      return { category: "safe", confidence: "low", evidence: ["URL could not be parsed"] };
    }

    var hostname = normalizeHostname(parsed.hostname);
    var lowerUrl = url.toLowerCase();
    var evidence = [];

    /* --- Adult content --- */
    if (matchesDomain(hostname, ADULT_DOMAINS)) {
      evidence.push("Domain is a known adult-content site: " + hostname);
      return { category: "adult", confidence: "high", evidence: evidence };
    }

    var adultKw = matchesKeyword(lowerUrl, ADULT_URL_KEYWORDS);
    if (adultKw) {
      evidence.push("Adult-content keyword detected in URL: " + adultKw);
      return { category: "adult", confidence: "medium", evidence: evidence };
    }

    /* --- Gambling --- */
    if (matchesDomain(hostname, GAMBLING_DOMAINS)) {
      evidence.push("Domain is a known gambling/betting site: " + hostname);
      return { category: "gambling", confidence: "high", evidence: evidence };
    }

    var gamblingKw = matchesKeyword(lowerUrl, GAMBLING_URL_KEYWORDS);
    if (gamblingKw) {
      evidence.push("Gambling-related keyword detected in URL: " + gamblingKw);
      return { category: "gambling", confidence: "medium", evidence: evidence };
    }

    /* --- Safe --- */
    return { category: "safe", confidence: "high", evidence: [] };
  }

  /* ------------------------------------------------------------------ */
  /* Export                                                               */
  /* ------------------------------------------------------------------ */

  var api = { classifyUrl: classifyUrl };

  root.FamilyShield = api;
  root.classifyUrl = classifyUrl;
  if (typeof window !== "undefined") {
    window.FamilyShield = api;
    window.classifyUrl = classifyUrl;
  }
  if (typeof module !== "undefined" && module.exports) module.exports = api;

})(typeof self !== "undefined" ? self : this);
