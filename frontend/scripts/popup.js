/*
 * popup.js — TriVex UI logic (Member 1).
 *
 * Talks to the detector only through analyzeUrl(url) from detector.js.
 * It never fetches or opens the analyzed URL.
 *
 * Updates (Phase 9):
 *   - Uses new feature keys (hostname_is_ip, etc.) with backward-compat fallback
 *     to old keys (hasIp, longUrl, etc.) so old and new detector.js both work.
 *   - Family Shield toggle: loads/saves setting via chrome.storage.local (or
 *     localStorage as fallback), updates shield badge in header.
 */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  var VERDICT_TEXT = { phishing: "Flagged: suspicious", not_flagged: "Not flagged" };

  /* ------------------------------------------------------------------ */
  /* Feature key mapping: new canonical names → old stand-in names       */
  /* popup.js supports both so switching detector.js versions is smooth   */
  /* ------------------------------------------------------------------ */

  /**
   * FEATURE_LABELS to show in the UI when PhishGuard.FEATURE_LABELS is
   * unavailable.  Keys are the NEW canonical names used by the rewritten
   * detector.js; old names are kept as aliases below.
   */
  var FALLBACK_LABELS = {
    hostname_is_ip:     "IP address used as hostname",
    suspicious_symbols: "Suspicious symbols (@ or multiple hyphens)",
    hostname_dot_count: "Excessive subdomain depth (more than 3 dots)",
    keyword_match:      "Targeted keyword in URL",
    url_length:         "URL longer than 75 characters",
    uses_https:         "HTTPS absent (plain HTTP)",
    // Backward-compat old keys
    hasIp:           "IP address used as hostname",
    longUrl:         "URL longer than 75 characters",
    deepSubdomains:  "Excessive subdomain depth (more than 3 dots)",
    targetedKeyword: "Targeted keyword in URL",
    noHttps:         "HTTPS absent (plain HTTP)",
  };

  /* ------------------------------------------------------------------ */
  /* Storage helpers (chrome.storage.local with localStorage fallback)   */
  /* ------------------------------------------------------------------ */

  function storageGet(key, cb) {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get([key], function (res) { cb(res[key]); });
    } else {
      try { cb(localStorage.getItem(key)); } catch (e) { cb(null); }
    }
  }

  function storageSet(key, value) {
    var obj = {};
    obj[key] = value;
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set(obj);
    } else {
      try { localStorage.setItem(key, value); } catch (e) { /* ignore */ }
    }
  }

  /* ------------------------------------------------------------------ */
  /* Family Shield toggle                                                  */
  /* ------------------------------------------------------------------ */

  function applyShieldState(enabled) {
    var badge  = $("shieldBadge");
    var toggle = $("familyShieldToggle");
    if (badge)  badge.classList.toggle("active", !!enabled);
    if (toggle) toggle.checked = !!enabled;
  }

  function initFamilyShield() {
    storageGet("familyShieldEnabled", function (val) {
      var enabled = val === true || val === "true" || val === 1;
      applyShieldState(enabled);
    });

    var toggle = $("familyShieldToggle");
    if (toggle) {
      toggle.addEventListener("change", function () {
        var enabled = toggle.checked;
        storageSet("familyShieldEnabled", enabled);
        applyShieldState(enabled);
      });
    }
  }

  /* ------------------------------------------------------------------ */
  /* UI helpers                                                           */
  /* ------------------------------------------------------------------ */

  function setError(msg) {
    var el = $("error");
    el.textContent = msg || "";
    el.hidden = !msg;
  }

  function fillList(ul, items) {
    ul.textContent = "";
    (items || []).forEach(function (text) {
      var li = document.createElement("li");
      li.textContent = text; // textContent: never inject URL text as HTML
      ul.appendChild(li);
    });
  }

  function setPill(el, verdict) {
    el.className = "pill " + verdict;
    el.textContent = VERDICT_TEXT[verdict] || verdict;
  }

  function buildExplanation(r) {
    // Support both old (ruleBased/weighted/hybrid) and new (systemA/B/C) names
    var a = r.systemA || r.ruleBased;
    var b = r.systemB || r.weighted;
    var c = r.systemC || r.hybrid;
    var flagged = [a, b, c].filter(function (x) {
      return x && x.verdict === "phishing";
    }).length;
    if (flagged === 0) {
      return "None of the three detectors flagged this URL. That only means these six URL features did not look suspicious. It is not a guarantee that the site is safe.";
    }
    if (flagged === 3) {
      return "All three detectors flagged this URL. Check the triggered features above and avoid entering passwords or personal details unless you are sure of the site.";
    }
    return "The detectors disagree on this URL (" + flagged + " of 3 flagged it). Treat it with caution and review the triggered features above.";
  }

  function render(r) {
    // Support both new and old detector result shapes
    var sysA = r.systemA || r.ruleBased;
    var sysB = r.systemB || r.weighted;
    var sysC = r.systemC || r.hybrid;

    // Feature labels: prefer PhishGuard.FEATURE_LABELS if available
    var labels = (window.PhishGuard && window.PhishGuard.FEATURE_LABELS) || FALLBACK_LABELS;

    $("analyzedUrl").textContent = r.url;
    $("results").hidden = false;

    setPill($("verdictA"), sysA.verdict);
    fillList($("reasonsA"), sysA.reasons);

    setPill($("verdictB"), sysB.verdict);
    fillList($("reasonsB"), sysB.reasons);
    $("scoreText").textContent = "Score " + sysB.score + " / " + sysB.maxScore;
    var fill = $("meterFill");
    fill.style.width = Math.min(100, (sysB.score / sysB.maxScore) * 100) + "%";
    fill.classList.toggle("over", sysB.score >= sysB.threshold);

    setPill($("verdictC"), sysC.verdict);
    fillList($("reasonsC"), sysC.reasons);

    var banner = $("disagreement");
    if (sysA.verdict !== sysB.verdict) {
      banner.hidden = false;
      banner.textContent =
        "Disagreement: Rule-based says " + (VERDICT_TEXT[sysA.verdict] || sysA.verdict) +
        ", Weighted score says " + (VERDICT_TEXT[sysB.verdict] || sysB.verdict) + ".";
    } else {
      banner.hidden = true;
    }

    // Feature list — iterate over the labels object; skip keys not in features
    var featureList = $("featureList");
    featureList.textContent = "";
    Object.keys(labels).forEach(function (key) {
      // Skip old alias keys if the new keys are present in features
      var hasNewKeys = ("hostname_is_ip" in (r.features || {}));
      var isOldAlias = ["hasIp","longUrl","deepSubdomains","targetedKeyword","noHttps","suspiciousSymbols"].indexOf(key) !== -1;
      if (hasNewKeys && isOldAlias) return;

      if (!(key in (r.features || {}))) return;

      var li    = document.createElement("li");
      var name  = document.createElement("span");
      name.textContent = labels[key] || key;
      var state = document.createElement("span");
      var val   = r.features[key];
      state.className = val ? "yes" : "no";
      state.textContent = val ? "Yes" : "No";
      li.appendChild(name);
      li.appendChild(state);
      featureList.appendChild(li);
    });

    $("explanation").textContent = buildExplanation(r);
  }

  /* ------------------------------------------------------------------ */
  /* Analysis entry point                                                 */
  /* ------------------------------------------------------------------ */

  function analyze(url) {
    setError("");
    var result;
    try {
      result = window.analyzeUrl(url);
    } catch (e) {
      $("results").hidden = true;
      setError("Something went wrong while analyzing this URL.");
      return;
    }
    if (result.error) {
      $("results").hidden = true;
      setError(result.error);
      return;
    }
    render(result);
  }

  function scanCurrentTab() {
    setError("");
    if (typeof chrome === "undefined" || !chrome.tabs || !chrome.tabs.query) {
      setError("Tab access is only available when running as an extension.");
      return;
    }
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var tab = tabs && tabs[0];
      if (!tab || !tab.url) {
        $("results").hidden = true;
        setError("Could not read the address of this tab.");
        return;
      }
      $("urlInput").value = tab.url;
      analyze(tab.url);
    });
  }

  /* ------------------------------------------------------------------ */
  /* Init                                                                 */
  /* ------------------------------------------------------------------ */

  document.addEventListener("DOMContentLoaded", function () {
    initFamilyShield();

    $("scanTab").addEventListener("click", scanCurrentTab);
    $("scanUrl").addEventListener("click", function () {
      analyze($("urlInput").value);
    });
    $("urlInput").addEventListener("keydown", function (e) {
      if (e.key === "Enter") analyze($("urlInput").value);
    });
  });
})();
