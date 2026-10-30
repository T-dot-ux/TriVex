/*
 * popup.js - UI logic (Member 1).
 *
 * Talks to the detector only through analyzeUrl(url) from detector.js.
 * The popup renders what the detector returns; it never invents a verdict.
 * It never fetches or opens the analyzed URL, and it never stores anything.
 *
 * Fields read from the detector result (agree these names with Member 2):
 *   features, ruleBased{verdict,reasons}, weighted{score,maxScore,threshold,verdict,reasons},
 *   hybrid{verdict,reasons,disagreement}, hostname (optional),
 *   recommendedAction (optional string or array of strings)
 *   error (string) when the input URL is invalid
 */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  // ---- Display text -------------------------------------------------------
  var PILL_TEXT = { phishing: "Suspicious", not_flagged: "No indicators" };
  var PHRASE = { phishing: "suspicious", not_flagged: "no high-risk indicators" };

  var HEADLINES = {
    suspicious: {
      icon: "⚠︎",
      title: "Suspicious: high-risk indicators detected",
      sub: "Treat this URL with caution.",
    },
    disagree: {
      icon: "≠",
      title: "Systems disagree",
      sub: "",
    },
    none: {
      icon: "ℹ︎",
      title: "No high-risk indicators detected",
      sub: "This is not a guarantee that the site is safe.",
    },
  };

  var NEXT_STEPS = {
    suspicious: [
      "Do not enter passwords, card details or personal information on this site.",
      "If the link came from a message or email, do not click it. Open the official site by typing its address yourself.",
      "If you already entered details, change that password and contact the real site's support.",
    ],
    disagree: [
      "The detectors disagree, so treat this URL with caution.",
      "Review the triggered features above and check the address carefully before entering any details.",
    ],
    none: [
      "No high-risk indicators were found in the URL text, but that does not guarantee the site is safe.",
      "Check that the address matches the site you expect before signing in.",
    ],
  };

  // Used only if the detector does not supply its own feature labels.
  var DEFAULT_LABELS = {
    hasIp: "IP address used as hostname",
    suspiciousSymbols: "Suspicious symbols (@ or multiple hyphens)",
    deepSubdomains: "Excessive subdomain depth (more than 3 dots)",
    targetedKeyword: "Targeted keyword in URL",
    longUrl: "URL longer than 75 characters",
    noHttps: "HTTPS absent (plain HTTP)",
  };

  var URL_MAX = 90, URL_HEAD = 60, URL_TAIL = 24;
  var HOST_MAX = 48, HOST_HEAD = 30, HOST_TAIL = 14;

  // Only the newest analysis may update the screen.
  var runId = 0;

  // ---- Small helpers ------------------------------------------------------
  function shorten(text, max, head, tail) {
    return text.length <= max ? text : text.slice(0, head) + "…" + text.slice(text.length - tail);
  }

  function announce(text) {
    var el = $("announce");
    el.textContent = "";
    setTimeout(function () { el.textContent = text; }, 50);
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
    el.textContent = PILL_TEXT[verdict] || String(verdict);
  }

  function looksValid(r) {
    return !!(r && typeof r === "object" &&
      r.features && typeof r.features === "object" &&
      r.ruleBased && r.weighted && r.hybrid);
  }

  // ---- Views: initial, loading, result, invalid, unavailable ---------------
  function setView(view, message, focusInput) {
    var statusBox = $("statusBox");
    var busy = view === "loading";

    $("scanTab").disabled = busy;
    $("scanUrl").disabled = busy;
    $("results").setAttribute("aria-busy", busy ? "true" : "false");

    $("results").hidden = true;
    $("error").hidden = true;
    $("error").textContent = "";
    statusBox.hidden = true;
    statusBox.className = "state";

    function showBox(title, text, extraClass) {
      $("statusTitle").textContent = title;
      $("statusText").textContent = text;
      if (extraClass) statusBox.classList.add(extraClass);
      statusBox.hidden = false;
      announce(title + ". " + text);
    }

    if (view === "initial") {
      $("statusTitle").textContent = "No URL analyzed yet";
      $("statusText").textContent =
        "Choose \"Analyze current page\" or paste a URL above. TriVex checks only the text of the address and never opens it.";
      statusBox.hidden = false;
    } else if (view === "loading") {
      showBox("Analysing…", "Checking the six URL features.");
    } else if (view === "unavailable") {
      showBox("Analysis unavailable", message || "Something went wrong. Please try again.", "state-unavailable");
    } else if (view === "invalid") {
      $("error").textContent = message || "That URL could not be analyzed.";
      $("error").hidden = false;
      announce($("error").textContent);
      if (focusInput) $("urlInput").focus();
    } else if (view === "result") {
      $("results").hidden = false;
    }
  }

  // ---- Rendering ----------------------------------------------------------
  function renderUrl(r) {
    var full = String(r.url || "");
    var host = r.hostname;
    if (!host) {
      try { host = new URL(full).hostname; } catch (e) { host = ""; }
    }

    var hostEl = $("hostName");
    hostEl.textContent = shorten(host, HOST_MAX, HOST_HEAD, HOST_TAIL);
    hostEl.title = host;
    hostEl.hidden = !host;

    var short = shorten(full, URL_MAX, URL_HEAD, URL_TAIL);
    var urlEl = $("analyzedUrl");
    var toggle = $("toggleUrl");
    var expanded = false;

    urlEl.textContent = short;
    urlEl.title = full;

    if (short !== full) {
      toggle.hidden = false;
      toggle.textContent = "Show full URL";
      toggle.setAttribute("aria-expanded", "false");
      toggle.onclick = function () {
        expanded = !expanded;
        urlEl.textContent = expanded ? full : short;
        toggle.textContent = expanded ? "Show shorter URL" : "Show full URL";
        toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
      };
    } else {
      toggle.hidden = true;
      toggle.onclick = null;
    }
  }

  function renderHeadline(r, disagree) {
    var hybridPhish = r.hybrid.verdict === "phishing";
    var key = disagree ? "disagree" : (hybridPhish ? "suspicious" : "none");
    var h = HEADLINES[key];

    $("headline").className = "headline " + (hybridPhish && !disagree ? "suspicious" : key);
    $("hIcon").textContent = h.icon;
    $("hTitle").textContent = h.title;
    $("hSub").textContent = disagree
      ? "Final decision (Hybrid): " + (PHRASE[r.hybrid.verdict] || r.hybrid.verdict) + "."
      : h.sub;

    announce(h.title + ". " + ($("hSub").textContent || ""));
    return hybridPhish ? "suspicious" : (disagree ? "disagree" : "none");
  }

  function renderNextSteps(r, stepsKey) {
    var steps = NEXT_STEPS[stepsKey];
    // If the detector supplies its own recommended action, show that instead.
    if (typeof r.recommendedAction === "string" && r.recommendedAction) {
      steps = [r.recommendedAction];
    } else if (Array.isArray(r.recommendedAction) && r.recommendedAction.length) {
      steps = r.recommendedAction.map(String);
    }
    fillList($("nextSteps"), steps);
  }

  function render(r) {
    var labels = DEFAULT_LABELS;
    if (window.PhishGuard && window.PhishGuard.FEATURE_LABELS) labels = window.PhishGuard.FEATURE_LABELS;

    var disagree = typeof r.hybrid.disagreement === "boolean"
      ? r.hybrid.disagreement
      : r.ruleBased.verdict !== r.weighted.verdict;

    var stepsKey = renderHeadline(r, disagree);
    renderUrl(r);

    var banner = $("disagreement");
    if (disagree) {
      banner.hidden = false;
      banner.textContent =
        "Disagreement: Rule-based says " + (PHRASE[r.ruleBased.verdict] || r.ruleBased.verdict) +
        ", Weighted score says " + (PHRASE[r.weighted.verdict] || r.weighted.verdict) + ".";
    } else {
      banner.hidden = true;
    }

    // System A
    setPill($("verdictA"), r.ruleBased.verdict);
    fillList($("reasonsA"), r.ruleBased.reasons);

    // System B
    var w = r.weighted;
    var hasMax = typeof w.maxScore === "number" && w.maxScore > 0;
    var hasThreshold = typeof w.threshold === "number";
    setPill($("verdictB"), w.verdict);
    fillList($("reasonsB"), w.reasons);
    $("scoreText").textContent = "Score " + w.score + (hasMax ? " / " + w.maxScore : "");
    $("scoreNote").textContent = hasThreshold ? "(flagged at " + w.threshold + " or more)" : "";
    var fill = $("meterFill");
    fill.style.width = hasMax ? Math.min(100, (w.score / w.maxScore) * 100) + "%" : "0";
    fill.classList.toggle("over", w.verdict === "phishing");
    var mark = $("meterMark");
    mark.hidden = !(hasMax && hasThreshold);
    if (hasMax && hasThreshold) mark.style.left = Math.min(100, (w.threshold / w.maxScore) * 100) + "%";

    // System C
    setPill($("verdictC"), r.hybrid.verdict);
    fillList($("reasonsC"), r.hybrid.reasons);

    // Six features
    var list = $("featureList");
    list.textContent = "";
    var keys = Object.keys(labels);
    Object.keys(r.features).forEach(function (k) { if (keys.indexOf(k) === -1) keys.push(k); });
    keys.forEach(function (key) {
      var li = document.createElement("li");
      var name = document.createElement("span");
      name.textContent = labels[key] || key;
      var state = document.createElement("span");
      var on = !!r.features[key];
      state.className = on ? "yes" : "no";
      state.textContent = on ? "Yes" : "No";
      li.appendChild(name);
      li.appendChild(state);
      list.appendChild(li);
    });

    renderNextSteps(r, stepsKey);

    $("explanation").textContent =
      "These checks look only at the text of the URL. They can miss clean-looking phishing links and can warn on legitimate sites.";
  }

  // ---- Running an analysis -------------------------------------------------
  function analyze(url, fromInput) {
    var id = ++runId;
    setView("loading");

    // Promise wrapper so the popup also works if the detector becomes async.
    Promise.resolve()
      .then(function () {
        if (typeof window.analyzeUrl !== "function") {
          var err = new Error("detector-missing");
          err.code = "missing";
          throw err;
        }
        return window.analyzeUrl(url);
      })
      .then(function (result) {
        if (id !== runId) return; // a newer analysis replaced this one
        if (result && typeof result === "object" && result.error) {
          setView("invalid", String(result.error), fromInput);
          return;
        }
        if (!looksValid(result)) {
          setView("unavailable", "The detector returned data in an unexpected format.");
          return;
        }
        render(result);
        setView("result");
      })
      .catch(function (e) {
        if (id !== runId) return;
        if (e && e.code === "missing") {
          setView("unavailable", "The detection module could not be loaded. Reload the extension and try again.");
        } else {
          setView("unavailable", "Something went wrong while analysing this URL.");
        }
      });
  }

  function scanCurrentTab() {
    if (typeof chrome === "undefined" || !chrome.tabs || !chrome.tabs.query) {
      setView("unavailable", "Tab access is only available when TriVex runs as a browser extension.");
      return;
    }
    var id = ++runId;
    setView("loading");
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (id !== runId) return;
        var failed = chrome.runtime && chrome.runtime.lastError;
        var tab = tabs && tabs[0];
        if (failed || !tab || !tab.url) {
          setView("unavailable", "Could not read the address of this tab.");
          return;
        }
        $("urlInput").value = tab.url;
        analyze(tab.url, false);
      });
    } catch (e) {
      setView("unavailable", "Could not read the address of this tab.");
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    setView("initial");
    $("scanTab").addEventListener("click", scanCurrentTab);
    $("scanUrl").addEventListener("click", function () {
      analyze($("urlInput").value, true);
    });
    $("urlInput").addEventListener("keydown", function (e) {
      if (e.key === "Enter") analyze($("urlInput").value, true);
    });
  });
})();
