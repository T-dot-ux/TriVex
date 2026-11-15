/*
 * popup.js — TriVex UI Logic & Controller.
 *
 * Coordinates between:
 *   - Local detection engine (scripts/detector.js)
 *   - Background service worker (scripts/background.js)
 *   - Family Shield policy (scripts/family_shield.js)
 *   - Continuous page context signals (scripts/content.js)
 *
 * Privacy & Safety Rules:
 *   - Never stores browsing history.
 *   - Never injects untrusted URL strings as HTML (uses textContent).
 *   - Never executes or fetches the analyzed URL.
 */

(function () {
  "use strict";

  var $ = function (id) {
    return document.getElementById(id);
  };

  // ---- Display text -------------------------------------------------------
  var PILL_TEXT = {
    phishing: "High Risk",
    suspicious: "Caution",
    not_flagged: "No Indicators",
  };

  var PHRASE = {
    phishing: "high-risk phishing",
    suspicious: "caution (moderate indicators)",
    not_flagged: "no high-risk indicators",
  };

  var HEADLINES = {
    phishing: {
      icon: "⚠︎",
      title: "Suspicious: high-risk indicators detected",
      sub: "Avoid entering credentials or sensitive data on this website.",
    },
    suspicious: {
      icon: "!",
      title: "Caution: moderate indicators detected",
      sub: "Some suspicious patterns detected, but below critical phishing threshold.",
    },
    disagree: {
      icon: "≠",
      title: "Systems disagree on this address",
      sub: "",
    },
    none: {
      icon: "ℹ︎",
      title: "No high-risk indicators detected",
      sub: "URL structure appears standard. This is not a guarantee that the site is safe.",
    },
    family_shield: {
      icon: "🛡️",
      title: "Blocked by Family Shield: Restricted content detected",
      sub: "This website matches the Family Shield protection filter. Live navigation is blocked.",
    },
  };

  var NEXT_STEPS = {
    phishing: [
      "Do not enter passwords, payment cards or personal information on this site.",
      "If this link came from an unsolicited email or message, close it immediately.",
      "If you already entered credentials, change them immediately on the authentic service.",
    ],
    family_shield: [
      "Access to this website is blocked under active Family Shield protection.",
      "Visiting this address in the browser redirects to the Family Shield safety page.",
      "To allow this category, turn off Family Shield in settings below.",
    ],
    suspicious: [
      "Verify the site address carefully before signing in or submitting personal details.",
      "Check whether this is the official domain of the service you intended to visit.",
      "Look for unusual subdomains, multiple hyphens, or unexpected HTTP connections.",
    ],
    disagree: [
      "The rule-based and weighted scoring detectors disagree on this URL.",
      "Review the specific triggered indicators below and verify the site identity independently.",
    ],
    none: [
      "No high-risk indicators were detected in the URL text.",
      "Remember that URL-only checks cannot detect compromised legitimate websites.",
      "Always ensure the address matches the expected company before signing in.",
    ],
  };

  var FEATURE_LABELS = {
    hostname_is_ip: "IP address used as hostname",
    suspicious_symbols: "Suspicious symbols (@ or multiple hyphens)",
    hostname_dot_count: "Excessive subdomain depth (>3 dots in host)",
    keyword_match: "Targeted credential/banking keyword",
    url_length: "URL longer than 75 characters",
    uses_https: "HTTPS absent (plain HTTP connection)",
    // Legacy stand-in aliases
    hasIp: "IP address used as hostname",
    longUrl: "URL longer than 75 characters",
    deepSubdomains: "Excessive subdomain depth (>3 dots in host)",
    targetedKeyword: "Targeted credential/banking keyword",
    noHttps: "HTTPS absent (plain HTTP connection)",
    suspiciousSymbols: "Suspicious symbols (@ or multiple hyphens)",
  };

  var URL_MAX = 80,
    URL_HEAD = 50,
    URL_TAIL = 26;
  var HOST_MAX = 42,
    HOST_HEAD = 26,
    HOST_TAIL = 12;

  var runId = 0;

  // ---- Helpers ------------------------------------------------------------
  function shorten(text, max, head, tail) {
    if (!text || text.length <= max) return text || "";
    return text.slice(0, head) + "…" + text.slice(text.length - tail);
  }

  function announce(text) {
    var el = $("announce");
    if (!el) return;
    el.textContent = "";
    setTimeout(function () {
      el.textContent = text;
    }, 50);
  }

  function fillList(ul, items) {
    if (!ul) return;
    ul.textContent = "";
    (items || []).forEach(function (text) {
      var li = document.createElement("li");
      li.textContent = text; // textContent: never inject as HTML
      ul.appendChild(li);
    });
  }

  function setPill(el, verdict) {
    if (!el) return;
    var normVerdict = verdict || "not_flagged";
    el.className = "pill " + normVerdict;
    el.textContent = PILL_TEXT[normVerdict] || String(normVerdict);
  }

  // ---- Storage Helpers ----------------------------------------------------
  function storageGet(key, cb) {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get([key], function (res) {
        cb(res[key]);
      });
    } else {
      try {
        cb(localStorage.getItem(key));
      } catch (e) {
        cb(null);
      }
    }
  }

  function storageSet(key, val, cb) {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      var obj = {};
      obj[key] = val;
      chrome.storage.local.set(obj, cb);
    } else {
      try {
        localStorage.setItem(key, String(val));
      } catch (e) { }
      if (cb) cb();
    }
  }

  // ---- Family Shield Controller -------------------------------------------
  var isFamilyShieldEnabled = true;

  function updateShieldUI(enabled) {
    isFamilyShieldEnabled = !!enabled;
    var badge = $("shieldBadge");
    var toggle = $("familyShieldToggle");
    if (badge) badge.classList.toggle("active", !!enabled);
    if (toggle) toggle.checked = !!enabled;
  }

  function initFamilyShield() {
    storageGet("familyShieldEnabled", function (val) {
      var isEnabled = val === undefined || val === null ? true : (val === true || val === "true" || val === 1);
      updateShieldUI(isEnabled);
    });

    var toggle = $("familyShieldToggle");
    if (toggle) {
      toggle.addEventListener("change", function () {
        var isEnabled = toggle.checked;
        storageSet("familyShieldEnabled", isEnabled, function () {
          updateShieldUI(isEnabled);
          announce(
            isEnabled
              ? "Family Shield protection enabled."
              : "Family Shield protection disabled."
          );
        });
      });
    }
  }

  // ---- View Controller ----------------------------------------------------
  function setView(view, message, focusInput) {
    var statusBox = $("statusBox");
    var busy = view === "loading";

    if ($("scanTab")) $("scanTab").disabled = busy;
    if ($("scanUrl")) $("scanUrl").disabled = busy;

    var resSec = $("results");
    if (resSec) {
      resSec.setAttribute("aria-busy", busy ? "true" : "false");
      resSec.hidden = view !== "result";
    }

    var errEl = $("error");
    if (errEl) {
      errEl.hidden = view !== "invalid";
      errEl.textContent = view === "invalid" ? message || "" : "";
    }

    if (statusBox) {
      statusBox.hidden = true;
      statusBox.className = "state";

      if (view === "initial") {
        $("statusTitle").textContent = "No URL analyzed yet";
        $("statusText").textContent =
          "Select \"Analyze current page\" or enter a web address above. TriVex analyzes URL structure locally.";
        statusBox.hidden = false;
      } else if (view === "loading") {
        $("statusTitle").textContent = "Analysing address…";
        $("statusText").textContent =
          "Checking URL features, weighted score, and hybrid decision.";
        statusBox.hidden = false;
        announce("Analysing address. Checking URL features.");
      } else if (view === "unavailable") {
        $("statusTitle").textContent = "Analysis unavailable";
        $("statusText").textContent =
          message || "An error occurred while analyzing the URL.";
        statusBox.classList.add("state-unavailable");
        statusBox.hidden = false;
        announce("Analysis unavailable. " + ($("statusText").textContent || ""));
      }
    }

    if (view === "invalid" && focusInput && $("urlInput")) {
      $("urlInput").focus();
    }
  }

  // ---- Rendering Results --------------------------------------------------
  function renderUrl(r) {
    var full = String(r.url || "");
    var host = r.hostname;
    if (!host) {
      try {
        host = new URL(full).hostname;
      } catch (e) {
        host = "";
      }
    }

    var hostEl = $("hostName");
    if (hostEl) {
      hostEl.textContent = shorten(host, HOST_MAX, HOST_HEAD, HOST_TAIL);
      hostEl.title = host;
      hostEl.hidden = !host;
    }

    var short = shorten(full, URL_MAX, URL_HEAD, URL_TAIL);
    var urlEl = $("analyzedUrl");
    var toggle = $("toggleUrl");
    var expanded = false;

    if (urlEl) {
      urlEl.textContent = short;
      urlEl.title = full;
    }

    if (toggle) {
      if (short !== full) {
        toggle.hidden = false;
        toggle.textContent = "Show full URL";
        toggle.setAttribute("aria-expanded", "false");
        toggle.onclick = function () {
          expanded = !expanded;
          if (urlEl) urlEl.textContent = expanded ? full : short;
          toggle.textContent = expanded ? "Show shorter URL" : "Show full URL";
          toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
        };
      } else {
        toggle.hidden = true;
        toggle.onclick = null;
      }
    }
  }

  function renderHeadline(r, shieldRes) {
    var sysC = r.systemC || r.hybrid;
    var sysA = r.systemA || r.ruleBased;
    var sysB = r.systemB || r.weighted;

    var disagree =
      sysC && typeof sysC.disagreement === "boolean"
        ? sysC.disagreement
        : sysA && sysB && sysA.verdict !== sysB.verdict;

    var verdict = (sysC && sysC.verdict) || r.finalVerdict || "not_flagged";
    var fsBlocked = shieldRes && (shieldRes.category === "adult" || shieldRes.category === "gambling") && (shieldRes.confidence === "high" || shieldRes.confidence === "medium");

    var hKey = "none";
    if (verdict === "phishing") {
      hKey = "phishing";
    } else if (fsBlocked) {
      hKey = "family_shield";
    } else if (verdict === "suspicious") {
      hKey = "suspicious";
    } else if (disagree) {
      hKey = "disagree";
    }

    var h = HEADLINES[hKey] || HEADLINES.none;
    var headEl = $("headline");
    if (headEl) {
      headEl.className = "headline " + hKey;
      $("hIcon").textContent = h.icon;
      $("hTitle").textContent = (fsBlocked && hKey === "family_shield")
        ? "Blocked by Family Shield: " + (shieldRes.category === "adult" ? "Adult content" : "Gambling content") + " detected"
        : h.title;
      $("hSub").textContent = disagree
        ? "System A says " +
        (PHRASE[sysA.verdict] || sysA.verdict) +
        ", System B says " +
        (PHRASE[sysB.verdict] || sysB.verdict) +
        "."
        : h.sub;
    }

    announce(($("hTitle") ? $("hTitle").textContent : h.title) + ". " + ($("hSub").textContent || ""));
    return hKey;
  }

  function renderPageSignals(tabUrl) {
    var section = $("pageSignalsSection");
    var list = $("signalList");
    if (!section || !list) return;

    storageGet("pageSignals", function (history) {
      var signals = null;
      if (Array.isArray(history) && history.length > 0) {
        if (tabUrl) {
          var matched = history.find(function (item) {
            return item.url === tabUrl;
          });
          signals = matched ? matched.signals : history[0].signals;
        } else {
          signals = history[0].signals;
        }
      }

      if (!signals) {
        section.hidden = true;
        return;
      }

      section.hidden = false;
      list.textContent = "";

      var items = [
        {
          label: "Page Title",
          value: signals.title || "(No title recorded)",
          warn: false,
        },
        {
          label: "Password Fields",
          value:
            signals.passwordFieldCount > 0
              ? signals.passwordFieldCount + " detected (values never read)"
              : "None detected",
          warn: signals.passwordFieldCount > 0,
        },
        {
          label: "Form Actions",
          value:
            signals.formActions && signals.formActions.length > 0
              ? signals.formActions.length + " destination(s)"
              : "No forms with action URLs",
          warn: false,
        },
        {
          label: "External Links",
          value: signals.externalLinkCount || 0,
          warn: false,
        },
      ];

      items.forEach(function (item) {
        var li = document.createElement("li");
        var nameSpan = document.createElement("span");
        nameSpan.textContent = item.label;
        var valSpan = document.createElement("span");
        valSpan.className = "signal-val" + (item.warn ? " warn" : "");
        valSpan.textContent = String(item.value);
        li.appendChild(nameSpan);
        li.appendChild(valSpan);
        list.appendChild(li);
      });
    });
  }

  function render(r, shieldRes) {
    var sysA = r.systemA || r.ruleBased || { verdict: "not_flagged", reasons: [] };
    var sysB = r.systemB || r.weighted || { score: 0, maxScore: 120, threshold: 45, verdict: "not_flagged", reasons: [] };
    var sysC = r.systemC || r.hybrid || { verdict: "not_flagged", reasons: [] };

    renderUrl(r);
    var hKey = renderHeadline(r, shieldRes);

    // Family Shield policy card
    var fsBlocked = shieldRes && (shieldRes.category === "adult" || shieldRes.category === "gambling") && (shieldRes.confidence === "high" || shieldRes.confidence === "medium");
    var fsCard = $("cardFamilyShield");
    var fsPill = $("verdictFamilyShield");
    var fsReasons = $("reasonsFamilyShield");
    if (fsCard) {
      if (fsBlocked) {
        fsCard.hidden = false;
        if (fsPill) {
          fsPill.className = "pill blocked";
          fsPill.textContent = "Blocked (" + (shieldRes.category === "adult" ? "Adult" : "Gambling") + ")";
        }
        fillList(fsReasons, shieldRes.evidence);
      } else {
        fsCard.hidden = true;
      }
    }

    // Disagreement Banner
    var banner = $("disagreement");
    var disagree =
      typeof sysC.disagreement === "boolean"
        ? sysC.disagreement
        : sysA.verdict !== sysB.verdict;

    if (banner) {
      if (disagree) {
        banner.hidden = false;
        banner.textContent =
          "Disagreement: Rule-based (System A) says \"" +
          (PHRASE[sysA.verdict] || sysA.verdict) +
          "\", Weighted score (System B) says \"" +
          (PHRASE[sysB.verdict] || sysB.verdict) +
          "\".";
      } else {
        banner.hidden = true;
      }
    }

    // System A
    setPill($("verdictA"), sysA.verdict);
    fillList($("reasonsA"), sysA.reasons);

    // System B
    setPill($("verdictB"), sysB.verdict);
    fillList($("reasonsB"), sysB.reasons);

    var hasMax = typeof sysB.maxScore === "number" && sysB.maxScore > 0;
    var maxVal = hasMax ? sysB.maxScore : 120;
    var hasThreshold = typeof sysB.threshold === "number";
    var threshVal = hasThreshold ? sysB.threshold : 45;

    if ($("scoreText")) {
      $("scoreText").textContent = "Score " + sysB.score + " / " + maxVal;
    }
    if ($("scoreNote")) {
      $("scoreNote").textContent = "(flagged at " + threshVal + " or more)";
    }

    var fill = $("meterFill");
    if (fill) {
      var pct = Math.min(100, Math.max(0, (sysB.score / maxVal) * 100));
      fill.style.width = pct + "%";
      fill.classList.toggle("over", sysB.score >= threshVal);
      fill.classList.toggle("caution", sysB.score >= 30 && sysB.score < threshVal);
    }

    var mark = $("meterMark");
    if (mark) {
      mark.style.left = Math.min(100, (threshVal / maxVal) * 100) + "%";
    }

    // System C
    setPill($("verdictC"), sysC.verdict);
    fillList($("reasonsC"), sysC.reasons);

    // Six features list
    var list = $("featureList");
    if (list && r.features) {
      list.textContent = "";
      var keys = [
        "hostname_is_ip",
        "suspicious_symbols",
        "hostname_dot_count",
        "keyword_match",
        "url_length",
        "uses_https",
      ];
      keys.forEach(function (key) {
        var li = document.createElement("li");
        var nameSpan = document.createElement("span");
        nameSpan.textContent = FEATURE_LABELS[key] || key;
        var stateSpan = document.createElement("span");
        var on = !!r.features[key];
        stateSpan.className = on ? "yes" : "no";
        stateSpan.textContent = on ? "Yes" : "No";
        li.appendChild(nameSpan);
        li.appendChild(stateSpan);
        list.appendChild(li);
      });
    }

    // Continuous page context signals
    renderPageSignals(r.url);

    // Recommended next steps
    var stepsKey = hKey === "none" ? "none" : (hKey === "family_shield" ? "family_shield" : (hKey === "disagree" ? "disagree" : (hKey === "suspicious" ? "suspicious" : "phishing")));
    var steps = NEXT_STEPS[stepsKey] || NEXT_STEPS.none;
    fillList($("nextSteps"), steps);

    // Explanation
    var expEl = $("explanation");
    if (expEl) {
      expEl.textContent =
        r.explanation ||
        "Analysis examined six structural URL features locally in the browser.";
    }
  }

  // ---- Analysis Entry Points ----------------------------------------------
  function analyze(url, fromInput) {
    var id = ++runId;
    setView("loading");

    var targetUrl = (typeof url === "string" ? url : "").trim();
    if (!targetUrl) {
      setView("invalid", "Please enter a valid website address.", fromInput);
      return;
    }

    // Evaluate Family Shield classification if enabled
    var shieldRes = null;
    if (isFamilyShieldEnabled) {
      var classifier = (window.FamilyShield && window.FamilyShield.classifyUrl) ||
                       (self.FamilyShield && self.FamilyShield.classifyUrl);
      if (typeof classifier === "function") {
        try {
          shieldRes = classifier(targetUrl);
        } catch (e) {
          console.warn("TriVex: FamilyShield classification error:", e);
        }
      }
    }

    // First try the local detector.js function if loaded
    if (typeof window.analyzeUrl === "function") {
      try {
        var localResult = window.analyzeUrl(targetUrl);
        if (id !== runId) return;
        if (localResult.error) {
          setView("invalid", localResult.error, fromInput);
          return;
        }
        render(localResult, shieldRes);
        setView("result");
        return;
      } catch (err) {
        console.warn("TriVex: Local analyzeUrl threw error, trying background:", err);
      }
    }

    // Fallback: request analysis from background service worker
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage(
        { type: "ANALYZE_URL", url: targetUrl, source: "popup" },
        function (response) {
          if (id !== runId) return;
          if (chrome.runtime.lastError || !response || !response.ok) {
            setView("unavailable", "Analysis service is currently unavailable.");
            return;
          }
          if (response.result && response.result.error) {
            setView("invalid", response.result.error, fromInput);
            return;
          }
          render(response.result, shieldRes);
          setView("result");
        }
      );
    } else {
      setView("unavailable", "The detection engine could not be reached.");
    }
  }

  function scanCurrentTab() {
    if (typeof chrome === "undefined" || !chrome.tabs || !chrome.tabs.query) {
      setView("unavailable", "Tab access is only available when running as an extension.");
      return;
    }

    var id = ++runId;
    setView("loading");

    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (id !== runId) return;
      var tab = tabs && tabs[0];
      if (chrome.runtime.lastError || !tab || !tab.url) {
        setView("unavailable", "Could not read the address of the active tab.");
        return;
      }

      // Check for internal browser URLs
      var url = tab.url;
      if (
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("about:") ||
        url.startsWith("edge://") ||
        url.startsWith("brave://")
      ) {
        setView("initial");
        return;
      }

      if ($("urlInput")) $("urlInput").value = url;
      analyze(url, false);
    });
  }

  // ---- Initialization -----------------------------------------------------
  document.addEventListener("DOMContentLoaded", function () {
    initFamilyShield();
    setView("initial");

    // Automatically inspect current active tab on popup open (VirusTotal pattern)
    scanCurrentTab();

    var scanTabBtn = $("scanTab");
    if (scanTabBtn) scanTabBtn.addEventListener("click", scanCurrentTab);

    var scanUrlBtn = $("scanUrl");
    if (scanUrlBtn) {
      scanUrlBtn.addEventListener("click", function () {
        if ($("urlInput")) analyze($("urlInput").value, true);
      });
    }

    var urlInput = $("urlInput");
    if (urlInput) {
      urlInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") analyze(urlInput.value, true);
      });
    }
  });
})();
