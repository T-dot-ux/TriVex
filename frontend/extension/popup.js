/*
 * popup.js - UI logic (Member 1).
 * Talks to the detector only through analyzeUrl(url) from detector.js.
 * It never fetches or opens the analyzed URL.
 */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  var VERDICT_TEXT = { phishing: "Flagged: suspicious", not_flagged: "Not flagged" };

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
    var flagged = [r.ruleBased, r.weighted, r.hybrid].filter(function (x) {
      return x.verdict === "phishing";
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
    var labels = window.PhishGuard.FEATURE_LABELS;

    $("analyzedUrl").textContent = r.url;
    $("results").hidden = false;

    setPill($("verdictA"), r.ruleBased.verdict);
    fillList($("reasonsA"), r.ruleBased.reasons);

    setPill($("verdictB"), r.weighted.verdict);
    fillList($("reasonsB"), r.weighted.reasons);
    $("scoreText").textContent = "Score " + r.weighted.score + " / " + r.weighted.maxScore;
    var fill = $("meterFill");
    fill.style.width = Math.min(100, (r.weighted.score / r.weighted.maxScore) * 100) + "%";
    fill.classList.toggle("over", r.weighted.score >= r.weighted.threshold);

    setPill($("verdictC"), r.hybrid.verdict);
    fillList($("reasonsC"), r.hybrid.reasons);

    var banner = $("disagreement");
    if (r.ruleBased.verdict !== r.weighted.verdict) {
      banner.hidden = false;
      banner.textContent =
        "Disagreement: Rule-based says " + VERDICT_TEXT[r.ruleBased.verdict] +
        ", Weighted score says " + VERDICT_TEXT[r.weighted.verdict] + ".";
    } else {
      banner.hidden = true;
    }

    var list = $("featureList");
    list.textContent = "";
    Object.keys(labels).forEach(function (key) {
      var li = document.createElement("li");
      var name = document.createElement("span");
      name.textContent = labels[key];
      var state = document.createElement("span");
      state.className = r.features[key] ? "yes" : "no";
      state.textContent = r.features[key] ? "Yes" : "No";
      li.appendChild(name);
      li.appendChild(state);
      list.appendChild(li);
    });

    $("explanation").textContent = buildExplanation(r);
  }

  function analyze(url) {
    setError("");
    var result;
    try {
      result = window.analyzeUrl(url);
    } catch (e) {
      // Safety net so a detector bug never leaves the popup blank.
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

  document.addEventListener("DOMContentLoaded", function () {
    $("scanTab").addEventListener("click", scanCurrentTab);
    $("scanUrl").addEventListener("click", function () {
      analyze($("urlInput").value);
    });
    $("urlInput").addEventListener("keydown", function (e) {
      if (e.key === "Enter") analyze($("urlInput").value);
    });
  });
})();
