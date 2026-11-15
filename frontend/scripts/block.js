/*
 * block.js — TriVex Phishing Warning Page Controller.
 * Manifest V3 CSP-compliant external script.
 */

(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    var btnBack = document.getElementById("btnBack");
    if (btnBack) {
      btnBack.addEventListener("click", function () {
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.close();
        }
      });
    }

    function getParam(name) {
      try {
        return new URLSearchParams(location.search).get(name) || "";
      } catch (e) {
        return "";
      }
    }

    var rawUrl = getParam("url");
    var reason = getParam("reason");

    var urlEl = document.getElementById("blockedUrl");
    if (urlEl) {
      urlEl.textContent = rawUrl || "(URL not provided)";
    }

    var reasonEl = document.getElementById("reasonBox");
    if (reasonEl && reason) {
      reasonEl.textContent = "Reason: " + reason;
    }
  });
})();
