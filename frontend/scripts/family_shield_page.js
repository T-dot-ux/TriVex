/*
 * family_shield_page.js — TriVex Family Shield Warning Page Controller.
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

    /* Display blocked URL via textContent — never innerHTML */
    var urlEl = document.getElementById("blockedUrl");
    if (urlEl) {
      urlEl.textContent = rawUrl || "(URL not provided)";
    }

    /* Display reason text safely */
    if (reason) {
      var reasonEl = document.getElementById("reasonBox");
      if (reasonEl) {
        reasonEl.textContent =
          "This page was blocked because: " + reason +
          ". TriVex Family Shield helps keep browsing safe and family-friendly.";
      }
    }
  });
})();
