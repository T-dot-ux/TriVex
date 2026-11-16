/*
 * content.js — TriVex page monitoring & active in-DOM Family Shield content script.
 *
 * Responsibilities:
 *   1. Real-time in-DOM Adult Age Gate & Vulgar Content Scanner (Family Shield).
 *      - Immediately halts and blocks pages requesting adult age confirmation (English, Hindi, multilingual).
 *      - Immediately halts and blocks pages containing multiple vulgar / adult words.
 *      - Replaces DOM with Family Shield educational screen and notifies background.
 *   2. Real-time client-side URL block enforcement (Phishing & Family Shield URL classification).
 *   3. Reads only structural/metadata signals from the page for PhishGuard (Phase 8):
 *      - document title, meta description, form action URLs, password input count, external link count.
 *   4. Debounced MutationObserver fires on DOM changes.
 *
 * NEVER reads:
 *   - Form field values
 *   - Password inputs
 *   - Any user-entered data
 */

(function () {
  "use strict";

  /* Skip extension pages and about: pages */
  var pageUrl = location.href || "";
  if (!pageUrl.startsWith("http://") && !pageUrl.startsWith("https://")) {
    return;
  }

  var isPageBlocked = false;
  var isFamilyShieldActive = true;

  /* Sync Family Shield status from storage */
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    try {
      chrome.storage.local.get(["familyShieldEnabled"], function (res) {
        if (res && res.familyShieldEnabled !== undefined) {
          isFamilyShieldActive = !!res.familyShieldEnabled;
        }
      });
      if (chrome.storage.onChanged) {
        chrome.storage.onChanged.addListener(function (changes, area) {
          if (area === "local" && changes.familyShieldEnabled) {
            isFamilyShieldActive = !!changes.familyShieldEnabled.newValue;
          }
        });
      }
    } catch (e) {}
  }

  /* ------------------------------------------------------------------ */
  /* REAL-TIME CLIENT-SIDE BLOCK ENFORCEMENT                             */
  /* ------------------------------------------------------------------ */

  function renderBlockScreen(type, blockedUrl, reasonText) {
    if (isPageBlocked) return;
    isPageBlocked = true;

    try {
      window.stop();
    } catch (e) {}

    // Disconnect mutation observer to prevent any further work
    if (observer) {
      try { observer.disconnect(); } catch (e) {}
    }

    // Stop all media playback immediately
    try {
      var media = document.querySelectorAll("video, audio");
      for (var i = 0; i < media.length; i++) {
        media[i].pause();
        media[i].src = "";
      }
    } catch (e) {}

    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        chrome.runtime.sendMessage({
          type: "PAGE_BLOCKED",
          blockType: type,
          url: blockedUrl
        });
      } catch (e) {}
    }

    var isFS = type === "family_shield";
    var bgGrad = isFS ? "linear-gradient(135deg, #0d3b5c 0%, #1a6b3c 100%)" : "#1a0000";
    var cardBg = isFS ? "rgba(255,255,255,0.08)" : "#2d0000";
    var cardBorder = isFS ? "2px solid rgba(255,255,255,0.25)" : "2px solid #c0392b";
    var textColor = isFS ? "#e8f5e9" : "#f8d7da";
    var titleColor = isFS ? "#a5d6a7" : "#ff6b6b";
    var icon = isFS ? "🛡️" : "⚠️";
    var titleText = isFS ? "TriVex Family Shield" : "TriVex Blocked This Page";
    var subText = isFS
      ? "TriVex Family Shield has restricted access to this address."
      : "This page was flagged as a potential phishing site.";

    document.title = isFS ? "TriVex Family Shield" : "TriVex — Phishing Warning";

    var html =
      '<!DOCTYPE html>' +
      '<html lang="en">' +
      '<head>' +
      '<meta charset="UTF-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>' + (isFS ? "TriVex Family Shield" : "TriVex — Phishing Warning") + '</title>' +
      '<style>' +
      '*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }' +
      'html, body {' +
      '  display: block !important; visibility: visible !important; opacity: 1 !important;' +
      '  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;' +
      '  background: ' + bgGrad + ' !important;' +
      '  color: ' + textColor + ' !important;' +
      '  min-height: 100vh; width: 100vw;' +
      '  display: flex !important; align-items: center; justify-content: center; padding: 24px;' +
      '}' +
      '.card {' +
      '  background: ' + cardBg + ';' +
      '  border: ' + cardBorder + ';' +
      '  border-radius: 14px; max-width: 640px; width: 100%; padding: 36px 32px;' +
      '  box-shadow: 0 8px 40px rgba(0,0,0,0.4);' +
      '}' +
      '.icon { font-size: 64px; text-align: center; display: block; margin-bottom: 12px; line-height: 1; }' +
      'h1 { font-size: 1.6rem; font-weight: 700; color: ' + titleColor + '; text-align: center; margin-bottom: 6px; }' +
      '.sub { text-align: center; font-size: 0.95rem; opacity: 0.85; margin-bottom: 24px; }' +
      '.box {' +
      '  background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.15);' +
      '  border-radius: 6px; padding: 10px 14px; margin-bottom: 18px; word-break: break-all; font-size: 0.88rem;' +
      '}' +
      '.box-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; opacity: 0.7; margin-bottom: 4px; }' +
      '.reason-box {' +
      '  background: ' + (isFS ? "rgba(0,0,0,0.25)" : "#3d0000") + ';' +
      '  border-left: 4px solid ' + (isFS ? "#4db6ac" : "#e74c3c") + ';' +
      '  padding: 10px 14px; margin-bottom: 24px; font-size: 0.9rem; border-radius: 4px;' +
      '}' +
      '.btn {' +
      '  display: inline-block; background: ' + (isFS ? "#2e7d32" : "#444") + '; color: #fff;' +
      '  padding: 10px 20px; border: none; border-radius: 6px; font-weight: 600; font-size: 0.95rem;' +
      '  cursor: pointer; transition: opacity 0.15s;' +
      '}' +
      '.btn:hover { opacity: 0.9; }' +
      '.res-title { font-size: 0.9rem; font-weight: 600; margin-bottom: 10px; color: #80cbc4; }' +
      '.res-list { list-style: none; margin-bottom: 24px; }' +
      '.res-list li { margin: 6px 0; }' +
      '.res-list a { color: #b2dfdb; text-decoration: none; font-size: 0.88rem; }' +
      '.res-list a:hover { text-decoration: underline; }' +
      '</style>' +
      '</head>' +
      '<body>' +
      '<div class="card">' +
      '<span class="icon">' + icon + '</span>' +
      '<h1>' + titleText + '</h1>' +
      '<p class="sub">' + subText + '</p>' +
      '<div class="box">' +
      '<div class="box-label">Blocked Address</div>' +
      '<div id="trivexBlockedUrl"></div>' +
      '</div>' +
      '<div class="reason-box" id="trivexBlockedReason"></div>' +
      (isFS
        ? '<div class="res-title">Parent-Approved Safe Resources:</div>' +
          '<ul class="res-list">' +
          '<li>🚀 <a href="https://www.nasa.gov/kidsclub/index.html" target="_blank" rel="noopener">NASA Kids Club</a> — Space exploration and activities</li>' +
          '<li>🦁 <a href="https://kids.nationalgeographic.com" target="_blank" rel="noopener">National Geographic Kids</a> — Animals and science</li>' +
          '<li>📖 <a href="https://kids.britannica.com" target="_blank" rel="noopener">Britannica Kids</a> — Safe encyclopedia for students</li>' +
          '<li>📺 <a href="https://pbslearningmedia.org" target="_blank" rel="noopener">PBS LearningMedia</a> — Educational lessons and videos</li>' +
          '</ul>'
        : '') +
      '<div>' +
      '<button class="btn" id="trivexBtnBack" type="button">← Go Back</button>' +
      '</div>' +
      '</div>' +
      '</body>' +
      '</html>';

    if (!document.documentElement) {
      document.write(html);
    } else {
      document.documentElement.innerHTML = html;
    }

    var urlEl = document.getElementById("trivexBlockedUrl");
    if (urlEl) urlEl.textContent = blockedUrl;

    var reasonEl = document.getElementById("trivexBlockedReason");
    if (reasonEl) reasonEl.textContent = "Reason: " + reasonText;

    var btnBack = document.getElementById("trivexBtnBack");
    if (btnBack) {
      btnBack.addEventListener("click", function () {
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.location.href = "https://www.google.com";
        }
      });
    }
  }

  // Active check on page start via URL classifiers
  function checkUrlOnLoad() {
    var detector = (window.PhishGuard && window.PhishGuard.analyzeUrl) || window.analyzeUrl;
    var classifier = (window.FamilyShield && window.FamilyShield.classifyUrl) || window.classifyUrl;

    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(["familyShieldEnabled"], function (res) {
        var fsEnabled = res && res.familyShieldEnabled !== undefined ? !!res.familyShieldEnabled : true;
        isFamilyShieldActive = fsEnabled;

        // Phishing check
        if (detector) {
          try {
            var pRes = detector(pageUrl);
            if (pRes && !pRes.error && pRes.finalVerdict === "phishing") {
              var pReason =
                (pRes.systemC && pRes.systemC.reasons && pRes.systemC.reasons[0]) ||
                "High-risk phishing indicators detected";
              renderBlockScreen("phishing", pageUrl, pReason);
              return;
            }
          } catch (e) {}
        }

        // Family Shield URL check
        if (fsEnabled && classifier) {
          try {
            var fRes = classifier(pageUrl);
            if (
              fRes &&
              (fRes.category === "adult" || fRes.category === "gambling") &&
              (fRes.confidence === "high" || fRes.confidence === "medium")
            ) {
              var fReason =
                (fRes.evidence && fRes.evidence[0]) ||
                ("Filtered by Family Shield (" + fRes.category + ")");
              renderBlockScreen("family_shield", pageUrl, fReason);
              return;
            }
          } catch (e) {}
        }

        // Run in-DOM content scanner
        scanPageForAdultContent();
      });
    } else {
      scanPageForAdultContent();
    }
  }

  /* ------------------------------------------------------------------ */
  /* REAL-TIME ADULT AGE GATE & VULGAR CONTENT SCANNER (FAMILY SHIELD)  */
  /* ------------------------------------------------------------------ */

  // Adult Age Confirmation Gate patterns (English, Hindi, multilingual)
  var AGE_GATE_PATTERNS = [
    // Direct statements of adult age restriction or verification
    /\b(?:18\s*(?:or\s*older|\+|years\s*of\s*age|years\s*old|\s*plus)|over\s*18|at\s*least\s*18)\b/i,
    /\b(?:i\s*am|i'm)\s*(?:at\s*least\s*)?18(?:\s*or\s*older|\+)?\b/i,
    /\b(?:i\s*am|i'm)\s*(?:an?\s*)?adult\b/i,
    /\b(?:confirm|verify)\s*(?:your\s*)?age\b/i,
    /\bage\s*(?:verification|gate|restricted|restriction|check)\b/i,
    /\brestricted\s*to\s*adults\b/i,
    /\badults\s*only\b/i,
    /\badult\s*content\s*(?:warning|notice|disclaimer|filter)\b/i,
    /\benter\s*(?:\(18\+\)|18\+)\b/i,
    /\b(?:under|below)\s*18\s*(?:exit|leave|prohibited)\b/i,
    /\b18\s*u\.?s\.?c\.?\s*2257\b/i,
    /\brta\b.*(?:restricted\s*to\s*adults|5042)/i,
    /\bparental\s*(?:control|advisory|filter).*(?:adult|18\+)/i,
    /\b(?:contains|access\s*to)\s*(?:sexually\s*explicit|age[\s\-]restricted|adult\s*materials?)/i,
    /\blegal\s*age\s*to\s*(?:view|access)\s*(?:adult|sexually)/i,
    /\bby\s*entering\s*(?:this\s*)?(?:site|website).*certify.*18/i,

    // Hindi / Indian regional age gate patterns
    /(?:18\s*साल|18\s*वर्ष)\s*(?:से\s*(?:अधिक|ऊपर|बड़ा)|या\s*उससे\s*अधिक)/,
    /वयस्क\s*(?:सामग्री|सत्यापन|केवल)/,
    /व्यस्क\s*(?:सामग्री|सत्यापन|केवल)/,
    /आयु\s*सत्यापन/,
    /\b18\s*saal\s*se\s*(?:upar|bada|adhik)\b/i,

    // Multilingual (French, Spanish, German, Portuguese, Russian)
    /(?:interdit|réservé)\s*aux\s*moins\s*de\s*18/i,
    /(?:j'ai|avoir)\s*18\s*ans\s*ou\s*plus/i,
    /(?:mayor|mayores)\s*de\s*18(?:\s*años)?/i,
    /s[oó]lo\s*para\s*adultos/i,
    /verificaci[oó]n\s*de\s*edad/i,
    /ab\s*18\s*jahren/i,
    /nur\s*f[uü]r\s*erwachsene/i,
    /(?:старше|от)\s*18\s*лет/i,
    /только\s*для\s*взрослых/i
  ];

  var AGE_GATE_BUTTON_PATTERNS = [
    /^(?:i\s*am\s*18|i'm\s*18|18\+\s*enter|enter\s*18\+|enter\s*\(18\+\)|i\s*am\s*an\s*adult|agree\s*&\s*enter|18\s*or\s*older|enter\s*site\s*\(18\+\))$/i,
    /^(?:under\s*18|i\s*am\s*under\s*18|exit\s*site|exit\s*\(under\s*18\)|leave\s*site)$/i
  ];

  // Robust multilingual vulgar words list (English, Hindi/Desi, international)
  var VULGAR_WORDS = [
    // English adult / pornographic / sexual terms
    "porn", "porno", "pornography", "pornstar", "xxx", "xxnx", "xvideos", "xnxx", "xhamster",
    "sexx", "sexxx", "nudity", "nsfw",
    "boobs", "tits", "titties", "nipples", "pussy", "dildo",
    "masturbat", "cumshot", "cumming", "creampie", "squirting", "blowjob", "handjob",
    "deepthroat", "threesome", "gangbang", "milf", "erotica", "hentai", "ecchi",
    "incest", "bdsm", "cuckold", "femdom",
    "sex video", "sex clip", "sex clips", "sex tape", "nude video", "leaked sex", "leaked mms", "mms video", "adult cams",

    // Indian / Hindi / Desi adult & vulgar terms (transliterated Latin)
    "chut", "choot", "chuth", "chudai", "chudakkad", "chudna", "choda", "chodna", "chodi",
    "gaand", "gand", "gandu", "lund", "lauda", "lawda", "laude", "lavda",
    "bhabhi sex", "desi bhabhi", "desi porn", "desi sex", "desi mms", "desi aunty", "savita bhabhi",
    "randi", "raand", "veshya", "muth", "mutthal", "suhagraat sex", "suhagrat sex", "suhagrat",
    "boor", "bhosda", "bhosdi", "bhosdike", "mallu sex", "tamil sex", "telugu sex", "bangla sex",
    "punjabi sex", "chuchi", "chuchiyan", "choche", "tharki", "antarvasna", "sex kahani", "mms leak",

    // Hindi Devanagari script vulgar / adult terms
    "चूत", "चूतड़", "चुदाई", "चोदना", "चोदी", "गांड", "गांडू", "लंड", "लौड़ा", "लवड़ा",
    "भाभी सेक्स", "देसी सेक्स", "देसी पोर्न", "देसी एमएमएस", "रंडी", "वेश्या",
    "मुठ", "मुठिया", "सुहागरात सेक्स", "कामसूत्र", "संभोग", "हवस", "ठरकी",
    "भोसड़ा", "भोसड़ी", "कामुक", "स्तन", "एमएमएस",

    // Spanish / Portuguese / French / German vulgar / adult terms
    "follar", "puta", "coño", "tetas", "verga", "culona",
    "baiser", "salope", "nichons", "ficken", "titten", "fotze", "schwanz"
  ];

  function scanPageForAdultContent() {
    if (isPageBlocked || !isFamilyShieldActive) return;

    // 1. Check meta tags for explicit adult/RTA rating
    try {
      var ratingMeta = document.querySelector("meta[name='rating'], meta[name='RTA'], meta[name='rating-labels']");
      if (ratingMeta) {
        var ratingVal = (ratingMeta.getAttribute("content") || "").toLowerCase();
        if (
          ratingVal.indexOf("rta") !== -1 ||
          ratingVal.indexOf("adult") !== -1 ||
          ratingVal.indexOf("mature") !== -1 ||
          ratingVal.indexOf("restricted") !== -1
        ) {
          renderBlockScreen("family_shield", pageUrl, "Adult rating metadata detected (RTA/adult)");
          return;
        }
      }
    } catch (e) {}

    // 2. Check for common age-gate CSS classes/IDs
    try {
      var ageElements = document.querySelectorAll(
        ".age-gate, .agegate, #age-gate, #agegate, .adult-warning, .warning-18, [id*='age-verif'], [class*='age-verif'], [id*='adult-confirm'], [class*='adult-confirm']"
      );
      if (ageElements.length > 0) {
        renderBlockScreen("family_shield", pageUrl, "Adult age-verification modal detected");
        return;
      }
    } catch (e) {}

    // 3. Check button / link text for age gate actions
    try {
      var buttons = document.querySelectorAll("button, a, input[type='button'], input[type='submit'], [role='button']");
      for (var b = 0; b < buttons.length; b++) {
        var btnText = (buttons[b].innerText || buttons[b].value || "").trim();
        if (btnText && btnText.length < 50) {
          for (var p = 0; p < AGE_GATE_BUTTON_PATTERNS.length; p++) {
            if (AGE_GATE_BUTTON_PATTERNS[p].test(btnText)) {
              renderBlockScreen("family_shield", pageUrl, "Adult age-confirmation button detected (" + btnText + ")");
              return;
            }
          }
        }
      }
    } catch (e) {}

    // 4. Gather visible text from title, meta tags, and body
    var titleText = (document.title || "").toLowerCase();
    var metaText = "";
    try {
      var metaEls = document.querySelectorAll("meta[name='description'], meta[name='keywords'], meta[property='og:title'], meta[property='og:description']");
      for (var m = 0; m < metaEls.length; m++) {
        metaText += " " + (metaEls[m].getAttribute("content") || "");
      }
    } catch (e) {}
    metaText = metaText.toLowerCase();

    var bodyText = "";
    try {
      if (document.body) {
        bodyText = (document.body.innerText || "").slice(0, 35000).toLowerCase();
      }
    } catch (e) {}

    var combinedText = titleText + " " + metaText + " " + bodyText;
    if (!combinedText.trim()) return;

    // 5. Check Age Gate regex patterns across text
    for (var g = 0; g < AGE_GATE_PATTERNS.length; g++) {
      if (AGE_GATE_PATTERNS[g].test(combinedText)) {
        renderBlockScreen("family_shield", pageUrl, "Adult age-confirmation gate detected");
        return;
      }
    }

    // 6. Check for explicit adult keyword in page title
    var titleExplicit = ["porn", "xxx", "xvideos", "xnxx", "xhamster", "bhabhi sex", "desi sex", "chudai", "चुदाई", "पोर्न"];
    for (var t = 0; t < titleExplicit.length; t++) {
      if (titleText.indexOf(titleExplicit[t]) !== -1) {
        renderBlockScreen("family_shield", pageUrl, "Adult keyword in page title (" + titleExplicit[t] + ")");
        return;
      }
    }

    // 7. Check for multiple vulgar / explicit keywords across page content
    var matchedVulgar = [];
    for (var i = 0; i < VULGAR_WORDS.length; i++) {
      var word = VULGAR_WORDS[i];
      if (word.indexOf(" ") !== -1) {
        if (combinedText.indexOf(word) !== -1) {
          matchedVulgar.push(word);
        }
      } else if (/[\u0900-\u097F]/.test(word)) {
        if (combinedText.indexOf(word) !== -1) {
          matchedVulgar.push(word);
        }
      } else {
        var wordRe = new RegExp("(?:^|[^a-zA-Z0-9])" + word + "(?:[^a-zA-Z0-9]|$)", "i");
        if (wordRe.test(combinedText)) {
          matchedVulgar.push(word);
        }
      }
    }

    if (matchedVulgar.length >= 2) {
      renderBlockScreen(
        "family_shield",
        pageUrl,
        "Multiple vulgar / explicit keywords detected on page (" + matchedVulgar.slice(0, 4).join(", ") + ")"
      );
      return;
    }
  }

  // Initial check
  checkUrlOnLoad();

  /* ------------------------------------------------------------------ */
  /* Signal collection (Phase 8 PhishGuard monitoring)                  */
  /* ------------------------------------------------------------------ */

  function collectSignals() {
    var title = document.title || "";

    var metaDesc = "";
    var metaEl = document.querySelector("meta[name='description']");
    if (metaEl) metaDesc = metaEl.getAttribute("content") || "";

    var formActions = [];
    var forms = document.querySelectorAll("form[action]");
    forms.forEach(function (form) {
      var action = form.getAttribute("action") || "";
      if (action && formActions.indexOf(action) === -1) {
        formActions.push(action);
      }
    });

    var passwordFieldCount = document.querySelectorAll("input[type='password']").length;

    var currentHost = location.hostname;
    var externalLinkCount = 0;
    var anchors = document.querySelectorAll("a[href]");
    anchors.forEach(function (a) {
      var href = a.getAttribute("href") || "";
      if (href.startsWith("http://") || href.startsWith("https://")) {
        try {
          var linkHost = new URL(href).hostname;
          if (linkHost && linkHost !== currentHost) {
            externalLinkCount++;
          }
        } catch (e) {}
      }
    });

    return {
      title:              title.slice(0, 200),
      metaDescription:    metaDesc.slice(0, 300),
      formActions:        formActions.slice(0, 10),
      passwordFieldCount: passwordFieldCount,
      externalLinkCount:  externalLinkCount,
      url:                location.href,
      collectedAt:        Date.now(),
    };
  }

  /* ------------------------------------------------------------------ */
  /* Send signals to background                                           */
  /* ------------------------------------------------------------------ */

  function sendSignals(signals) {
    if (isPageBlocked) return;
    try {
      chrome.runtime.sendMessage({ type: "PAGE_SIGNALS", signals: signals });
    } catch (e) {}
  }

  /* ------------------------------------------------------------------ */
  /* Debounce helper                                                      */
  /* ------------------------------------------------------------------ */

  function debounce(fn, delayMs) {
    var timer = null;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(fn, delayMs);
    };
  }

  /* ------------------------------------------------------------------ */
  /* Meaningful-change detector                                           */
  /* ------------------------------------------------------------------ */

  var lastTitle    = "";
  var lastNumForms = 0;
  var lastNumMeta  = 0;

  function isMeaningfulChange() {
    var title    = document.title;
    var numForms = document.querySelectorAll("form").length;
    var metaEl   = document.querySelector("meta[name='description']");
    var numMeta  = metaEl ? 1 : 0;

    if (title !== lastTitle || numForms !== lastNumForms || numMeta !== lastNumMeta) {
      lastTitle    = title;
      lastNumForms = numForms;
      lastNumMeta  = numMeta;
      return true;
    }
    return false;
  }

  /* ------------------------------------------------------------------ */
  /* Observer & Scanner Triggers                                          */
  /* ------------------------------------------------------------------ */

  var adultScanTimer = null;
  function triggerFastAdultScan() {
    if (isPageBlocked || !isFamilyShieldActive) return;
    if (adultScanTimer) return;
    adultScanTimer = setTimeout(function () {
      adultScanTimer = null;
      scanPageForAdultContent();
    }, 60);
  }

  var debouncedSignals = debounce(function () {
    if (isMeaningfulChange()) {
      sendSignals(collectSignals());
    }
  }, 1000);

  function onDomMutation() {
    if (isPageBlocked) return;
    triggerFastAdultScan();
    debouncedSignals();
  }

  function onInitialReady() {
    if (isPageBlocked) return;
    scanPageForAdultContent();
    lastTitle    = document.title;
    lastNumForms = document.querySelectorAll("form").length;
    var metaEl   = document.querySelector("meta[name='description']");
    lastNumMeta  = metaEl ? 1 : 0;
    sendSignals(collectSignals());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", onInitialReady);
  } else {
    onInitialReady();
  }

  window.addEventListener("load", function () {
    if (!isPageBlocked) scanPageForAdultContent();
  });

  // Watch for DOM mutations (modals, age gates, loaded content)
  var observer = new MutationObserver(onDomMutation);
  if (document.documentElement) {
    observer.observe(document.documentElement, {
      childList: true,
      subtree:   true
    });
  } else {
    document.addEventListener("DOMContentLoaded", function () {
      if (!isPageBlocked && document.documentElement) {
        observer.observe(document.documentElement, {
          childList: true,
          subtree:   true
        });
      }
    });
  }

  // Direct query listener for instant popup response
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
      if (message && message.type === "GET_LIVE_PAGE_SIGNALS") {
        sendResponse(collectSignals());
      }
      return false;
    });
  }

})();
