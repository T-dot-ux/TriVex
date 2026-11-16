/*
 * system_c_v2.js — TriVex System C v2 Local Machine Learning Decision Engine.
 *
 * Combines:
 *   1. Calibrated LightGBM Phishing Probability
 *   2. System A Deterministic Rule Evidence
 *   3. System B Cumulative Weighted Scoring
 *   4. Page Structural Evidence (content monitoring)
 *
 * Safe Decision Policy:
 *   - Below 0.20 (20%): Low Risk / Allow
 *   - 0.20 - 0.69 (20%-69%): Caution / Review
 *   - 0.70 - 0.94 (70%-94%): Strong Warning
 *   - >= 0.95 (95%+): Candidate for Block IF corroborated by critical signal
 *     (Prevents false-positive hard block on ML probability alone)
 */

(function (root) {
  "use strict";

  function getFeatureExtractor() {
    if (root.TriVexFeatureExtractor) return root.TriVexFeatureExtractor;
    if (typeof require !== "undefined") {
      try { return require("./feature_extractor.js"); } catch (e) {}
    }
    return null;
  }

  function getRuntime() {
    if (root.TriVexLightGBMRuntime) return root.TriVexLightGBMRuntime;
    if (typeof require !== "undefined") {
      try { return require("./lightgbm_runtime.js"); } catch (e) {}
    }
    return null;
  }

  function getModelLoader() {
    if (root.TriVexModelLoader) return root.TriVexModelLoader;
    if (typeof require !== "undefined") {
      try { return require("./model_loader.js"); } catch (e) {}
    }
    return null;
  }

  /**
   * Evaluates System C v2 for a given URL and context.
   *
   * @param {string} url Input URL
   * @param {object} context Optional context { pageSignals, systemA, systemB, assets }
   * @returns {object} Structured System C v2 verdict & explanation
   */
  function evaluateSystemC_v2(url, context) {
    context = context || {};
    var sysA = context.systemA || { verdict: "not_flagged", reasons: [] };
    var sysB = context.systemB || { score: 0, threshold: 45, reasons: [] };
    var pageSignals = context.pageSignals || null;
    var assets = context.assets || (getModelLoader() ? getModelLoader().getCachedModel() : null);

    var extractor = getFeatureExtractor();
    var runtime = getRuntime();

    // Fallback if ML runtime or model assets are unavailable
    if (!assets || assets.status !== "ready" || !runtime || !extractor) {
      return fallbackRuleDecision(url, sysA, sysB, "ML runtime or model assets unavailable");
    }

    var manifest = assets.manifest;
    var model = assets.model;
    var calib = assets.calibration;

    // 1. Extract 38-feature numerical vector
    var featureDict = extractor.extractFeatures(url, pageSignals, sysA, sysB);
    var featureVector = extractor.extractVector(url, pageSignals, sysA, sysB);

    // 2. Execute LightGBM tree ensemble
    var pred = runtime.predict(model, calib, featureVector);
    var prob = pred.calibratedProbability;
    var rawMargin = pred.rawMargin;

    // 3. Extract contributing features for explainability
    var contributingSignals = [];
    if (featureDict.is_ip_host === 1.0) contributingSignals.push("Raw IP address used as hostname");
    if (featureDict.has_at_symbol === 1.0) contributingSignals.push("User-info '@' symbol indicates URL spoofing");
    if (featureDict.no_https === 1.0 && featureDict.total_phish_token_count > 0) {
      contributingSignals.push("Credential/banking token on unencrypted HTTP connection");
    }
    if (featureDict.subdomain_depth >= 3) contributingSignals.push("Excessive subdomain depth (>= 3 dots)");
    if (featureDict.hyphen_count_host >= 2) contributingSignals.push("Multiple hyphens in hostname indicate typosquatting");
    if (featureDict.url_length > 75) contributingSignals.push("Anomalously long URL length (> 75 chars)");
    if (featureDict.is_suspicious_tld === 1.0) contributingSignals.push("High-risk phishing top-level domain");
    if (featureDict.has_file_extension === 1.0) contributingSignals.push("Suspicious executable/script path extension");
    if (featureDict.cross_origin_form_count > 0) contributingSignals.push("Page contains forms submitting to differing origins");

    // 4. Evidence Fusion & Decision Policy
    var riskLevel = "low";
    var recommendedAction = "allow";
    var finalVerdict = "not_flagged";
    var reasons = [];

    var criticalRuleFired = (featureDict.is_ip_host === 1.0) ||
                            (featureDict.has_at_symbol === 1.0) ||
                            (featureDict.no_https === 1.0 && featureDict.total_phish_token_count > 0) ||
                            (sysB.score >= sysB.threshold);

    if (prob >= 0.95) {
      // 95%+ requires corroboration for hard block
      if (criticalRuleFired) {
        riskLevel = "high";
        recommendedAction = "block";
        finalVerdict = "phishing";
        reasons.push("Critical risk: Machine Learning probability (" + Math.round(prob * 100) + "%) corroborated by critical heuristic signal.");
      } else {
        riskLevel = "high";
        recommendedAction = "warn";
        finalVerdict = "phishing";
        reasons.push("High ML phishing probability (" + Math.round(prob * 100) + "%). Corroborating block evidence pending.");
      }
    } else if (prob >= 0.70) {
      riskLevel = "high";
      recommendedAction = "warn";
      finalVerdict = "phishing";
      reasons.push("High phishing risk detected by Machine Learning (" + Math.round(prob * 100) + "% probability).");
    } else if (prob >= 0.20 || sysA.verdict === "phishing" || sysB.score >= 30) {
      riskLevel = "medium";
      recommendedAction = "warn";
      finalVerdict = "suspicious";
      if (prob >= 0.20) {
        reasons.push("Moderate ML risk score (" + Math.round(prob * 100) + "% probability). Caution advised.");
      } else {
        reasons.push("Heuristic indicator triggered caution while ML probability remained low (" + Math.round(prob * 100) + "%).");
      }
    } else {
      riskLevel = "low";
      recommendedAction = "allow";
      finalVerdict = "not_flagged";
      reasons.push("URL structure and machine learning analysis appear standard.");
    }

    // Append contributing signals
    contributingSignals.forEach(function (sig) {
      if (reasons.indexOf(sig) === -1) reasons.push(sig);
    });

    return {
      version: "2.0.0",
      engine: "System C v2 (LightGBM GBDT)",
      modelStatus: manifest.model_status || "EXPERIMENTAL",
      modelVersion: manifest.model_version || "2.0.0",
      phishingProbability: prob,
      rawScore: rawMargin,
      riskLevel: riskLevel,
      recommendedAction: recommendedAction,
      finalVerdict: finalVerdict,
      reasons: reasons,
      contributingSignals: contributingSignals,
      disagreement: (sysA.verdict !== sysB.verdict) || (finalVerdict !== sysA.verdict),
      systemA: sysA,
      systemB: sysB,
      features: featureDict,
    };
  }

  function fallbackRuleDecision(url, sysA, sysB, fallbackReason) {
    var rawUrl = url || "";
    var isIp = /(?:^\d{1,3}(\.\d{1,3}){3}$|^\[.+\]$)/.test(rawUrl);
    var hasAt = rawUrl.indexOf("@") !== -1;
    var hasScoreThreshold = sysB.score >= sysB.threshold;

    var verdict = "not_flagged";
    var riskLevel = "low";
    var action = "allow";
    var reasons = [];

    if (hasScoreThreshold || isIp || hasAt) {
      verdict = "phishing";
      riskLevel = "high";
      action = "block";
      reasons.push("Fallback heuristic rule flagged high risk.");
    } else if (sysA.verdict === "phishing" || sysB.score >= 30) {
      verdict = "suspicious";
      riskLevel = "medium";
      action = "warn";
      reasons.push("Fallback heuristic rule flagged suspicious indicators.");
    } else {
      reasons.push("URL structure appears standard.");
    }

    return {
      version: "1.1.0-fallback",
      engine: "System C v1 (Heuristic Fallback)",
      modelStatus: "unavailable",
      modelVersion: "none",
      phishingProbability: null,
      rawScore: sysB.score,
      riskLevel: riskLevel,
      recommendedAction: action,
      finalVerdict: verdict,
      reasons: reasons,
      contributingSignals: sysA.reasons.concat(sysB.reasons),
      disagreement: sysA.verdict !== sysB.verdict,
      systemA: sysA,
      systemB: sysB,
      fallbackReason: fallbackReason,
    };
  }

  var api = {
    evaluateSystemC_v2: evaluateSystemC_v2,
    fallbackRuleDecision: fallbackRuleDecision,
  };

  root.TriVexSystemCv2 = api;
  if (typeof window !== "undefined") window.TriVexSystemCv2 = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;

})(typeof self !== "undefined" ? self : this);
