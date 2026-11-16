/*
 * model_loader.js — Local Model Asset Loader & Cache for TriVex Extension.
 *
 * Loads packaged model assets from local extension storage:
 *   - models/model_manifest.json
 *   - models/phishing_model.json
 *   - models/calibration.json
 *
 * Never performs remote network downloads.
 * Handles service worker lifecycles, memory caching, and graceful fallback.
 */

(function (root) {
  "use strict";

  var cachedAssets = null;
  var loadingPromise = null;

  function loadJsonFromPath(relPath) {
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL) {
      var url = chrome.runtime.getURL(relPath);
      return fetch(url).then(function (res) {
        if (!res.ok) {
          throw new Error("HTTP error loading " + relPath + ": " + res.status);
        }
        return res.json();
      });
    }

    // Node.js fallback for tests
    if (typeof require !== "undefined") {
      try {
        var path = require("path");
        var fs = require("fs");
        var absPath = path.resolve(__dirname, "../../", relPath);
        if (!fs.existsSync(absPath)) {
          absPath = path.resolve(process.cwd(), "frontend", relPath);
        }
        var data = JSON.parse(fs.readFileSync(absPath, "utf8"));
        return Promise.resolve(data);
      } catch (err) {
        return Promise.reject(err);
      }
    }

    return Promise.reject(new Error("Unable to resolve local asset path: " + relPath));
  }

  function loadModelAssets() {
    if (cachedAssets) {
      return Promise.resolve(cachedAssets);
    }
    if (loadingPromise) {
      return loadingPromise;
    }

    loadingPromise = Promise.all([
      loadJsonFromPath("models/model_manifest.json"),
      loadJsonFromPath("models/phishing_model.json"),
      loadJsonFromPath("models/calibration.json"),
    ])
      .then(function (results) {
        var manifest = results[0];
        var model = results[1];
        var calibration = results[2];

        // Schema & feature count validation
        if (!manifest || !manifest.features || !model || !model.trees) {
          throw new Error("Model asset structure validation failed");
        }

        cachedAssets = {
          manifest: manifest,
          model: model,
          calibration: calibration,
          status: "ready",
          loadedAt: Date.now(),
        };
        loadingPromise = null;
        return cachedAssets;
      })
      .catch(function (err) {
        loadingPromise = null;
        console.error("TriVex: Failed to load local model assets:", err);
        return {
          manifest: null,
          model: null,
          calibration: null,
          status: "unavailable",
          error: String(err),
        };
      });

    return loadingPromise;
  }

  function getCachedModel() {
    return cachedAssets;
  }

  var api = {
    loadModelAssets: loadModelAssets,
    getCachedModel: getCachedModel,
  };

  root.TriVexModelLoader = api;
  if (typeof window !== "undefined") window.TriVexModelLoader = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;

})(typeof self !== "undefined" ? self : this);
