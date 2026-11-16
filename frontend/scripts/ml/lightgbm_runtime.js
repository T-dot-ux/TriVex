/*
 * lightgbm_runtime.js — Pure JavaScript LightGBM Tree Ensemble Interpreter.
 *
 * Executes serialized LightGBM GBDT binary models directly in browser or Node.js.
 * Correctly evaluates:
 *   - Numerical split thresholds (<= threshold goes left, > threshold goes right)
 *   - Default direction handling for missing / NaN values
 *   - Per-tree shrinkage and leaf value summation
 *   - Log-odds base margin calculation
 *   - Logistic / Sigmoid binary probability transformation
 *   - Platt calibration scaling: 1 / (1 + exp(A * margin + B))
 */

(function (root) {
  "use strict";

  /**
   * Traverses a single decision tree recursively.
   * @param {object} node Current tree node
   * @param {Array<number>} featureVector Array of numeric feature values
   * @returns {number} Leaf value
   */
  function evaluateNode(node, featureVector) {
    if (node.is_leaf) {
      return node.leaf_value;
    }

    var val = featureVector[node.feature_index];
    var isMissing = val === undefined || val === null || isNaN(val);

    if (isMissing) {
      return node.default_left
        ? evaluateNode(node.left, featureVector)
        : evaluateNode(node.right, featureVector);
    }

    // LightGBM default numerical split: val <= threshold goes left
    if (val <= node.threshold) {
      return evaluateNode(node.left, featureVector);
    } else {
      return evaluateNode(node.right, featureVector);
    }
  }

  /**
   * Evaluates all trees in a model and sums leaf values.
   * @param {object} model Serialized model from phishing_model.json
   * @param {Array<number>} featureVector Numeric feature vector
   * @returns {number} Raw margin (log-odds score)
   */
  function predictRawMargin(model, featureVector) {
    if (!model || !Array.isArray(model.trees)) {
      throw new Error("Invalid LightGBM model format: missing trees array");
    }

    var score = typeof model.base_score === "number" ? model.base_score : 0.0;
    var trees = model.trees;
    for (var i = 0; i < trees.length; i++) {
      var tree = trees[i];
      var leafVal = evaluateNode(tree.root, featureVector);
      var shrinkage = typeof tree.shrinkage === "number" ? tree.shrinkage : 1.0;
      score += leafVal * shrinkage;
    }
    return score;
  }

  /**
   * Computes standard uncalibrated sigmoid probability: 1 / (1 + exp(-margin)).
   */
  function sigmoid(margin) {
    var clipped = Math.max(-25.0, Math.min(25.0, margin));
    return 1.0 / (1.0 + Math.exp(-clipped));
  }

  /**
   * Applies Platt sigmoid calibration: 1 / (1 + exp(A * margin + B)).
   * @param {number} margin Raw log-odds margin
   * @param {object} calib Calibration parameters from calibration.json
   * @returns {number} Calibrated probability [0.0, 1.0]
   */
  function applyCalibration(margin, calib) {
    if (!calib || calib.method !== "platt_sigmoid" || !calib.parameters) {
      return sigmoid(margin);
    }
    var A = calib.parameters.A;
    var B = calib.parameters.B;
    var logits = A * margin + B;
    var clipped = Math.max(-25.0, Math.min(25.0, logits));
    return 1.0 / (1.0 + Math.exp(clipped));
  }

  /**
   * Full inference prediction.
   * @param {object} model Parsed phishing_model.json
   * @param {object} calib Parsed calibration.json
   * @param {Array<number>} featureVector Feature values in exact schema order
   * @returns {{ rawMargin: number, rawProbability: number, calibratedProbability: number }}
   */
  function predict(model, calib, featureVector) {
    var rawMargin = predictRawMargin(model, featureVector);
    var rawProb = sigmoid(rawMargin);
    var calibProb = applyCalibration(rawMargin, calib);

    return {
      rawMargin: Math.round(rawMargin * 1000000) / 1000000,
      rawProbability: Math.round(rawProb * 10000) / 10000,
      calibratedProbability: Math.round(calibProb * 10000) / 10000,
    };
  }

  var api = {
    evaluateNode: evaluateNode,
    predictRawMargin: predictRawMargin,
    sigmoid: sigmoid,
    applyCalibration: applyCalibration,
    predict: predict,
  };

  root.TriVexLightGBMRuntime = api;
  if (typeof window !== "undefined") window.TriVexLightGBMRuntime = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;

})(typeof self !== "undefined" ? self : this);
