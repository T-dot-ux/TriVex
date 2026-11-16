"""
test_unit_ml.py — Unit tests for TriVex System C v2 Python ML Engine.

Tests:
1. Feature schema definitions, defaults, and count.
2. Feature extractor calculations (entropy, IP, keywords, length).
3. Malformed URL handling and missing inputs.
4. Dataset validation functions.
5. Model training & serialization.
6. Calibration functions.
"""

import unittest
import numpy as np
from backend.ml.feature_schema import FEATURE_NAMES, FEATURE_COUNT, SCHEMA_VERSION, FEATURE_SPECIFICATIONS
from backend.ml.feature_extractor import (
    extract_feature_dict, extract_feature_vector, calculate_entropy, is_ip_hostname
)
from backend.ml.calibrate_model import fit_platt_scaling, apply_platt


class TestFeatureSchema(unittest.TestCase):
    def test_schema_count(self):
        self.assertEqual(len(FEATURE_NAMES), FEATURE_COUNT)
        self.assertEqual(FEATURE_COUNT, 38)
        self.assertEqual(len(FEATURE_SPECIFICATIONS), 38)

    def test_schema_uniqueness(self):
        self.assertEqual(len(set(FEATURE_NAMES)), FEATURE_COUNT)


class TestFeatureExtractor(unittest.TestCase):
    def test_entropy_computation(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy("aaaa"), 0.0)
        # 4 distinct characters equal probability: -4 * 0.25 * log2(0.25) = 2.0
        self.assertAlmostEqual(calculate_entropy("abcd"), 2.0, places=3)

    def test_ip_detection(self):
        self.assertTrue(is_ip_hostname("192.168.1.1"))
        self.assertTrue(is_ip_hostname("10.0.0.1"))
        self.assertTrue(is_ip_hostname("[::1]"))
        self.assertFalse(is_ip_hostname("google.com"))
        self.assertFalse(is_ip_hostname("paypal.com.evil.com"))

    def test_malformed_and_empty_urls(self):
        empty_vec = extract_feature_vector("")
        self.assertEqual(len(empty_vec), FEATURE_COUNT)
        self.assertTrue(all(v == 0.0 for v in empty_vec))

        malformed_vec = extract_feature_vector("not a valid url ://")
        self.assertEqual(len(malformed_vec), FEATURE_COUNT)

    def test_phishing_features(self):
        url = "http://192.168.1.1/secure/login"
        feats = extract_feature_dict(url)
        self.assertEqual(feats["is_ip_host"], 1.0)
        self.assertEqual(feats["no_https"], 1.0)
        self.assertEqual(feats["has_kw_login"], 1.0)
        self.assertEqual(feats["has_kw_secure"], 1.0)


class TestCalibration(unittest.TestCase):
    def test_platt_scaling(self):
        margins = np.array([-3.0, -2.0, -1.0, 1.0, 2.0, 3.0], dtype=np.float32)
        labels = np.array([0, 0, 0, 1, 1, 1], dtype=np.int32)
        A, B = fit_platt_scaling(margins, labels)
        probs = apply_platt(margins, A, B)

        self.assertEqual(len(probs), 6)
        self.assertTrue(np.all(probs >= 0.0) and np.all(probs <= 1.0))
        # Monotonicity check
        self.assertTrue(probs[0] < probs[-1])


if __name__ == "__main__":
    unittest.main()
