# TriVex Evaluation Dataset Provenance & Methodology

**Dataset Version:** `1.1.0`  
**Total Records:** 120  
**Class Distribution:** 60 Phishing (Positive), 60 Benign (Negative)  
**Maintained by:** Youganter Kumar Singh (Member 3) & TriVex Engineering Team  
**Date:** November 2026  

---

## 1. Objective & Design Principles

The primary objective of this dataset is to provide an honest, rigorous offline benchmark for the TriVex detection engine (Systems A, B, and C).

Rather than evaluating exclusively on trivial instances where all signals align (which generates artificial 100% metrics), this version includes:
1. **High-Confidence Phishing Attacks:** Known phishing signatures (IP hostnames, credential keywords on unencrypted HTTP, userinfo `@` obfuscation, typosquatting multi-hyphen brand impersonation).
2. **Standard Benign Controls:** Top-traffic root domains (Tranco / Alexa Top 100).
3. **Hard Negatives (Benign Edge Cases):**
   - Legitimate long URLs (>75 characters, such as Wikipedia articles, deep documentation links, git commit SHAs).
   - Multi-hyphenated legitimate domains (e.g. `merriam-webster.com`, `e-learning-platform.org`).
   - Legitimate authentication and account portals operating over secure HTTPS (e.g. `github.com/login`, `myaccount.google.com`, `login.microsoftonline.com`).
   - Deep legitimate corporate/cloud subdomains (>3 dots in hostname, e.g. AWS console, Cloudflare CDN endpoints).
4. **Boundary Disagreement Instances:** Cases where System A (rule-based) flags on a single characteristic while System B (weighted score) produces a low risk score, validating System C's false-positive mitigation policy.

---

## 2. Dataset Composition Breakdown

| Category | Count | Sample Characteristics | Target Detection Behavior |
|---|---|---|---|
| **Phishing — Critical High Risk** | 30 | Raw IP hostnames, `@` symbols, unencrypted HTTP + banking keywords | System A flags, System B >= 45, System C = Phishing (High Risk) |
| **Phishing — Multi-Feature Composite** | 30 | Multi-hyphen domains, typosquats, delivery & tax refund scams | System B >= 45, System C = Phishing (High Risk) |
| **Benign — Standard Controls** | 30 | High-reputation root domains (`google.com`, `github.com`, `wikipedia.org`) | System A = Not Flagged, System B = 0, System C = Not Flagged |
| **Benign — Hard Negatives (Long URLs)** | 7 | Deep paths > 75 chars over HTTPS (`wikipedia.org/wiki/...`, `cloud.google.com/...`) | System A flags length, System B = 10, System C = Suspicious/Caution (Not Hard Blocked) |
| **Benign — Hard Negatives (Multi-Hyphens)** | 6 | Legitimate hyphenated domains (`e-learning-platform.org`, `merriam-webster.com`) | System A flags symbols, System B = 30, System C = Suspicious/Caution (Not Hard Blocked) |
| **Benign — Hard Negatives (Auth on HTTPS)** | 9 | Legitimate login pages (`github.com/login`, `myaccount.google.com`) | System A = Not Flagged, System B = 15, System C = Not Flagged |
| **Benign — Hard Negatives (Deep Subdomains)**| 5 | Cloud & CDN subdomains with >3 dots over HTTPS | System A flags dots, System B = 20, System C = Suspicious/Caution (Not Hard Blocked) |
| **Benign — Clean Additional Services** | 3 | `duckduckgo.com`, `gitlab.com`, `spotify.com` | Clean negative baselines |

---

## 3. Data Integrity & Leakage Prevention

- **Deduplication:** All 120 URL strings are unique.
- **Label Validation:** Ground truth labels are strictly verified against genuine ownership.
- **Cross-Language Consistency:** Identical parsing results are verified between Python `urllib.parse` and JavaScript WHATWG `new URL()`.
- **No Training Leakage:** TriVex uses deterministic and weighted rules, not a black-box model trained on this test set.
