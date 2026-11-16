# TriVex System C v2: Machine Learning Architecture & Local Inference Engine

**Version:** 2.0.0  
**Status:** IMPLEMENTED (Local LightGBM Binary GBDT Engine)  
**Date:** November 16, 2026  

---

## 1. Architectural Overview

TriVex System C v2 introduces a genuine, local, client-side Machine Learning engine powered by **LightGBM** (Light Gradient Boosting Machine) to detect phishing URLs directly in Google Chrome / Microsoft Edge under Manifest V3.

Unlike cloud-dependent extensions, System C v2 runs entirely in the browser runtime:
- **Zero API keys required.**
- **Zero external network requests** during inference.
- **Zero remote telemetry or cloud LLM calls.**
- **100% offline functionality** after local installation.

```
+-------------------------------------------------------------------------+
|                           Incoming URL String                           |
+-------------------------------------------------------------------------+
                                     |
       +-----------------------------+-----------------------------+
       |                             |                             |
       v                             v                             v
+--------------+              +--------------+              +--------------+
|   System A   |              |   System B   |              | Family Shield|
|  Rule-Based  |              |Weighted Score|              |Content Filter|
+--------------+              +--------------+              +--------------+
       |                             |                             |
       +--------------+--------------+                             |
                      |                                            |
                      v                                            v
       +-----------------------------+                    +-----------------+
       | Feature Extractor (38 feats)|                    | DNR Declarative |
       | (Lexical, Host, Token, DOM) |                    |  Net Intercept  |
       +-----------------------------+                    +-----------------+
                      |
                      v
       +-----------------------------+
       |   Pure JS LightGBM Engine   |
       |  (Tree Ensemble Traversal)  |
       +-----------------------------+
                      |
                      v
       +-----------------------------+
       |  Platt Sigmoid Calibration  |
       |  P = 1 / (1 + exp(A*raw+B)) |
       +-----------------------------+
                      |
                      v
       +---------------------------------------------+
       |        System C v2 Evidence Fusion          |
       |  - Prob < 20%: Allow / Low Risk             |
       |  - 20% - 69%: Caution / Review              |
       |  - 70% - 94%: Strong Warning                |
       |  - >= 95% + Corroboration: Hard Block       |
       +---------------------------------------------+
```

---

## 2. Shared Canonical Feature Schema (v2.0.0)

Both Python training and JavaScript client inference evaluate the identical 38-feature numerical vector in strictly immutable order:

1. `url_length`: Total raw character length.
2. `host_length`: Length of parsed hostname.
3. `path_length`: Length of path string.
4. `query_length`: Length of query string.
5. `num_query_params`: Count of key-value query parameters.
6. `special_char_count`: Count of special characters (`?`, `=`, `&`, `%`, `#`, `+`, `_`, `~`, `-`).
7. `has_at_symbol`: Binary indicator for `@` user-info obfuscation.
8. `hyphen_count_total`: Total hyphens in entire URL.
9. `hyphen_count_host`: Hyphens in hostname (typosquatting indicator).
10. `percent_encoding_count`: Count of `%xx` hex escape sequences.
11. `digit_ratio_url`: Ratio of digits to total URL length.
12. `digit_ratio_host`: Ratio of digits to hostname length.
13. `is_ip_host`: Binary flag for IPv4 or IPv6 hostname literals.
14. `dot_count_host`: Total dots in hostname.
15. `subdomain_depth`: Depth of subdomains (dots - 1, min 0).
16. `host_entropy`: Shannon entropy of hostname characters.
17. `is_punycode`: Binary indicator for internationalized domain (`xn--`).
18. `has_suspicious_port`: Non-standard port flag (excluding 80, 443, 8080).
19. `is_suspicious_tld`: Known high-abuse phishing TLDs (`.xyz`, `.top`, `.click`, etc.).
20. `has_kw_login`: Presence of login token.
21. `has_kw_verify`: Presence of verify/verification token.
22. `has_kw_account`: Presence of account token.
23. `has_kw_update`: Presence of update token.
24. `has_kw_banking`: Presence of banking token.
25. `has_kw_secure`: Presence of secure/security token.
26. `has_kw_password`: Presence of password token.
27. `has_kw_auth`: Presence of auth/oauth/signin token.
28. `total_phish_token_count`: Count of distinct phishing tokens matched.
29. `path_entropy`: Shannon entropy of URL path.
30. `has_file_extension`: High-risk executable/script extension.
31. `has_fragment`: Presence of `#` fragment identifier.
32. `no_https`: Binary indicator (1.0 for HTTP, 0.0 for HTTPS).
33. `has_page_signals`: Availability flag for DOM context.
34. `password_input_count`: Number of password inputs observed.
35. `cross_origin_form_count`: Number of cross-origin form actions.
36. `external_link_ratio`: Ratio of external outbound links to total links.
37. `sys_a_score_norm`: Normalized System A rule flag (0.0 or 1.0).
38. `sys_b_score_norm`: Normalized System B score (`score / 120.0`).

---

## 3. LightGBM JavaScript Tree Traversal

The browser executes the trained trees via `frontend/scripts/ml/lightgbm_runtime.js`.
Each node is evaluated deterministically:
- If `value <= threshold`: proceed to `left` child.
- Else: proceed to `right` child.
- If missing / NaN: follow `default_left` direction.
- On reaching a leaf: return `leaf_value * shrinkage`.
- Sum of leaf values equals the base log-odds margin.

### Probability Calibration
Raw tree log-odds margins are converted into statistical probabilities using Platt scaling:
$$\text{Probability} = \frac{1}{1 + \exp(A \cdot \text{margin} + B)}$$
Where $A$ and $B$ are logistic calibration parameters fitted on a held-out calibration set.

---

## 4. Evidence Fusion & False-Positive Mitigation

Automatic hard blocking in web browsers carries significant false-positive cost (blocking legitimate banking or internal corporate portals). System C v2 enforces balanced decision rules:
- **Low Risk / Allow (< 20%):** Standard navigation allowed without disruption.
- **Caution (20% – 69%):** Warning banner in popup; user advised to verify site identity.
- **Strong Warning (70% – 94%):** Strong alert; password entry discouraged.
- **Candidate for Hard Block (>= 95%):** Automatically blocked **only if corroborated** by a deterministic signal (raw IP hostname, `@` spoofing, or high cumulative weighted score). Without corroboration, it is treated as a Strong Warning to safeguard against false-positive model drift.
