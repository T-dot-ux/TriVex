"""
feature_schema.py — Canonical Feature Schema for TriVex System C v2.

Defines the exact, versioned, ordered list of numerical features shared
between Python training/evaluation and JavaScript client inference.
"""

SCHEMA_VERSION = "2.0.0"

# Target: 36 Numerical Features
# Feature definition order is STRICTLY IMMUTABLE once finalized.
# The JavaScript runtime expects the feature vector in this EXACT order.

FEATURE_SPECIFICATIONS = [
    # Group A: URL Lexical features
    {
        "name": "url_length",
        "description": "Total character length of the raw URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "host_length",
        "description": "Character length of the hostname",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "path_length",
        "description": "Character length of the URL path",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "query_length",
        "description": "Character length of the query string excluding '?'",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "num_query_params",
        "description": "Number of key-value query parameters",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "special_char_count",
        "description": "Count of special characters (?, =, &, %, #, +, ~, _, -) in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_at_symbol",
        "description": "Binary indicator for presence of '@' userinfo symbol in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "hyphen_count_total",
        "description": "Count of hyphens across entire URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "hyphen_count_host",
        "description": "Count of hyphens in hostname",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "percent_encoding_count",
        "description": "Count of percent-encoded sequences (%xx) in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "digit_ratio_url",
        "description": "Ratio of numeric digits to total URL length",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "digit_ratio_host",
        "description": "Ratio of numeric digits to hostname length",
        "type": "float",
        "default": 0.0,
    },

    # Group B: Hostname features
    {
        "name": "is_ip_host",
        "description": "Binary indicator if hostname is an IPv4 or IPv6 address literal",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "dot_count_host",
        "description": "Count of dots in hostname",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "subdomain_depth",
        "description": "Estimated depth of subdomains (dots minus 1, min 0)",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "host_entropy",
        "description": "Shannon entropy of characters in hostname",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "is_punycode",
        "description": "Binary indicator if hostname contains 'xn--' (punycode IDN)",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_suspicious_port",
        "description": "Binary indicator if URL specifies a non-standard port",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "is_suspicious_tld",
        "description": "Binary indicator for high-risk phishing TLDs (e.g. .xyz, .top, .work, .click, .fit)",
        "type": "float",
        "default": 0.0,
    },

    # Group C: Lexical tokens
    {
        "name": "has_kw_login",
        "description": "Presence of 'login' token in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_kw_verify",
        "description": "Presence of 'verify' or 'verification' token in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_kw_account",
        "description": "Presence of 'account' token in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_kw_update",
        "description": "Presence of 'update' token in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_kw_banking",
        "description": "Presence of 'banking' or 'bank' token in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_kw_secure",
        "description": "Presence of 'secure' or 'security' token in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_kw_password",
        "description": "Presence of 'password' or 'passwd' token in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_kw_auth",
        "description": "Presence of 'auth', 'oauth', or 'signin' token in URL",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "total_phish_token_count",
        "description": "Count of distinct phishing tokens matched in URL",
        "type": "float",
        "default": 0.0,
    },

    # Group D: Statistical & Structural features
    {
        "name": "path_entropy",
        "description": "Shannon entropy of characters in URL path",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_file_extension",
        "description": "Binary indicator if path ends in an executable/script/doc extension (.exe, .php, .apk, .zip, etc.)",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "has_fragment",
        "description": "Binary indicator for presence of '#' URL fragment",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "no_https",
        "description": "Binary indicator: 1.0 if HTTP (insecure), 0.0 if HTTPS",
        "type": "float",
        "default": 0.0,
    },

    # Group E: Page Structural Signals (observed from content.js, default/imputed if unavailable)
    {
        "name": "has_page_signals",
        "description": "Indicator if DOM structural signals are available (1.0) or unavailable (0.0)",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "password_input_count",
        "description": "Count of password input elements on page",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "cross_origin_form_count",
        "description": "Count of forms posting to a differing origin",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "external_link_ratio",
        "description": "Ratio of external links to total links on page (0.0 if no links)",
        "type": "float",
        "default": 0.0,
    },

    # Group F: Heuristic Detector Evidence
    {
        "name": "sys_a_score_norm",
        "description": "Normalized System A heuristic output (1.0 if flagged, 0.0 otherwise)",
        "type": "float",
        "default": 0.0,
    },
    {
        "name": "sys_b_score_norm",
        "description": "Normalized System B weighted score (score / 120.0, clipped [0, 1])",
        "type": "float",
        "default": 0.0,
    },
]

FEATURE_NAMES = [f["name"] for f in FEATURE_SPECIFICATIONS]
FEATURE_COUNT = len(FEATURE_NAMES)  # 38 features

def get_schema_dict():
    """Returns a serializable dictionary representing the schema."""
    return {
        "schema_version": SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_names": FEATURE_NAMES,
        "features": FEATURE_SPECIFICATIONS,
    }
