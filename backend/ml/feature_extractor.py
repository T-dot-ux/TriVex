"""
feature_extractor.py — Canonical Feature Extractor for TriVex System C v2.

Extracts the exact numerical feature vector defined in feature_schema.py.
Designed to be replicated byte-for-byte in JavaScript.
"""

import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

try:
    from backend.ml.feature_schema import FEATURE_NAMES, get_schema_dict
except ImportError:
    from feature_schema import FEATURE_NAMES, get_schema_dict

# Pre-compiled regex patterns for performance and parity
IPV4_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SPECIAL_CHARS = set("?=&%#+_~-")
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "fit", "buzz", "gq", "ml", "cf", "ga",
    "tk", "icu", "cam", "rest", "surf", "monster", "bar", "live", "link"
}
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".zip", ".rar", ".7z", ".apk", ".php", ".asp", ".aspx",
    ".jsp", ".cgi", ".bin", ".bat", ".cmd", ".vbs", ".ps1", ".jar"
}

TOKEN_PATTERNS = {
    "login": re.compile(r"(?:login|log-in|signin|sign-in)", re.IGNORECASE),
    "verify": re.compile(r"(?:verify|verification|validation)", re.IGNORECASE),
    "account": re.compile(r"(?:account|acct|myaccount)", re.IGNORECASE),
    "update": re.compile(r"(?:update|upgrade|renew)", re.IGNORECASE),
    "banking": re.compile(r"(?:bank|banking|paypal|chase|wellsfargo|citi)", re.IGNORECASE),
    "secure": re.compile(r"(?:secure|security|safelogin)", re.IGNORECASE),
    "password": re.compile(r"(?:password|passwd|passcode)", re.IGNORECASE),
    "auth": re.compile(r"(?:auth|oauth|authenticate|authorization)", re.IGNORECASE),
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_ip_hostname(hostname: str) -> bool:
    """Check if hostname is IPv4 or IPv6."""
    if not hostname:
        return False
    if hostname.startswith("[") and hostname.endswith("]"):
        return True  # IPv6 wrapped literal
    return bool(IPV4_REGEX.match(hostname))


def extract_feature_dict(
    url: str,
    page_signals: Optional[Dict[str, Any]] = None,
    system_a_result: Optional[Dict[str, Any]] = None,
    system_b_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, float]:
    """
    Extracts all 38 numerical features from URL string and optional context.
    Returns a dictionary mapping feature_name -> float value.
    """
    raw_url = (url or "").strip()
    if not raw_url:
        # Return zeros for empty input
        return {k: 0.0 for k in FEATURE_NAMES}

    # Ensure parseable scheme
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        parse_target = "http://" + raw_url
    else:
        parse_target = raw_url

    try:
        parsed = urlparse(parse_target)
    except Exception:
        # If unparseable, return zeros
        return {k: 0.0 for k in FEATURE_NAMES}

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    port = parsed.port
    scheme = (parsed.scheme or "").lower()

    lower_url = raw_url.lower()
    url_len = len(raw_url)
    host_len = len(hostname)

    # 1. Lexical URL Features
    url_length = float(url_len)
    host_length = float(host_len)
    path_length = float(len(path))
    query_length = float(len(query))

    num_query_params = float(len([p for p in query.split("&") if p])) if query else 0.0

    special_char_count = float(sum(1 for c in raw_url if c in SPECIAL_CHARS))
    has_at_symbol = 1.0 if "@" in raw_url else 0.0
    hyphen_count_total = float(raw_url.count("-"))
    hyphen_count_host = float(hostname.count("-"))
    percent_encoding_count = float(len(re.findall(r"%[0-9a-fA-F]{2}", raw_url)))

    digits_in_url = sum(1 for c in raw_url if c.isdigit())
    digit_ratio_url = round(digits_in_url / url_len, 4) if url_len > 0 else 0.0

    digits_in_host = sum(1 for c in hostname if c.isdigit())
    digit_ratio_host = round(digits_in_host / host_len, 4) if host_len > 0 else 0.0

    # 2. Hostname features
    is_ip_host = 1.0 if is_ip_hostname(hostname) else 0.0
    dot_count_host = float(hostname.count("."))
    subdomain_depth = float(max(0, hostname.count(".") - 1)) if not is_ip_host else 0.0
    host_entropy = calculate_entropy(hostname)
    is_punycode = 1.0 if "xn--" in hostname else 0.0

    has_suspicious_port = 0.0
    if port is not None and port not in (80, 443, 8080):
        has_suspicious_port = 1.0

    is_suspicious_tld = 0.0
    if "." in hostname and not is_ip_host:
        tld = hostname.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            is_suspicious_tld = 1.0

    # 3. Keyword / Lexical token features
    kw_hits = {}
    for kw, pattern in TOKEN_PATTERNS.items():
        kw_hits[kw] = 1.0 if pattern.search(lower_url) else 0.0

    total_phish_token_count = float(sum(kw_hits.values()))

    # 4. Statistical & Structural features
    path_entropy = calculate_entropy(path)

    has_file_extension = 0.0
    for ext in SUSPICIOUS_EXTENSIONS:
        if path.lower().endswith(ext):
            has_file_extension = 1.0
            break

    has_fragment = 1.0 if fragment else 0.0
    no_https = 1.0 if scheme == "http" else 0.0

    # 5. Page Structural features (from content.js observer)
    if page_signals and isinstance(page_signals, dict) and page_signals.get("available", False):
        has_page_signals = 1.0
        password_input_count = float(page_signals.get("passwordInputs", 0))
        cross_origin_form_count = float(page_signals.get("crossOriginForms", 0))
        total_links = page_signals.get("totalLinks", 0)
        ext_links = page_signals.get("externalLinks", 0)
        external_link_ratio = round(ext_links / total_links, 4) if total_links > 0 else 0.0
    else:
        has_page_signals = 0.0
        password_input_count = 0.0
        cross_origin_form_count = 0.0
        external_link_ratio = 0.0

    # 6. Heuristic Detector features (Systems A & B)
    if system_a_result and isinstance(system_a_result, dict):
        sys_a_score_norm = 1.0 if system_a_result.get("verdict") == "phishing" else 0.0
    else:
        # Compute baseline System A from raw signals
        sys_a_flag = (
            bool(is_ip_host)
            or (url_length > 75)
            or (dot_count_host > 3)
            or (has_at_symbol == 1.0 or hyphen_count_host >= 2)
            or (total_phish_token_count > 0 and no_https == 1.0)
        )
        sys_a_score_norm = 1.0 if sys_a_flag else 0.0

    if system_b_result and isinstance(system_b_result, dict):
        raw_b_score = float(system_b_result.get("score", 0.0))
        sys_b_score_norm = round(min(1.0, max(0.0, raw_b_score / 120.0)), 4)
    else:
        # Compute baseline System B score
        b_score = 0.0
        if is_ip_host:
            b_score += 35.0
        if has_at_symbol == 1.0 or hyphen_count_host >= 2:
            b_score += 30.0
        if dot_count_host > 3:
            b_score += 20.0
        if total_phish_token_count > 0:
            b_score += 15.0
        if url_length > 75:
            b_score += 10.0
        if no_https == 1.0:
            b_score += 10.0
        sys_b_score_norm = round(min(1.0, max(0.0, b_score / 120.0)), 4)

    return {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "query_length": query_length,
        "num_query_params": num_query_params,
        "special_char_count": special_char_count,
        "has_at_symbol": has_at_symbol,
        "hyphen_count_total": hyphen_count_total,
        "hyphen_count_host": hyphen_count_host,
        "percent_encoding_count": percent_encoding_count,
        "digit_ratio_url": digit_ratio_url,
        "digit_ratio_host": digit_ratio_host,
        "is_ip_host": is_ip_host,
        "dot_count_host": dot_count_host,
        "subdomain_depth": subdomain_depth,
        "host_entropy": host_entropy,
        "is_punycode": is_punycode,
        "has_suspicious_port": has_suspicious_port,
        "is_suspicious_tld": is_suspicious_tld,
        "has_kw_login": kw_hits["login"],
        "has_kw_verify": kw_hits["verify"],
        "has_kw_account": kw_hits["account"],
        "has_kw_update": kw_hits["update"],
        "has_kw_banking": kw_hits["banking"],
        "has_kw_secure": kw_hits["secure"],
        "has_kw_password": kw_hits["password"],
        "has_kw_auth": kw_hits["auth"],
        "total_phish_token_count": total_phish_token_count,
        "path_entropy": path_entropy,
        "has_file_extension": has_file_extension,
        "has_fragment": has_fragment,
        "no_https": no_https,
        "has_page_signals": has_page_signals,
        "password_input_count": password_input_count,
        "cross_origin_form_count": cross_origin_form_count,
        "external_link_ratio": external_link_ratio,
        "sys_a_score_norm": sys_a_score_norm,
        "sys_b_score_norm": sys_b_score_norm,
    }


def extract_feature_vector(
    url: str,
    page_signals: Optional[Dict[str, Any]] = None,
    system_a_result: Optional[Dict[str, Any]] = None,
    system_b_result: Optional[Dict[str, Any]] = None,
) -> List[float]:
    """
    Extracts features and returns an ordered list of floats matching FEATURE_NAMES exactly.
    """
    f_dict = extract_feature_dict(url, page_signals, system_a_result, system_b_result)
    return [f_dict[name] for name in FEATURE_NAMES]
