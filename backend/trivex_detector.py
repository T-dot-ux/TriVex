"""
trivex_detector.py — Python reference implementation of the TriVex detection engine.

Mirrors the JavaScript detector.js logic exactly so offline evaluation results
are directly comparable to what the browser extension would produce.

Three detection systems:
  System A — Rule-based  (flag if ANY rule triggers)
  System B — Weighted    (flag if score >= THRESHOLD)
  System C — Hybrid      (A wins if it flags; otherwise B; disagreements reported)

Usage:
    from trivex_detector import analyze_url
    result = analyze_url("http://192.168.1.1/secure/login")
    print(result.system_c.verdict)   # "phishing"
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEYWORDS: List[str] = ["secure", "login", "verify", "update", "account", "banking"]

WEIGHTS: dict = {
    "hostname_is_ip":     35,
    "suspicious_symbols": 30,
    "hostname_dot_count": 20,
    "keyword_match":      15,
    "url_length":         10,
    "uses_https":         10,   # weight applies when HTTPS is *absent*
}

THRESHOLD: int = 45
MAX_SCORE: int  = 120


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class UrlFeatures:
    """The six URL features extracted from a URL string."""
    hostname_is_ip:     bool = False
    suspicious_symbols: bool = False
    hostname_dot_count: bool = False   # True when dot count > 3
    keyword_match:      bool = False
    url_length:         bool = False   # True when length > 75
    uses_https:         bool = False   # True when HTTPS is *absent* (noHttps)


@dataclass
class SystemAResult:
    """Result from System A (rule-based)."""
    verdict: str            # "phishing" | "not_flagged"
    reasons: List[str] = field(default_factory=list)


@dataclass
class SystemBResult:
    """Result from System B (weighted scoring)."""
    score:     int
    max_score: int
    threshold: int
    verdict:   str            # "phishing" | "not_flagged"
    reasons:   List[str] = field(default_factory=list)


@dataclass
class SystemCResult:
    """Result from System C (hybrid)."""
    verdict:      str          # "phishing" | "suspicious" | "not_flagged"
    risk_level:   str = "low"  # "high" | "medium" | "low"
    risk_score:   int = 0
    reasons:      List[str] = field(default_factory=list)
    disagreement: bool = False


@dataclass
class AnalysisResult:
    """Complete analysis result for a URL."""
    url:              str
    hostname:         str
    validation_status: str     # "ok" | "empty" | "parse_error" | "unsupported_scheme" | "no_hostname"
    features:         Optional[UrlFeatures] = None
    matched_keywords: List[str] = field(default_factory=list)
    system_a:         Optional[SystemAResult] = None
    system_b:         Optional[SystemBResult] = None
    system_c:         Optional[SystemCResult] = None
    final_verdict:    str = ""
    risk_level:       str = "low"
    risk_score:       int = 0
    error:            str = ""

    @property
    def system_a_verdict(self) -> str:
        return self.system_a.verdict if self.system_a else ""

    @property
    def system_b_verdict(self) -> str:
        return self.system_b.verdict if self.system_b else ""

    @property
    def system_c_verdict(self) -> str:
        return self.system_c.verdict if self.system_c else ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# IPv4: four dotted-decimal octets
_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _is_ip_hostname(hostname: str) -> bool:
    """
    Return True if *hostname* is a raw IP address (IPv4 or IPv6).

    The Python urlparse library strips brackets from IPv6 literals, so we
    check for colons as the IPv6 indicator.  The JS URL API keeps brackets,
    which is why JS checks for '[' — both approaches detect the same cases.
    """
    if not hostname:
        return False
    # IPv6: contains colons (urlparse strips the brackets for us)
    if ":" in hostname:
        return True
    # IPv4
    return bool(_IPV4_RE.match(hostname))


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(raw_url: str, parsed) -> tuple[UrlFeatures, List[str]]:
    """
    Extract the six URL features defined in the TriVex playbook.

    Args:
        raw_url: The original URL string.
        parsed:  Result of urllib.parse.urlparse(raw_url).

    Returns:
        (UrlFeatures, matched_keywords)
    """
    hostname  = parsed.hostname or ""
    lower_url = raw_url.lower()

    # Count hyphens and dots in hostname only (not path / query)
    hyphen_count = hostname.count("-")
    dot_count    = hostname.count(".")

    matched = [kw for kw in KEYWORDS if kw in lower_url]

    no_https = parsed.scheme == "http"

    features = UrlFeatures(
        hostname_is_ip     = _is_ip_hostname(hostname),
        suspicious_symbols = ("@" in raw_url) or (hyphen_count >= 2),
        hostname_dot_count = dot_count > 3,
        keyword_match      = len(matched) > 0,
        url_length         = len(raw_url) > 75,
        uses_https         = no_https,   # True = suspicious (no HTTPS)
    )
    return features, matched


# ---------------------------------------------------------------------------
# System A — Rule-based
# ---------------------------------------------------------------------------

def run_system_a(features: UrlFeatures) -> SystemAResult:
    """
    Flag the URL if ANY of the five rules fires.

    The keyword rule triggers only when a keyword is present *and* HTTPS is
    absent — matching the JS implementation exactly.
    """
    reasons: List[str] = []

    if features.hostname_is_ip:
        reasons.append("IP address detected in hostname")
    if features.url_length:
        reasons.append("URL length exceeds 75 characters")
    if features.hostname_dot_count:
        reasons.append("Hostname has more than 3 dots (deep subdomains)")
    if features.suspicious_symbols:
        reasons.append("URL contains '@' or hostname has 2+ hyphens")
    if features.keyword_match and features.uses_https:
        reasons.append("Targeted keyword found AND HTTPS is absent")

    return SystemAResult(
        verdict = "phishing" if reasons else "not_flagged",
        reasons = reasons,
    )


# ---------------------------------------------------------------------------
# System B — Weighted scoring
# ---------------------------------------------------------------------------

_FEATURE_LABELS: dict = {
    "hostname_is_ip":     "IP address in hostname",
    "suspicious_symbols": "Suspicious symbols (@ or 2+ hyphens)",
    "hostname_dot_count": "Deep subdomains (>3 dots in hostname)",
    "keyword_match":      "Targeted phishing keyword",
    "url_length":         "Long URL (>75 chars)",
    "uses_https":         "HTTPS absent",
}


def run_system_b(features: UrlFeatures) -> SystemBResult:
    """
    Compute a weighted risk score.  Flag if score >= THRESHOLD.

    The 'uses_https' weight is added when HTTPS is *absent* (features.uses_https = True).
    """
    score   = 0
    reasons: List[str] = []

    for key, weight in WEIGHTS.items():
        if getattr(features, key, False):
            score += weight
            label  = _FEATURE_LABELS.get(key, key)
            reasons.append(f"{label} (+{weight})")

    return SystemBResult(
        score     = score,
        max_score = MAX_SCORE,
        threshold = THRESHOLD,
        verdict   = "phishing" if score >= THRESHOLD else "not_flagged",
        reasons   = reasons,
    )


# ---------------------------------------------------------------------------
# System C — Hybrid
# ---------------------------------------------------------------------------

def run_system_c(
    features: UrlFeatures,
    raw_url: str,
    system_a: SystemAResult,
    system_b: SystemBResult,
) -> SystemCResult:
    """
    Hybrid decision engine (mirrors JS runSystemC exactly):

    1. Runs System A and System B independently.
    2. Flags high-confidence "phishing" if:
       - Weighted risk score >= THRESHOLD (45+), OR
       - Critical high-confidence rule fires: IP hostname, '@' user-info,
         or phishing keyword combined with plain HTTP.
    3. Classifies as "suspicious" (caution / review needed) if:
       - System A flagged a single moderate/weak rule (e.g. length > 75 or >3 dots)
         while System B score is low, preventing false-positive hard blocking.
       - Or System B has a moderate cumulative score (30 <= score < 45).
    4. Classifies as "not_flagged" (low risk) if neither system flagged.
    5. Explicitly records disagreement and uncertainty.
    """
    reasons: List[str] = []
    has_ip = features.hostname_is_ip
    has_at = "@" in raw_url
    has_keyword_no_https = features.keyword_match and features.uses_https
    has_score_threshold = system_b.score >= system_b.threshold

    disagree = system_a.verdict != system_b.verdict

    if has_score_threshold or has_ip or has_at or has_keyword_no_https:
        verdict = "phishing"
        risk_level = "high"
        if has_score_threshold:
            reasons.append(
                f"Cumulative weighted risk score ({system_b.score}) exceeds threshold ({system_b.threshold})"
            )
        if has_ip:
            reasons.append("Critical indicator: raw IP address used as hostname")
        if has_at:
            reasons.append("Critical indicator: '@' symbol in URL indicates user-info spoofing")
        if has_keyword_no_https:
            reasons.append("Critical indicator: credential/banking keyword on insecure HTTP connection")
        for r in system_a.reasons:
            reasons.append(f"  A: {r}")
    elif system_a.verdict == "phishing":
        verdict = "suspicious"
        risk_level = "medium"
        reasons.append(
            f"Moderate indicators detected ({', '.join(system_a.reasons)}), "
            f"but cumulative risk score ({system_b.score}/{system_b.threshold}) "
            "is below critical threshold. Treat with caution."
        )
        disagree = True
    elif system_b.score >= 30:
        verdict = "suspicious"
        risk_level = "medium"
        reasons.append(
            f"Moderate cumulative risk score ({system_b.score}/{system_b.threshold} threshold). "
            "Verify site credentials."
        )
        disagree = True
    else:
        verdict = "not_flagged"
        risk_level = "low"
        reasons.append(
            f"No high-risk indicators detected (score {system_b.score}/{system_b.threshold} threshold)."
        )

    if disagree:
        reasons.append(
            f'Disagreement: System A says "{system_a.verdict}" '
            f'and System B says "{system_b.verdict}".'
        )

    return SystemCResult(
        verdict=verdict,
        risk_level=risk_level,
        risk_score=system_b.score,
        reasons=reasons,
        disagreement=disagree,
    )


# ---------------------------------------------------------------------------
# parse_url helper
# ---------------------------------------------------------------------------

def parse_url(raw_url: str):
    """
    Validate and parse a URL string.

    Returns (parsed, error_string).  If error_string is non-empty the URL
    is invalid; parsed will be None.
    """
    if not raw_url or not raw_url.strip():
        return None, "Empty URL"

    raw_url = raw_url.strip()

    try:
        parsed = urlparse(raw_url)
    except Exception as exc:
        return None, f"Parse error: {exc}"

    if parsed.scheme not in ("http", "https"):
        return None, f"Unsupported scheme: {parsed.scheme!r}"

    if not parsed.hostname:
        return None, "URL has no hostname"

    return parsed, ""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_url(raw_url: str) -> AnalysisResult:
    """
    Analyze a URL with all three detection systems.

    Args:
        raw_url: Raw URL string (may be untrimmed).

    Returns:
        AnalysisResult.  If the URL is invalid, .error is set and system
        results will be None.
    """
    raw_url = (raw_url or "").strip()

    if not raw_url:
        return AnalysisResult(
            url="", hostname="", validation_status="empty",
            error="Empty URL", final_verdict="",
        )

    parsed, err = parse_url(raw_url)
    if err:
        status = "parse_error"
        if "Empty" in err:
            status = "empty"
        elif "scheme" in err.lower():
            status = "unsupported_scheme"
        elif "hostname" in err.lower():
            status = "no_hostname"
        return AnalysisResult(
            url=raw_url, hostname="", validation_status=status,
            error=err, final_verdict="",
        )

    features, matched = extract_features(raw_url, parsed)
    sys_a = run_system_a(features)
    sys_b = run_system_b(features)
    sys_c = run_system_c(features, raw_url, sys_a, sys_b)

    return AnalysisResult(
        url              = raw_url,
        hostname         = parsed.hostname or "",
        validation_status = "ok",
        features         = features,
        matched_keywords = matched,
        system_a         = sys_a,
        system_b         = sys_b,
        system_c         = sys_c,
        final_verdict    = sys_c.verdict,
        risk_level       = sys_c.risk_level,
        risk_score       = sys_c.risk_score,
    )
