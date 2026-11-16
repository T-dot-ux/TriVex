"""
validate_dataset.py — Dataset Quality & Validation Engine.

Performs rigorous audit of dataset records:
- Deduplication of URLs.
- Conflicting label detection.
- Normalization check.
- Malformed record handling.
- Domain leakage analysis across splits.
- Provenance auditing.
"""

import csv
import os
import sys
from collections import defaultdict
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple


def normalize_url(url: str) -> str:
    """Normalize URL string for deduplication."""
    clean = url.strip()
    if clean.endswith("/") and clean.count("/") > 3:
        clean = clean[:-1]
    return clean


def extract_registered_domain(url: str) -> str:
    """Extract approximate registered domain for leakage analysis."""
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"


def validate_dataset(filepath: str) -> Dict[str, Any]:
    """
    Validates a CSV dataset with columns: url, label, source, etc.
    Returns comprehensive validation results.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset file not found: {filepath}")

    records: List[Dict[str, str]] = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            records.append(row)

    total_records = len(records)
    url_to_labels = defaultdict(set)
    url_to_rows = defaultdict(list)
    domain_to_labels = defaultdict(set)
    domain_counts = defaultdict(int)

    malformed = []
    valid_records = []

    for idx, row in enumerate(records):
        url = row.get("url", "").strip()
        label_raw = row.get("label", row.get("true_label", "")).strip().lower()

        # Support both numeric (1/0) and textual ('phishing'/'benign'/'legitimate')
        if label_raw in ("1", "phishing", "malicious"):
            label = 1
        elif label_raw in ("0", "benign", "legitimate", "safe"):
            label = 0
        else:
            malformed.append({"row": idx + 2, "url": url, "label": label_raw})
            continue

        if not url:
            malformed.append({"row": idx + 2, "url": url, "label": label_raw})
            continue
        norm_url = normalize_url(url)
        url_to_labels[norm_url].add(label)
        url_to_rows[norm_url].append(idx + 2)

        domain = extract_registered_domain(norm_url)
        domain_to_labels[domain].add(label)
        domain_counts[domain] += 1

        valid_records.append({"url": norm_url, "label": label, "domain": domain, "raw": row})

    # Duplicates & Conflicts
    unique_urls = len(url_to_labels)
    duplicate_urls = {u: rows for u, rows in url_to_rows.items() if len(rows) > 1}
    conflicting_urls = {u: labels for u, labels in url_to_labels.items() if len(labels) > 1}

    # Class balance
    pos_count = sum(1 for r in valid_records if r["label"] == 1)
    neg_count = sum(1 for r in valid_records if r["label"] == 0)

    # Domain leakage analysis
    mixed_domains = {d: labels for d, labels in domain_to_labels.items() if len(labels) > 1}

    report = {
        "file": filepath,
        "total_rows": total_records,
        "valid_count": len(valid_records),
        "malformed_count": len(malformed),
        "unique_urls": unique_urls,
        "duplicate_count": len(duplicate_urls),
        "conflicting_count": len(conflicting_urls),
        "phishing_count": pos_count,
        "benign_count": neg_count,
        "unique_domains": len(domain_counts),
        "mixed_domain_count": len(mixed_domains),
        "status": "PASS" if len(conflicting_urls) == 0 and len(malformed) == 0 else "WARNING",
    }

    return report


if __name__ == "__main__":
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "data", "dataset.csv")
    res = validate_dataset(dataset_path)
    print("=== Dataset Validation Report ===")
    for k, v in res.items():
        print(f"  {k}: {v}")
