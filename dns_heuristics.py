"""Shared DNS scoring helpers used by the CLI and dashboard.

Benign suffixes like `.local` and `.arpa` are deliberately excluded from
entropy-based DGA scoring so workstation / mDNS noise does not trigger false
positives. The tradeoff is explicit: any real abuse hiding under those suffixes
needs separate correlation.
"""

from __future__ import annotations

import math
from collections import Counter

BENIGN_SUFFIXES = ('.local', '.arpa', '.in-addr.arpa')
DGA_ENTROPY_THRESHOLD = 3.5
DGA_LABEL_LENGTH_THRESHOLD = 12


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text.lower())
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def normalize_qname(fqdn: str | None) -> str:
    return (fqdn or '').rstrip('.')


def is_benign_pattern(fqdn: str | None) -> bool:
    fqdn = normalize_qname(fqdn).lower()
    return any(fqdn.endswith(suffix) for suffix in BENIGN_SUFFIXES)


def label_from_qname(fqdn: str | None) -> str:
    fqdn = normalize_qname(fqdn)
    if not fqdn:
        return ''
    return fqdn.split('.')[0]


def entropy_score(fqdn: str | None) -> float | None:
    if not fqdn or is_benign_pattern(fqdn):
        return None
    return round(_entropy(label_from_qname(fqdn)), 3)


def dga_score(fqdn: str | None) -> float:
    """Compatibility score for dashboards that still want a normalized score."""
    if is_benign_pattern(fqdn):
        return 0.0

    label = label_from_qname(fqdn)
    if not label:
        return 0.0

    ent = _entropy(label)
    digit_r = sum(c.isdigit() for c in label) / len(label)
    vowels = sum(c in 'aeiou' for c in label.lower())
    vowel_r = vowels / len(label)
    max_cons = 0
    run = 0
    for c in label.lower():
        if c not in 'aeiou' and c.isalpha():
            run += 1
            max_cons = max(max_cons, run)
        else:
            run = 0
    num_labels = normalize_qname(fqdn).count('.')
    score = (
        min(ent / 5.0, 1.0) * 0.45
        + digit_r * 0.20
        + (1.0 - vowel_r) * 0.15
        + min(max_cons / 8.0, 1.0) * 0.10
        + min(num_labels / 6.0, 1.0) * 0.10
    )
    return round(min(score, 1.0), 3)


def score_dns_entropy(fqdn: str | None) -> dict:
    label = label_from_qname(fqdn)
    benign = is_benign_pattern(fqdn)
    score = entropy_score(fqdn)
    return {
        'name': normalize_qname(fqdn),
        'label': label,
        'entropy_score': score,
        'known_benign_pattern': benign,
        'label_length': len(label),
        'dga_score': dga_score(fqdn),
    }
