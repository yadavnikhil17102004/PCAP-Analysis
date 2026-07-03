from __future__ import annotations

import math
import statistics
from collections import Counter

import pandas as pd

SEVERITY_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
}


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text.lower())
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _label_entropy(fqdn: str) -> float:
    """Entropy of leftmost label only — correct for DGA heuristics."""
    return _entropy(fqdn.split(".")[0])


def _sld(fqdn: str) -> str:
    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn


def _dga_score(fqdn: str) -> float:
    """
    Heuristic DGA confidence 0.0–1.0.
    Combines: label entropy, digit ratio, consonant runs, label count.
    """
    label = fqdn.split(".")[0]
    if not label:
        return 0.0
    ent = _entropy(label)
    digit_r = sum(c.isdigit() for c in label) / len(label)
    vowels = sum(c in "aeiou" for c in label.lower())
    vowel_r = vowels / len(label)
    max_cons = 0
    run = 0
    for c in label.lower():
        if c not in "aeiou" and c.isalpha():
            run += 1
            max_cons = max(max_cons, run)
        else:
            run = 0
    num_labels = fqdn.count(".")
    score = (
        min(ent / 5.0, 1.0) * 0.45
        + digit_r * 0.20
        + (1.0 - vowel_r) * 0.15
        + min(max_cons / 8.0, 1.0) * 0.10
        + min(num_labels / 6.0, 1.0) * 0.10
    )
    return round(min(score, 1.0), 3)


def _severity(score: float) -> str:
    if score >= 0.70:
        return "CRITICAL"
    if score >= 0.50:
        return "HIGH"
    if score >= 0.30:
        return "MEDIUM"
    return "LOW"


def build_query_df(dns_records: list) -> pd.DataFrame:
    rows = []
    for r in dns_records:
        if r.get("qr") != 0:
            continue
        qname = r.get("qname", "")
        dga = _dga_score(qname)
        rows.append({
            "time": pd.to_datetime(float(r.get("time", 0)), unit="s"),
            "ts": float(r.get("time", 0)),
            "src": r.get("src", "unknown"),
            "dst": r.get("dst", "unknown"),
            "qname": qname,
            "sld": _sld(qname),
            "label_ent": round(_label_entropy(qname), 3),
            "dga_score": dga,
            "severity": _severity(dga),
            "tx_id": r.get("id", 0),
        })
    return pd.DataFrame(rows)


def detect_beacons(df: pd.DataFrame) -> pd.DataFrame:
    """Flag (src, sld) pairs with low inter-query timing jitter."""
    results = []
    for (src, sld_val), grp in df.groupby(["src", "sld"]):
        times = sorted(grp["ts"].tolist())
        if len(times) < 3:
            continue
        intervals = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(intervals)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = stdev / mean if mean else 1
        results.append({
            "src": src,
            "sld": sld_val,
            "queries": len(times),
            "interval_mean_s": round(mean, 2),
            "jitter_cv": round(cv, 3),
            "beacon": cv < 0.30,
        })
    return pd.DataFrame(results) if results else pd.DataFrame()


def build_ip_df(enrich: dict) -> pd.DataFrame:
    rows = []
    for ip, data in enrich.get("ips", {}).items():
        api = data.get("ip_api", {})
        rdap = data.get("rdap", {})
        rows.append({
            "IP": ip,
            "Country": api.get("country", "?"),
            "CountryCode": api.get("countryCode", ""),
            "City": api.get("city", "?"),
            "ISP": api.get("isp", "?"),
            "Org": api.get("org", "?"),
            "ASN": rdap.get("asn", "?"),
            "ReverseDNS": data.get("reverse_dns") or "—",
            "Lat": api.get("lat"),
            "Lon": api.get("lon"),
        })
    return pd.DataFrame(rows)
