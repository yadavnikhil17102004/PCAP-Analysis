from __future__ import annotations

import math
import statistics
from collections import Counter

import pandas as pd

from dns_heuristics import dga_score, score_dns_entropy

QUERY_COLUMNS = [
    'time',
    'ts',
    'src',
    'dst',
    'qname',
    'sld',
    'label_ent',
    'entropy_score',
    'known_benign_pattern',
    'dga_score',
    'severity',
    'tx_id',
]

BEACON_COLUMNS = ['src', 'sld', 'queries', 'interval_mean_s', 'jitter_cv', 'beacon']

IP_COLUMNS = ['IP', 'Country', 'CountryCode', 'City', 'ISP', 'Org', 'ASN', 'ReverseDNS', 'Lat', 'Lon']

SEVERITY_COLOR = {
    'CRITICAL': '#ef4444',
    'HIGH': '#f97316',
    'MEDIUM': '#eab308',
    'LOW': '#22c55e',
}


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text.lower())
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _label_entropy(fqdn: str) -> float:
    """Entropy of leftmost label only — correct for DGA heuristics."""
    return _entropy(fqdn.split('.')[0])


def _sld(fqdn: str) -> str:
    parts = fqdn.rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else fqdn


def _severity(score: float | None) -> str:
    if score is None:
        return 'LOW'
    if score >= 0.70:
        return 'CRITICAL'
    if score >= 0.50:
        return 'HIGH'
    if score >= 0.30:
        return 'MEDIUM'
    return 'LOW'


def build_query_df(dns_records: list) -> pd.DataFrame:
    rows = []

    def _pick(record: dict, *keys, default='unknown'):
        for key in keys:
            value = record.get(key)
            if value not in (None, ''):
                return value
        return default

    for r in dns_records or []:
        if r.get('qr') != 0:
            continue
        qname = _pick(r, 'qname', 'query', 'domain', default='')
        scored = score_dns_entropy(qname)
        ts = float(r.get('time', r.get('ts', 0)) or 0)
        rows.append({
            'time': pd.to_datetime(ts, unit='s'),
            'ts': ts,
            'src': _pick(r, 'src', 'source', 'src_ip', 'client', default='unknown'),
            'dst': _pick(r, 'dst', 'destination', 'dst_ip', 'server', default='unknown'),
            'qname': qname,
            'sld': _sld(qname),
            'label_ent': round(_label_entropy(qname), 3) if scored['entropy_score'] is not None else None,
            'entropy_score': scored['entropy_score'],
            'known_benign_pattern': scored['known_benign_pattern'],
            'dga_score': scored['dga_score'],
            'severity': _severity(scored['dga_score']),
            'tx_id': r.get('id', r.get('tx_id', 0)),
        })
    return pd.DataFrame(rows, columns=QUERY_COLUMNS)


def detect_beacons(df: pd.DataFrame) -> pd.DataFrame:
    """Flag (src, sld) pairs with low inter-query timing jitter."""
    if df is None or df.empty or not {'src', 'sld', 'ts'}.issubset(df.columns):
        return pd.DataFrame(columns=BEACON_COLUMNS)

    results = []
    for (src, sld_val), grp in df.groupby(['src', 'sld']):
        times = sorted(pd.to_numeric(grp['ts'], errors='coerce').dropna().tolist())
        if len(times) < 3:
            continue
        intervals = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(intervals)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = stdev / mean if mean else 1
        results.append({
            'src': src,
            'sld': sld_val,
            'queries': len(times),
            'interval_mean_s': round(mean, 2),
            'jitter_cv': round(cv, 3),
            'beacon': cv < 0.30,
        })
    return pd.DataFrame(results, columns=BEACON_COLUMNS) if results else pd.DataFrame(columns=BEACON_COLUMNS)


def build_ip_df(enrich: dict) -> pd.DataFrame:
    rows = []
    for ip, data in enrich.get('ips', {}).items():
        api = data.get('ip_api', {})
        rdap = data.get('rdap', {})
        rows.append({
            'IP': ip,
            'Country': api.get('country', '?'),
            'CountryCode': api.get('countryCode', ''),
            'City': api.get('city', '?'),
            'ISP': api.get('isp', '?'),
            'Org': api.get('org', '?'),
            'ASN': rdap.get('asn', '?'),
            'ReverseDNS': data.get('reverse_dns') or '—',
            'Lat': api.get('lat'),
            'Lon': api.get('lon'),
        })
    return pd.DataFrame(rows, columns=IP_COLUMNS)
