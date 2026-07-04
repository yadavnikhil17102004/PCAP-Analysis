"""
PCAP Investigation Console — v2
Requirements: streamlit plotly pandas
Run: streamlit run dashboard.py
"""

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard_app.analysis import (
    SEVERITY_COLOR,
    build_ip_df,
    build_query_df,
    detect_beacons,
)
from dashboard_app.exports import export_ioc_csv, export_sigma, export_suricata
from utils.pcap_guard import check_pcap_size


@st.cache_data(show_spinner=False)
def load_data(deep_path: str, enrich_path: str):
    with open(deep_path, encoding="utf-8") as f:
        deep = json.load(f)
    with open(enrich_path, encoding="utf-8") as f:
        enrich = json.load(f)
    return deep, enrich


def _find_candidates(filename: str) -> list[str]:
    base = Path(__file__).resolve().parent
    paths = []
    for folder in [base / "outputs", base.parent / "outputs", base, base.parent]:
        p = folder / filename
        if p.exists():
            paths.append(str(p))
    return list(dict.fromkeys(paths))


def _bundled_example_paths() -> tuple[str, str]:
    root = Path(__file__).resolve().parents[1]
    deep = root / 'outputs' / 'pcap_deeper_results.json'
    enrich = root / 'outputs' / 'ip_enrichment_results.json'
    return str(deep), str(enrich)


def _run_pipeline(pcap_path: str, output_dir: str):
    """Run the analysis pipeline on a PCAP file."""
    base = Path(__file__).resolve().parent.parent
    pipeline_dir = base / "archive" / "pipeline"

    deep_py = pipeline_dir / "pcap_deep_analysis.py"
    enrich_py = pipeline_dir / "ip_enrichment.py"

    deep_json = Path(output_dir) / "pcap_deeper_results.json"
    enrich_json = Path(output_dir) / "ip_enrichment_results.json"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(pipeline_dir) + os.pathsep + env.get("PYTHONPATH", "")

    subprocess.run(
        [sys.executable, str(deep_py), "--pcap", pcap_path, "--out-json", str(deep_json)],
        check=True,
        env=env,
        capture_output=True,
    )
    subprocess.run(
        [sys.executable, str(enrich_py), "--in-json", str(deep_json), "--out-json", str(enrich_json)],
        check=True,
        env=env,
        capture_output=True,
    )
    return str(deep_json), str(enrich_json)


# ─────────────────────────── page sections ───────────────────────────────────

def _metric_card(label: str, value, delta=None, color=None):
    delta_html = f'<div style="font-size:12px;color:{color or "#6b7280"};margin-top:4px">{delta}</div>' if delta else ""
    val_color = color or "var(--text-color)"
    st.markdown(
        f"""
        <div style="
            background:var(--background-color);
            border:1px solid rgba(148,163,184,0.2);
            border-radius:12px;
            padding:16px 20px;
            border-left: 3px solid {color or '#3b82f6'};
        ">
            <div style="font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;font-weight:600">{label}</div>
            <div style="font-size:28px;font-weight:700;color:{val_color};margin-top:4px;font-family:monospace">{value}</div>
            {delta_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _inject_theme():
    st.markdown(
        """
        <style>
        :root {
            --bg: #0b1220;
            --panel: #101827;
            --line: rgba(148, 163, 184, 0.14);
            --muted: #94a3b8;
            --text: #e5eefc;
        }

        [data-testid="stAppViewContainer"] {
            background:
                radial-gradient(circle at top left, rgba(56, 189, 248, 0.08), transparent 30%),
                radial-gradient(circle at top right, rgba(249, 115, 22, 0.06), transparent 28%),
                linear-gradient(180deg, #070d18 0%, #0b1220 100%);
            color: var(--text);
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #07101d 0%, #0b1322 100%);
            border-right: 1px solid rgba(148, 163, 184, 0.12);
        }

        [data-testid="stHeader"], [data-testid="stToolbar"], footer {
            visibility: hidden;
            height: 0;
        }

        .block-container {
            padding-top: 1.2rem;
            padding-bottom: 2rem;
        }

        h1, h2, h3, h4 {
            letter-spacing: -0.02em;
        }

        .console-topbar {
            display:flex;
            justify-content:space-between;
            align-items:center;
            gap:1rem;
            padding: 14px 18px;
            margin: 0 0 1rem 0;
            border: 1px solid var(--line);
            border-radius: 16px;
            background: rgba(16, 24, 39, 0.92);
            box-shadow: 0 10px 30px rgba(0,0,0,0.22);
        }

        .console-kicker {
            color: #7dd3fc;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .18em;
            font-weight: 700;
        }

        .console-title {
            margin: 2px 0 0 0;
            font-size: 30px;
            font-weight: 850;
            color: var(--text);
        }

        .console-subtitle {
            margin: 6px 0 0 0;
            color: var(--muted);
            font-size: 14px;
        }

        .console-pill {
            display:inline-flex;
            align-items:center;
            gap:0.4rem;
            padding: 6px 10px;
            border-radius: 999px;
            background: rgba(56, 189, 248, 0.08);
            border: 1px solid rgba(56, 189, 248, 0.18);
            color: #bfdbfe;
            font-size: 12px;
            font-weight: 700;
            margin-right: 8px;
            margin-top: 8px;
        }

        .alert-card {
            padding: 14px 16px;
            border-radius: 14px;
            background: linear-gradient(180deg, rgba(17, 24, 39, 0.98), rgba(15, 23, 42, 0.96));
            border: 1px solid var(--line);
            border-left: 4px solid #3b82f6;
            margin-bottom: 10px;
            box-shadow: 0 8px 22px rgba(0,0,0,0.18);
        }

        .alert-card .meta {
            color: var(--muted);
            font-size: 12px;
            line-height: 1.5;
        }

        .alert-card .domain {
            font-size: 15px;
            font-weight: 800;
            color: var(--text);
            word-break: break-word;
        }

        .score-badge {
            display:inline-flex;
            align-items:center;
            padding: 3px 8px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: .02em;
        }

        .workspace-dock,
        .status-rail {
            border: 1px solid var(--line);
            border-radius: 16px;
            background: rgba(16, 24, 39, 0.92);
            box-shadow: 0 10px 28px rgba(0,0,0,0.18);
        }

        .workspace-dock {
            padding: 16px 18px 18px 18px;
        }

        .command-center {
            position: sticky;
            top: 0.75rem;
            z-index: 40;
            margin-bottom: 1rem;
            padding: 16px 18px;
            border-radius: 18px;
            border: 1px solid rgba(148, 163, 184, 0.16);
            background: rgba(8, 14, 24, 0.84);
            backdrop-filter: blur(18px);
            box-shadow: 0 18px 36px rgba(0, 0, 0, 0.28);
        }

        .workspace-kicker {
            color: #7dd3fc;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .18em;
            font-weight: 700;
        }

        .workspace-title {
            font-size: 20px;
            font-weight: 850;
            color: var(--text);
            margin-top: 4px;
        }

        .workspace-copy {
            color: var(--muted);
            font-size: 13px;
            margin-top: 6px;
            line-height: 1.5;
        }

        .workspace-note {
            color: #cbd5e1;
            font-size: 12px;
            line-height: 1.6;
        }

        .score-badge {
            display:inline-flex;
            align-items:center;
            padding: 3px 8px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: .02em;
        }

        div[data-testid="stDataFrame"] {
            border: 1px solid var(--line);
            border-radius: 14px;
            overflow: hidden;
            background: rgba(16, 24, 39, 0.75);
        }

        div[data-testid="stMetric"] {
            background: rgba(16, 24, 39, 0.92);
            border: 1px solid var(--line);
            border-radius: 14px;
            padding: 12px 14px;
        }

        div[data-baseweb="tab-list"] {
            overflow-x: auto;
            scrollbar-width: thin;
            -webkit-overflow-scrolling: touch;
        }

        div[data-baseweb="tab-list"] button {
            white-space: nowrap;
            flex-shrink: 0;
        }

        @media (max-width: 960px) {
            .block-container {
                padding-top: 0.85rem;
                padding-bottom: 1rem;
            }

            .command-center {
                position: static;
                top: auto;
                padding: 14px;
                margin-bottom: 0.75rem;
            }

            .console-title {
                font-size: 24px;
            }

            .console-subtitle {
                font-size: 13px;
            }

            .workspace-dock,
            .status-rail,
            .alert-card {
                border-radius: 14px;
            }

            .workspace-dock,
            .status-rail {
                padding: 12px;
            }

            div[data-testid="stHorizontalBlock"] {
                gap: 0.65rem;
            }

            div[data-testid="column"] {
                width: 100% !important;
                flex: 1 1 100% !important;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _risk_context(deep: dict, query_df: pd.DataFrame, beacon_df: pd.DataFrame, ip_df: pd.DataFrame):
    suspicious_slds = deep.get("suspicious_slds", {}) or {}
    critical = int((query_df["severity"] == "CRITICAL").sum()) if not query_df.empty else 0
    high = int((query_df["severity"] == "HIGH").sum()) if not query_df.empty else 0
    beacons = int(beacon_df["beacon"].sum()) if not beacon_df.empty else 0
    ru_ips = int((ip_df["CountryCode"] == "RU").sum()) if not ip_df.empty else 0
    unique_sources = int(query_df["src"].nunique()) if not query_df.empty else 0
    rare_domains = int((query_df.groupby("sld").size() <= 1).sum()) if not query_df.empty else 0

    risk = 15 + critical * 18 + high * 9 + beacons * 16 + len(suspicious_slds) * 12 + ru_ips * 5
    risk = min(risk, 100)

    if risk >= 75 or critical or beacons:
        verdict, color, icon = "MALICIOUS", "#ef4444", "🔴"
    elif risk >= 45 or high:
        verdict, color, icon = "SUSPICIOUS", "#f97316", "🟠"
    else:
        verdict, color, icon = "REVIEW", "#eab308", "🟡"

    if query_df.empty:
        narrative = "No DNS queries available for triage."
    else:
        top = query_df.sort_values("dga_score", ascending=False).iloc[0]
        narrative_bits = [
            f"Top signal: {top['sld']} ({top['severity']}, {top['dga_score']:.2f})",
            f"{unique_sources} source IPs",
        ]
        if beacons:
            narrative_bits.append(f"{beacons} beacon-like pair{'s' if beacons != 1 else ''}")
        if suspicious_slds:
            narrative_bits.append(f"{len(suspicious_slds)} pipeline-suspicious domain{'s' if len(suspicious_slds) != 1 else ''}")
        if ru_ips:
            narrative_bits.append(f"{ru_ips} RU-hosted IP{'s' if ru_ips != 1 else ''}")
        narrative = " · ".join(narrative_bits)

    primary_host = "—"
    if not query_df.empty:
        if "dga_score" in query_df.columns:
            primary_host = str(query_df.sort_values("dga_score", ascending=False).iloc[0]["src"])
        else:
            primary_host = str(query_df.iloc[0]["src"])

    contributors = [
        f"DGA behavior +{critical * 18 + high * 9}" if (critical or high) else "DGA behavior +0",
        f"Suspicious infrastructure +{len(suspicious_slds) * 12 + beacons * 16}" if (suspicious_slds or beacons) else "Suspicious infrastructure +0",
        f"Rare domains +{rare_domains * 4}" if rare_domains else "Rare domains +0",
    ]

    return {
        "risk": risk,
        "verdict": verdict,
        "color": color,
        "icon": icon,
        "narrative": narrative,
        "critical": critical,
        "high": high,
        "beacons": beacons,
        "ru_ips": ru_ips,
        "suspicious_slds": suspicious_slds,
        "unique_sources": unique_sources,
        "rare_domains": rare_domains,
        "primary_host": primary_host,
        "contributors": contributors,
    }


def _risk_gauge(risk: int, color: str):
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=risk,
            number={"font": {"color": color, "size": 30}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#475569"},
                "bar": {"color": color},
                "bgcolor": "rgba(0,0,0,0)",
                "steps": [
                    {"range": [0, 35], "color": "rgba(34,197,94,0.22)"},
                    {"range": [35, 65], "color": "rgba(234,179,8,0.24)"},
                    {"range": [65, 100], "color": "rgba(239,68,68,0.24)"},
                ],
            },
            title={"text": "Risk Index"},
        )
    )
    fig.update_layout(
        margin=dict(l=10, r=10, t=36, b=10),
        height=220,
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#cbd5e1"),
    )
    return fig


def section_alert_queue(query_df: pd.DataFrame, beacon_df: pd.DataFrame, suspicious_slds: dict, limit: int = 6):
    st.markdown("#### Triage Queue")
    if query_df.empty:
        st.info("No DNS queries loaded.")
        return

    merged = query_df.copy()
    beacon_lookup = set()
    if not beacon_df.empty and {"src", "sld", "beacon"}.issubset(beacon_df.columns):
        beacon_lookup = set((r.src, r.sld) for r in beacon_df[beacon_df["beacon"]].itertuples(index=False))

    merged["beacon"] = merged.apply(lambda r: (r["src"], r["sld"]) in beacon_lookup, axis=1)
    merged["why"] = merged.apply(
        lambda r: ", ".join(
            [
                reason for reason in [
                    "high entropy" if r["dga_score"] >= 0.70 else ("DGA-like" if r["dga_score"] >= 0.50 else None),
                    "beaconing" if r["beacon"] else None,
                    "pipeline-suspicious" if r["sld"] in suspicious_slds else None,
                ]
                if reason
            ]
        ) or "review",
        axis=1,
    )
    merged["rank"] = merged["dga_score"] + merged["beacon"].astype(int) * 0.25
    merged = merged.sort_values(["rank", "dga_score"], ascending=False).head(limit)

    cols = st.columns(2)
    cards = merged.to_dict("records")
    for idx, row in enumerate(cards):
        with cols[idx % 2]:
            sev = row["severity"]
            color = SEVERITY_COLOR.get(sev, "#64748b")
            badge_bg = f"{color}22"
            beacon_flag = " · beacon" if row["beacon"] else ""
            st.markdown(
                f"""
                <div class="alert-card" style="border-left-color:{color}">
                    <div style="display:flex; justify-content:space-between; gap:1rem; align-items:flex-start;">
                        <div>
                            <div class="domain">{row['qname']}</div>
                            <div class="meta">{row['src']} → {row['dst']} · {row['sld']}{beacon_flag}</div>
                        </div>
                        <div class="score-badge" style="background:{badge_bg}; color:{color};">{sev} · {row['dga_score']:.3f}</div>
                    </div>
                    <div class="meta" style="margin-top:10px">{row['why']}</div>
                    <div class="meta" style="margin-top:4px">{row['time']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )



def _fmt_dt(value) -> str:
    if value is None or value is pd.NaT:
        return '—'
    if hasattr(value, 'strftime'):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    try:
        return pd.to_datetime(value).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(value)


def _fmt_clock(value) -> str:
    if value is None or value is pd.NaT:
        return '—'
    try:
        return pd.to_datetime(value).strftime('%H:%M:%S')
    except Exception:
        return str(value)


def _qtype_name(value) -> str:
    return {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}.get(int(value), str(value)) if value is not None else '—'


def _analysis_timestamp(query_df: pd.DataFrame) -> str:
    if query_df.empty:
        return _fmt_dt(datetime.utcnow())
    return _fmt_dt(query_df['time'].max())


def _build_lookup_maps(deep: dict):
    qtype_map = {}
    answer_map = {}
    for record in deep.get('dns', []):
        qname = record.get('qname', '')
        if qname and record.get('qr') == 0 and qname not in qtype_map:
            qtype_map[qname] = record.get('qtype')
        if qname and record.get('qr') == 1:
            answers = []
            for ans in record.get('answers', []):
                ip = ans.get('rdata')
                if ip:
                    answers.append(ip)
            if answers:
                answer_map.setdefault(qname, [])
                for ip in answers:
                    if ip not in answer_map[qname]:
                        answer_map[qname].append(ip)
    return qtype_map, answer_map


def _derive_technique(row, beacon_pairs: set[tuple[str, str]] | None = None) -> str:
    beacon_pairs = beacon_pairs or set()
    pair = (row['src'], row['sld'])
    if pair in beacon_pairs:
        return 'T1071.004'
    if row['dga_score'] >= 0.70 or row['label_ent'] >= 3.0:
        return 'T1568.002'
    return 'T1071.004'


def _risk_badge(score: float) -> tuple[str, str]:
    if score >= 0.70:
        return 'CRITICAL', '#ef4444'
    if score >= 0.50:
        return 'HIGH', '#f97316'
    if score >= 0.30:
        return 'MEDIUM', '#eab308'
    return 'LOW', '#22c55e'


def _queue_reasons(row, domain_count: int, answer_map: dict[str, list[str]], ip_df: pd.DataFrame, beacon_pairs: set[tuple[str, str]]):
    reasons = []
    if row['dga_score'] >= 0.55:
        reasons.append('High entropy')
    if row['label_ent'] >= 2.8:
        reasons.append('Random label pattern')
    if domain_count <= 1:
        reasons.append('Rare domain')
    if row['dst'] in set(ip_df.get('IP', [])):
        country = ip_df.loc[ip_df['IP'] == row['dst'], 'CountryCode'].head(1)
        if not country.empty:
            reasons.append(f'Suspicious hosting ({country.iloc[0]})')
    if (row['src'], row['sld']) in beacon_pairs:
        reasons.append('Beacon-like cadence')
    if answer_map.get(row['qname']):
        reasons.append('Resolved infrastructure')
    return reasons or ['Suspicious DNS pattern']


def _build_event_rows(query_df: pd.DataFrame, beacon_df: pd.DataFrame, answer_map: dict[str, list[str]]):
    events = []
    domain_counts = query_df.groupby('sld').size().to_dict() if not query_df.empty else {}
    beacon_pairs = set()
    if not beacon_df.empty:
        for _, b in beacon_df.iterrows():
            if bool(b.get('beacon')):
                beacon_pairs.add((b['src'], b['sld']))
    for _, row in query_df.sort_values('time').iterrows():
        severity = row['severity']
        title = 'DGA domain generated' if row['dga_score'] >= 0.55 else 'Possible C2 lookup'
        if (row['src'], row['sld']) in beacon_pairs:
            title = 'Beacon-like periodic query'
        events.append({
            'time': row['time'],
            'clock': _fmt_clock(row['time']),
            'severity': severity,
            'title': title,
            'host': row['src'],
            'domain': row['qname'],
            'reason': ', '.join(_queue_reasons(row, domain_counts.get(row['sld'], 0), answer_map, pd.DataFrame(), beacon_pairs)[:3]),
        })
    return events[:20]


def _build_domain_intel(query_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None = None):
    if query_df.empty:
        return pd.DataFrame()
    domain_stats = []
    domain_counts = query_df.groupby('sld').size().to_dict()
    for sld, grp in query_df.groupby('sld'):
        domains = grp['qname'].tolist()
        qname = grp.sort_values('dga_score', ascending=False).iloc[0]['qname']
        ips = sorted(set(ip for domain in domains for ip in answer_map.get(domain, [])))
        ip_meta = ip_df[ip_df['IP'].isin(ips)] if not ip_df.empty and ips else pd.DataFrame()
        countries = sorted(set(ip_meta['Country'].dropna().tolist())) if not ip_meta.empty else []
        asn = ', '.join(sorted(set(ip_meta['ASN'].dropna().astype(str).tolist()))) if not ip_meta.empty else '—'
        domain_stats.append({
            'sld': sld,
            'focus': sld == focus_domain,
            'domain': qname,
            'risk': 'HIGH' if grp['dga_score'].max() >= 0.50 else 'MEDIUM',
            'dga_probability': round(grp['dga_score'].max() * 100, 0),
            'entropy': round(grp['label_ent'].max(), 3),
            'first_seen': grp['time'].min(),
            'last_seen': grp['time'].max(),
            'queries': int(domain_counts.get(sld, 0)),
            'sources': ', '.join(sorted(set(grp['src'].tolist()))),
            'ips': ', '.join(ips) if ips else '—',
            'countries': ', '.join(countries) if countries else '—',
            'asn': asn,
            'reasoning': 'Domain contains algorithmically generated labels' if grp['dga_score'].max() >= 0.55 else 'Suspicious DNS behavior under review',
            'score': grp['dga_score'].max(),
        })
    df = pd.DataFrame(domain_stats).sort_values(['focus', 'score', 'queries'], ascending=[False, False, False])
    if focus_domain:
        return df
    return df.head(8)


def _build_forensic_df(query_df: pd.DataFrame, deep: dict, beacon_df: pd.DataFrame):
    if query_df.empty:
        return pd.DataFrame()
    qtype_map, _ = _build_lookup_maps(deep)
    beacon_pairs = set()
    if not beacon_df.empty:
        for _, b in beacon_df.iterrows():
            if bool(b.get('beacon')):
                beacon_pairs.add((b['src'], b['sld']))
    rows = []
    for _, row in query_df.sort_values('time').iterrows():
        rows.append({
            'Time': _fmt_dt(row['time']),
            'Source': row['src'],
            'Destination': row['dst'],
            'Query': row['qname'],
            'Record Type': _qtype_name(qtype_map.get(row['qname'], row.get('qtype', 1))),
            'Entropy': round(row['label_ent'], 3),
            'Risk': round(row['dga_score'], 3),
            'MITRE Technique': _derive_technique(row, beacon_pairs),
            'Severity': row['severity'],
            'SLD': row['sld'],
        })
    return pd.DataFrame(rows)


def _build_network_graph(query_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None):
    if query_df.empty:
        return go.Figure()

    top_hosts = query_df.groupby('src').size().sort_values(ascending=False).head(3).index.tolist()
    domain_counts = query_df.groupby('sld').size().sort_values(ascending=False)
    focus_domain = focus_domain or domain_counts.index[0]
    focus_group = query_df[query_df['sld'] == focus_domain].sort_values('dga_score', ascending=False)
    focus_host = focus_group.iloc[0]['src'] if not focus_group.empty else top_hosts[0]
    focus_domains = focus_group['qname'].head(4).tolist()
    if not focus_domains:
        focus_domains = query_df.sort_values('dga_score', ascending=False)['qname'].head(4).tolist()

    nodes = []
    edges = []

    # x, y layered layout
    pos = {}
    y_positions = [0.7, 0.25, -0.25, -0.7]
    pos[f'host::{focus_host}'] = (0.0, 0.0)
    nodes.append(('Internal host', focus_host, 0.0, 0.0, '#3b82f6', 'Blue = internal asset'))

    for idx, domain in enumerate(focus_domains[:4]):
        y = y_positions[idx % len(y_positions)]
        key = f'domain::{domain}'
        pos[key] = (1.4, y)
        nodes.append(('Suspicious domain', domain, 1.4, y, '#f97316', 'Orange = suspicious domain'))
        edges.append((f'host::{focus_host}', key))
        for ip in answer_map.get(domain, [])[:2]:
            ip_key = f'ip::{ip}'
            if ip_key not in pos:
                ip_meta = ip_df[ip_df['IP'] == ip]
                country = ip_meta['Country'].iloc[0] if not ip_meta.empty else 'Unknown'
                pos[ip_key] = (2.8, y)
                nodes.append(('Resolved IP', f'{ip}\n{country}', 2.8, y, '#ef4444', 'Red = high-risk infrastructure'))
            edges.append((key, ip_key))
            ip_meta = ip_df[ip_df['IP'] == ip]
            if not ip_meta.empty:
                country_label = ip_meta['Country'].iloc[0]
                asn = str(ip_meta['ASN'].iloc[0])
                geo_key = f'geo::{ip}::{country_label}'
                if geo_key not in pos:
                    pos[geo_key] = (4.2, y)
                    nodes.append(('Country / ASN', f'{country_label}\nASN {asn}', 4.2, y, '#94a3b8', 'Geo / ASN enrichment'))
                edges.append((ip_key, geo_key))

    fig = go.Figure()
    for left, right in edges:
        x0, y0 = pos[left]
        x1, y1 = pos[right]
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1],
            mode='lines',
            line=dict(color='rgba(148,163,184,0.35)', width=1.5),
            hoverinfo='skip',
            showlegend=False,
        ))

    for kind, label, x, y, color, note in nodes:
        fig.add_trace(go.Scatter(
            x=[x], y=[y],
            mode='markers+text',
            text=[label],
            textposition='bottom center',
            textfont=dict(color='#e5eefc', size=11),
            marker=dict(size=22 if kind == 'Internal host' else 18, color=color, line=dict(color='white', width=1)),
            name=kind,
            hovertemplate=f'{kind}<br>%{{text}}<extra>{note}</extra>',
            showlegend=False,
        ))

    fig.update_layout(
        title='',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        height=360,
        margin=dict(l=0, r=0, t=10, b=0),
        font=dict(color='#e5eefc'),
    )
    return fig


def _build_report_package(deep: dict, query_df: pd.DataFrame, beacon_df: pd.DataFrame, ip_df: pd.DataFrame, risk_ctx: dict, focus_domain: str | None, answer_map: dict[str, list[str]]):
    suspicious = risk_ctx.get('suspicious_slds', {}) or {}
    affected_hosts = sorted(set(query_df['src'].tolist())) if not query_df.empty else []
    techniques = []
    if not query_df.empty:
        if (query_df['severity'] == 'CRITICAL').any() or (query_df['dga_score'] >= 0.70).any():
            techniques.append('T1568.002 - Domain Generation Algorithm')
        techniques.append('T1071.004 - DNS')
    if not beacon_df.empty and beacon_df['beacon'].any():
        techniques.append('Beaconing / periodic DNS activity')
    indicators = []
    for sld, details in list(suspicious.items())[:6]:
        indicators.append(sld)
    domains = list(dict.fromkeys(query_df.sort_values('dga_score', ascending=False)['qname'].head(8).tolist())) if not query_df.empty else []
    ips = list(dict.fromkeys([ip for dom in domains for ip in answer_map.get(dom, [])]))

    summary = (
        f"Analysis identified suspicious DNS behavior originating from {affected_hosts[0] if affected_hosts else 'an unknown host'}. "
        f"Multiple high entropy domains indicate possible malware using DGA-based command and control communication."
    )
    indicator_lines = [f'- {i}' for i in indicators] if indicators else ['- None identified']
    host_lines = [f'- {h}' for h in affected_hosts[:10]] if affected_hosts else ['- None identified']
    technique_lines = [f'- {t}' for t in techniques] if techniques else ['- None identified']

    txt = '\n'.join([
        'PCAP Threat Intelligence Console - Investigation Report',
        f'Verdict: {risk_ctx["verdict"]} ({risk_ctx["risk"]}/100)',
        f'Confidence: {"HIGH" if risk_ctx["risk"] >= 50 else "MEDIUM"}',
        '',
        'Attack summary:',
        summary,
        '',
        'Indicators:',
        *indicator_lines,
        '',
        'Affected hosts:',
        *host_lines,
        '',
        'MITRE techniques:',
        *technique_lines,
        '',
        'Recommended actions:',
        '- Isolate the affected host and preserve volatile evidence.',
        '- Block suspicious domains and resolved IPs at DNS / proxy layers.',
        '- Hunt across the environment for the listed domains, IPs, and techniques.',
        '- Review endpoint telemetry for persistence or execution tied to this DNS activity.',
    ])

    stix_objects = [
        {
            'type': 'identity',
            'spec_version': '2.1',
            'id': 'identity--11111111-1111-4111-8111-111111111111',
            'created': _analysis_timestamp(query_df),
            'modified': _analysis_timestamp(query_df),
            'name': 'PCAP Threat Intelligence Console',
            'identity_class': 'organization',
        }
    ]
    for dom in indicators[:8]:
        stix_objects.append({
            'type': 'indicator',
            'spec_version': '2.1',
            'id': f'indicator--{abs(hash(dom)) & ((1 << 64) - 1):016x}',
            'created': _analysis_timestamp(query_df),
            'modified': _analysis_timestamp(query_df),
            'name': dom,
            'pattern': f"[domain-name:value = '{dom}']",
            'pattern_type': 'stix',
            'valid_from': _analysis_timestamp(query_df),
        })
    for ip in ips[:8]:
        stix_objects.append({
            'type': 'indicator',
            'spec_version': '2.1',
            'id': f'indicator--{abs(hash(ip)) & ((1 << 64) - 1):016x}',
            'created': _analysis_timestamp(query_df),
            'modified': _analysis_timestamp(query_df),
            'name': ip,
            'pattern': f"[ipv4-addr:value = '{ip}']",
            'pattern_type': 'stix',
            'valid_from': _analysis_timestamp(query_df),
        })

    return {
        'summary': summary,
        'txt': txt,
        'json': json.dumps({
            'verdict': risk_ctx['verdict'],
            'risk_score': risk_ctx['risk'],
            'confidence': 'HIGH' if risk_ctx['risk'] >= 50 else 'MEDIUM',
            'summary': summary,
            'affected_hosts': affected_hosts,
            'indicators': indicators,
            'domains': domains,
            'ips': ips,
            'mitre_techniques': techniques,
        }, indent=2, default=str),
        'stix': json.dumps({'type': 'bundle', 'id': 'bundle--11111111-1111-4111-8111-111111111111', 'objects': stix_objects}, indent=2),
        'domains': domains,
        'ips': ips,
        'affected_hosts': affected_hosts,
        'techniques': techniques,
        'indicators': indicators,
    }




def _fmt_dt(value) -> str:
    if value is None or value is pd.NaT:
        return '—'
    if hasattr(value, 'strftime'):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    try:
        return pd.to_datetime(value).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(value)


def _fmt_clock(value) -> str:
    if value is None or value is pd.NaT:
        return '—'
    try:
        return pd.to_datetime(value).strftime('%H:%M:%S')
    except Exception:
        return str(value)


def _qtype_name(value) -> str:
    return {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}.get(int(value), str(value)) if value is not None else '—'


def _analysis_timestamp(query_df: pd.DataFrame) -> str:
    if query_df.empty:
        return _fmt_dt(datetime.utcnow())
    return _fmt_dt(query_df['time'].max())


def _build_lookup_maps(deep: dict):
    qtype_map = {}
    answer_map = {}
    for record in deep.get('dns', []):
        qname = record.get('qname', '')
        if qname and record.get('qr') == 0 and qname not in qtype_map:
            qtype_map[qname] = record.get('qtype')
        if qname and record.get('qr') == 1:
            answers = []
            for ans in record.get('answers', []):
                ip = ans.get('rdata')
                if ip:
                    answers.append(ip)
            if answers:
                answer_map.setdefault(qname, [])
                for ip in answers:
                    if ip not in answer_map[qname]:
                        answer_map[qname].append(ip)
    return qtype_map, answer_map


def _derive_technique(row, beacon_pairs: set[tuple[str, str]] | None = None) -> str:
    beacon_pairs = beacon_pairs or set()
    pair = (row['src'], row['sld'])
    if pair in beacon_pairs:
        return 'T1071.004'
    if row['dga_score'] >= 0.70 or row['label_ent'] >= 3.0:
        return 'T1568.002'
    return 'T1071.004'


def _risk_badge(score: float) -> tuple[str, str]:
    if score >= 0.70:
        return 'CRITICAL', '#ef4444'
    if score >= 0.50:
        return 'HIGH', '#f97316'
    if score >= 0.30:
        return 'MEDIUM', '#eab308'
    return 'LOW', '#22c55e'


def _queue_reasons(row, domain_count: int, answer_map: dict[str, list[str]], ip_df: pd.DataFrame, beacon_pairs: set[tuple[str, str]]):
    reasons = []
    if row['dga_score'] >= 0.55:
        reasons.append('High entropy')
    if row['label_ent'] >= 2.8:
        reasons.append('Random label pattern')
    if domain_count <= 1:
        reasons.append('Rare domain')
    if not ip_df.empty and row['dst'] in set(ip_df.get('IP', [])):
        country = ip_df.loc[ip_df['IP'] == row['dst'], 'CountryCode'].head(1)
        if not country.empty:
            reasons.append(f'Suspicious hosting ({country.iloc[0]})')
    if (row['src'], row['sld']) in beacon_pairs:
        reasons.append('Beacon-like cadence')
    if answer_map.get(row['qname']):
        reasons.append('Resolved infrastructure')
    return reasons or ['Suspicious DNS pattern']


def _build_event_rows(query_df: pd.DataFrame, beacon_df: pd.DataFrame, answer_map: dict[str, list[str]], ip_df: pd.DataFrame):
    events = []
    domain_counts = query_df.groupby('sld').size().to_dict() if not query_df.empty else {}
    beacon_pairs = set()
    if not beacon_df.empty:
        for _, b in beacon_df.iterrows():
            if bool(b.get('beacon')):
                beacon_pairs.add((b['src'], b['sld']))
    for _, row in query_df.sort_values('time').iterrows():
        severity = row['severity']
        title = 'DGA domain generated' if row['dga_score'] >= 0.55 else 'Possible C2 lookup'
        if (row['src'], row['sld']) in beacon_pairs:
            title = 'Beacon-like periodic query'
        events.append({
            'time': row['time'],
            'clock': _fmt_clock(row['time']),
            'severity': severity,
            'title': title,
            'host': row['src'],
            'domain': row['qname'],
            'reason': ', '.join(_queue_reasons(row, domain_counts.get(row['sld'], 0), answer_map, ip_df, beacon_pairs)[:3]),
        })
    return events[:20]


def _build_domain_intel(query_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None = None):
    if query_df.empty:
        return pd.DataFrame()
    domain_stats = []
    domain_counts = query_df.groupby('sld').size().to_dict()
    for sld, grp in query_df.groupby('sld'):
        domains = grp['qname'].tolist()
        qname = grp.sort_values('dga_score', ascending=False).iloc[0]['qname']
        ips = sorted(set(ip for domain in domains for ip in answer_map.get(domain, [])))
        ip_meta = ip_df[ip_df['IP'].isin(ips)] if not ip_df.empty and ips else pd.DataFrame()
        countries = sorted(set(ip_meta['Country'].dropna().tolist())) if not ip_meta.empty else []
        asn = ', '.join(sorted(set(ip_meta['ASN'].dropna().astype(str).tolist()))) if not ip_meta.empty else '—'
        domain_stats.append({
            'sld': sld,
            'focus': sld == focus_domain,
            'domain': qname,
            'risk': 'HIGH' if grp['dga_score'].max() >= 0.50 else 'MEDIUM',
            'dga_probability': round(grp['dga_score'].max() * 100, 0),
            'entropy': round(grp['label_ent'].max(), 3),
            'first_seen': grp['time'].min(),
            'last_seen': grp['time'].max(),
            'queries': int(domain_counts.get(sld, 0)),
            'sources': ', '.join(sorted(set(grp['src'].tolist()))),
            'ips': ', '.join(ips) if ips else '—',
            'countries': ', '.join(countries) if countries else '—',
            'asn': asn,
            'reasoning': 'Domain contains algorithmically generated labels' if grp['dga_score'].max() >= 0.55 else 'Suspicious DNS behavior under review',
            'score': grp['dga_score'].max(),
        })
    df = pd.DataFrame(domain_stats).sort_values(['focus', 'score', 'queries'], ascending=[False, False, False])
    if focus_domain:
        return df
    return df.head(8)


def _build_forensic_df(query_df: pd.DataFrame, deep: dict, beacon_df: pd.DataFrame):
    if query_df.empty:
        return pd.DataFrame()
    qtype_map, _ = _build_lookup_maps(deep)
    beacon_pairs = set()
    if not beacon_df.empty:
        for _, b in beacon_df.iterrows():
            if bool(b.get('beacon')):
                beacon_pairs.add((b['src'], b['sld']))
    rows = []
    for _, row in query_df.sort_values('time').iterrows():
        rows.append({
            'Time': _fmt_dt(row['time']),
            'Source': row['src'],
            'Destination': row['dst'],
            'Query': row['qname'],
            'Record Type': _qtype_name(qtype_map.get(row['qname'], row.get('qtype', 1))),
            'Entropy': round(row['label_ent'], 3),
            'Risk': round(row['dga_score'], 3),
            'MITRE Technique': _derive_technique(row, beacon_pairs),
            'Severity': row['severity'],
            'SLD': row['sld'],
        })
    return pd.DataFrame(rows)


def _build_network_graph(query_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None):
    if query_df.empty:
        return go.Figure()

    top_hosts = query_df.groupby('src').size().sort_values(ascending=False).head(3).index.tolist()
    domain_counts = query_df.groupby('sld').size().sort_values(ascending=False)
    focus_domain = focus_domain or domain_counts.index[0]
    focus_group = query_df[query_df['sld'] == focus_domain].sort_values('dga_score', ascending=False)
    focus_host = focus_group.iloc[0]['src'] if not focus_group.empty else top_hosts[0]
    focus_domains = focus_group['qname'].head(4).tolist()
    if not focus_domains:
        focus_domains = query_df.sort_values('dga_score', ascending=False)['qname'].head(4).tolist()

    nodes = []
    edges = []
    pos = {}
    y_positions = [0.7, 0.25, -0.25, -0.7]
    pos[f'host::{focus_host}'] = (0.0, 0.0)
    nodes.append(('Internal host', focus_host, 0.0, 0.0, '#3b82f6', 'Blue = internal asset'))

    for idx, domain in enumerate(focus_domains[:4]):
        y = y_positions[idx % len(y_positions)]
        key = f'domain::{domain}'
        pos[key] = (1.4, y)
        nodes.append(('Suspicious domain', domain, 1.4, y, '#f97316', 'Orange = suspicious domain'))
        edges.append((f'host::{focus_host}', key))
        for ip in answer_map.get(domain, [])[:2]:
            ip_key = f'ip::{ip}'
            if ip_key not in pos:
                ip_meta = ip_df[ip_df['IP'] == ip]
                country = ip_meta['Country'].iloc[0] if not ip_meta.empty else 'Unknown'
                pos[ip_key] = (2.8, y)
                nodes.append(('Resolved IP', f'{ip}\n{country}', 2.8, y, '#ef4444', 'Red = high-risk infrastructure'))
            edges.append((key, ip_key))
            ip_meta = ip_df[ip_df['IP'] == ip]
            if not ip_meta.empty:
                country_label = ip_meta['Country'].iloc[0]
                asn = str(ip_meta['ASN'].iloc[0])
                geo_key = f'geo::{ip}::{country_label}'
                if geo_key not in pos:
                    pos[geo_key] = (4.2, y)
                    nodes.append(('Country / ASN', f'{country_label}\nASN {asn}', 4.2, y, '#94a3b8', 'Geo / ASN enrichment'))
                edges.append((ip_key, geo_key))

    fig = go.Figure()
    for left, right in edges:
        x0, y0 = pos[left]
        x1, y1 = pos[right]
        fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode='lines', line=dict(color='rgba(148,163,184,0.35)', width=1.5), hoverinfo='skip', showlegend=False))

    for kind, label, x, y, color, note in nodes:
        fig.add_trace(go.Scatter(
            x=[x], y=[y],
            mode='markers+text',
            text=[label],
            textposition='bottom center',
            textfont=dict(color='#e5eefc', size=11),
            marker=dict(size=22 if kind == 'Internal host' else 18, color=color, line=dict(color='white', width=1)),
            name=kind,
            hovertemplate=f'{kind}<br>%{{text}}<extra>{note}</extra>',
            showlegend=False,
        ))

    fig.update_layout(title='', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', xaxis=dict(visible=False), yaxis=dict(visible=False), height=360, margin=dict(l=0, r=0, t=10, b=0), font=dict(color='#e5eefc'))
    return fig


def _build_report_package(deep: dict, query_df: pd.DataFrame, beacon_df: pd.DataFrame, ip_df: pd.DataFrame, risk_ctx: dict, focus_domain: str | None, answer_map: dict[str, list[str]]):
    suspicious = risk_ctx.get('suspicious_slds', {}) or {}
    affected_hosts = sorted(set(query_df['src'].tolist())) if not query_df.empty else []
    techniques = []
    if not query_df.empty:
        if (query_df['severity'] == 'CRITICAL').any() or (query_df['dga_score'] >= 0.70).any():
            techniques.append('T1568.002 - Domain Generation Algorithm')
        techniques.append('T1071.004 - DNS')
    if not beacon_df.empty and beacon_df['beacon'].any():
        techniques.append('Beaconing / periodic DNS activity')
    indicators = []
    for sld in list(suspicious.keys())[:6]:
        indicators.append(sld)
    domains = list(dict.fromkeys(query_df.sort_values('dga_score', ascending=False)['qname'].head(8).tolist())) if not query_df.empty else []
    ips = list(dict.fromkeys([ip for dom in domains for ip in answer_map.get(dom, [])]))

    summary = (
        f"Analysis identified suspicious DNS behavior originating from {affected_hosts[0] if affected_hosts else 'an unknown host'}. "
        f"Multiple high entropy domains indicate possible malware using DGA-based command and control communication."
    )
    txt = '\n'.join([
        'PCAP Threat Intelligence Console - Investigation Report',
        f'Verdict: {risk_ctx["verdict"]} ({risk_ctx["risk"]}/100)',
        f'Confidence: {"HIGH" if risk_ctx["risk"] >= 50 else "MEDIUM"}',
        '',
        'Attack summary:',
        summary,
        '',
        'Indicators:',
        *([f'- {i}' for i in indicators] if indicators else ['- None identified']),
        '',
        'Affected hosts:',
        *([f'- {h}' for h in affected_hosts[:10]] if affected_hosts else ['- None identified']),
        '',
        'MITRE techniques:',
        *([f'- {t}' for t in techniques] if techniques else ['- None identified']),
        '',
        'Recommended actions:',
        '- Isolate the affected host and preserve volatile evidence.',
        '- Block suspicious domains and resolved IPs at DNS / proxy layers.',
        '- Hunt across the environment for the listed domains, IPs, and techniques.',
        '- Review endpoint telemetry for persistence or execution tied to this DNS activity.',
    ])

    stix_objects = [
        {
            'type': 'identity',
            'spec_version': '2.1',
            'id': 'identity--11111111-1111-4111-8111-111111111111',
            'created': _analysis_timestamp(query_df),
            'modified': _analysis_timestamp(query_df),
            'name': 'PCAP Threat Intelligence Console',
            'identity_class': 'organization',
        }
    ]
    for dom in indicators[:8]:
        stix_objects.append({
            'type': 'indicator',
            'spec_version': '2.1',
            'id': f'indicator--{abs(hash(dom)) & ((1 << 64) - 1):016x}',
            'created': _analysis_timestamp(query_df),
            'modified': _analysis_timestamp(query_df),
            'name': dom,
            'pattern': f"[domain-name:value = '{dom}']",
            'pattern_type': 'stix',
            'valid_from': _analysis_timestamp(query_df),
        })
    for ip in ips[:8]:
        stix_objects.append({
            'type': 'indicator',
            'spec_version': '2.1',
            'id': f'indicator--{abs(hash(ip)) & ((1 << 64) - 1):016x}',
            'created': _analysis_timestamp(query_df),
            'modified': _analysis_timestamp(query_df),
            'name': ip,
            'pattern': f"[ipv4-addr:value = '{ip}']",
            'pattern_type': 'stix',
            'valid_from': _analysis_timestamp(query_df),
        })

    return {
        'summary': summary,
        'txt': txt,
        'json': json.dumps({
            'verdict': risk_ctx['verdict'],
            'risk_score': risk_ctx['risk'],
            'confidence': 'HIGH' if risk_ctx['risk'] >= 50 else 'MEDIUM',
            'summary': summary,
            'affected_hosts': affected_hosts,
            'indicators': indicators,
            'domains': domains,
            'ips': ips,
            'mitre_techniques': techniques,
        }, indent=2, default=str),
        'stix': json.dumps({'type': 'bundle', 'id': 'bundle--11111111-1111-4111-8111-111111111111', 'objects': stix_objects}, indent=2),
        'domains': domains,
        'ips': ips,
        'affected_hosts': affected_hosts,
        'techniques': techniques,
        'indicators': indicators,
    }


def section_setup() -> tuple[bool, str, str]:
    st.markdown(
        """
        <div class="workspace-dock">
            <div class="workspace-kicker">Workspace dock</div>
            <div class="workspace-title">Ingest a capture or point at existing outputs</div>
            <div class="workspace-copy">The dashboard now behaves like an analyst workstation. Pick one input path and start triage.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    mode = st.radio('Load mode', ['Demo example', 'Auto-detect', 'Upload PCAP', 'Custom paths'], horizontal=True)
    left, right = st.columns([1.35, 0.95], vertical_alignment='top')

    dp = ''
    ep = ''
    clicked = False

    with left:
        if mode == 'Demo example':
            dp, ep = _bundled_example_paths()
            st.success('Bundled demo data selected. This is the fastest way to see the dashboard.')
            st.caption('Uses the committed sample outputs in /outputs so the app works even on fresh deployments.')
            clicked = st.button('Load demo', type='primary', use_container_width=True)
        elif mode == 'Auto-detect':
            d_opts = _find_candidates('pcap_deeper_results.json')
            e_opts = _find_candidates('ip_enrichment_results.json')
            dp = st.selectbox('Analysis JSON', d_opts or [str(Path(_bundled_example_paths()[0]))])
            ep = st.selectbox('Enrichment JSON', e_opts or [str(Path(_bundled_example_paths()[1]))])
            clicked = st.button('Start triage', type='primary', use_container_width=True)
        elif mode == 'Upload PCAP':
            uploaded = st.file_uploader('Select .pcap file', type=['pcap', 'pcapng'])
            clicked = st.button('Process & Load', type='primary', use_container_width=True)
            if clicked and uploaded:
                is_safe, size_mb, message = check_pcap_size(uploaded)
                if not is_safe:
                    st.error(message)
                    clicked = False
                else:
                    st.caption(message)
                    with st.spinner('Processing PCAP pipeline (analysis + enrichment)...'):
                        try:
                            tmp_dir = tempfile.mkdtemp(prefix='pcap_dash_')
                            pcap_path = os.path.join(tmp_dir, Path(uploaded.name).name or 'upload.pcap')
                            with open(pcap_path, 'wb') as f:
                                f.write(uploaded.getbuffer())
                            dp, ep = _run_pipeline(pcap_path, tmp_dir)
                            st.success('Analysis complete. Loaded generated JSONs from temp.')
                        except subprocess.CalledProcessError as exc:
                            st.error('Analysis pipeline failed. Check console logs.')
                            st.code(str(exc))
                            clicked = False
            elif clicked and not uploaded:
                st.warning('Please upload a file first.')
                clicked = False
        else:
            d_opts = _find_candidates('pcap_deeper_results.json')
            e_opts = _find_candidates('ip_enrichment_results.json')
            dp = st.text_input('Analysis JSON path', value=d_opts[0] if d_opts else _bundled_example_paths()[0])
            ep = st.text_input('Enrichment JSON path', value=e_opts[0] if e_opts else _bundled_example_paths()[1])
            clicked = st.button('Start triage', type='primary', use_container_width=True)

    with right:
        st.markdown(
            """
            <div class="status-rail" style="padding:16px 16px 12px 16px;">
                <div class="workspace-kicker">How this lane works</div>
                <div class="workspace-note" style="margin-top:8px">
                    <b>1.</b> Load analysis JSON and enrichment JSON.<br>
                    <b>2.</b> Review verdict, queue, graph, and report.<br>
                    <b>3.</b> Export the evidence package.
                </div>
                <div class="workspace-note" style="margin-top:10px;color:#94a3b8">
                    Good fit for noisy DNS captures, DGA hunting, and quick IOC export.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div class="status-rail" style="padding:16px 16px 12px 16px;margin-top:12px;">
                <div class="workspace-kicker">Included example</div>
                <div class="workspace-note" style="margin-top:8px">
                    The repo ships with sample analysis JSONs under <b>/outputs</b> so the dashboard can open with a real demo dataset immediately.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    return clicked, dp, ep


def section_command_center(risk_ctx: dict, deep: dict, query_df: pd.DataFrame, beacon_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None, report_pkg: dict):
    analysis_ts = _analysis_timestamp(query_df)
    confidence = 'HIGH' if risk_ctx['risk'] >= 50 else 'MEDIUM'
    primary = risk_ctx['narrative']
    top_host = risk_ctx.get('primary_host', '—')
    st.markdown(
        f"""
        <div class="command-center">
            <div style="display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;flex-wrap:wrap;">
                <div>
                    <div class="console-kicker">PCAP Threat Intelligence Console</div>
                    <div class="console-title">Threat Hunting Workspace</div>
                    <div class="console-subtitle">Capture status: analysis loaded · Analysis timestamp: {analysis_ts}</div>
                </div>
                <div style="display:flex;gap:0.9rem;align-items:center;flex-wrap:wrap;justify-content:flex-end;">
                    <div style="text-align:right;min-width:180px;">
                        <div style="font-size:11px;color:#7dd3fc;text-transform:uppercase;letter-spacing:.18em;font-weight:700;">Threat Score</div>
                        <div style="font-size:34px;font-weight:900;color:{risk_ctx['color']};line-height:1;">{risk_ctx['risk']} / 100</div>
                        <div style="margin-top:2px;font-size:13px;color:#cbd5e1;">Status: {risk_ctx['verdict']} · Confidence: {confidence}</div>
                    </div>
                    <div style="max-width:300px;font-size:13px;color:#cbd5e1;line-height:1.45;border-left:1px solid rgba(148,163,184,0.18);padding-left:14px;">
                        <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.12em;font-weight:700;">Primary Detection</div>
                        {primary}
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    left, center, right = st.columns([1.05, 1.45, 1.1])

    with left:
        st.markdown(
            f"""
            <div class="alert-card" style="min-height:320px;border-left-color:{risk_ctx['color']};">
                <div class="score-badge" style="background:{risk_ctx['color']}22;color:{risk_ctx['color']};">{risk_ctx['icon']} {risk_ctx['verdict']}</div>
                <div style="margin-top:12px;font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">Threat Score</div>
                <div style="font-size:46px;font-weight:900;line-height:1;color:{risk_ctx['color']};">{risk_ctx['risk']} / 100</div>
                <div style="margin-top:8px;font-size:13px;color:#cbd5e1;">Confidence: {confidence}</div>
                <div style="margin-top:14px;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">Primary Detection</div>
                <div style="font-size:13px;color:#e5eefc;line-height:1.5;">{primary}</div>
                <div style="margin-top:12px;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">Affected Host</div>
                <div style="font-size:14px;color:#e5eefc;font-weight:700;">{top_host}</div>
                <div style="margin-top:12px;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">Risk Contributors</div>
                <div style="font-size:12px;color:#cbd5e1;line-height:1.65;">{'<br>'.join(risk_ctx.get('contributors', []))}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.download_button(
            'Export report',
            data=report_pkg['txt'],
            file_name='pcap_threat_report.txt',
            mime='text/plain',
            use_container_width=True,
            key='header-report-download',
        )

    with center:
        st.markdown('#### Detection Overview')
        metric_cards = [
            ('Packets', int(deep.get('packets_total', 0))),
            ('DNS Queries', len(query_df)),
            ('Hosts', query_df['src'].nunique() if not query_df.empty else 0),
            ('Suspicious Domains', query_df[query_df['severity'].isin(['HIGH', 'CRITICAL'])]['sld'].nunique() if not query_df.empty else 0),
            ('Countries', ip_df['Country'].nunique() if not ip_df.empty else 0),
            ('MITRE Techniques', len(report_pkg['techniques'])),
        ]
        for row_cards in [metric_cards[:3], metric_cards[3:]]:
            cols = st.columns(3)
            for col, (title, value) in zip(cols, row_cards):
                with col:
                    st.markdown(
                        f"""
                        <div class="alert-card" style="min-height:104px;padding:14px 14px 12px 14px;">
                            <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">{title}</div>
                            <div style="font-size:28px;font-weight:900;color:#e5eefc;margin-top:8px;line-height:1;">{value}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

    with right:
        section_priority_queue_compact(query_df, beacon_df, ip_df, answer_map, focus_domain, limit=5)



def section_executive_summary(deep: dict, query_df: pd.DataFrame, beacon_df: pd.DataFrame, ip_df: pd.DataFrame, report_pkg: dict):
    suspicious_domains = query_df[query_df['severity'].isin(['HIGH', 'CRITICAL'])]['sld'].nunique() if not query_df.empty else 0
    malicious_indicators = int((query_df['severity'] == 'CRITICAL').sum()) + int((beacon_df['beacon'].sum() if not beacon_df.empty else 0))
    country_count = ip_df['Country'].nunique() if not ip_df.empty else 0
    mitre_count = len(report_pkg['techniques'])
    cards = [
        ('Total Packets', int(deep.get('packets_total', 0)), 'capture volume', '🧩', '#3b82f6'),
        ('DNS Requests', len(query_df), 'queries to inspect', '🌐', '#8b5cf6'),
        ('Unique Source Hosts', query_df['src'].nunique() if not query_df.empty else 0, 'originating assets', '🖥️', '#06b6d4'),
        ('Unique Domains', query_df['sld'].nunique() if not query_df.empty else 0, 'sld spread', '🔎', '#22c55e'),
        ('Suspicious Domains', suspicious_domains, 'high entropy / rare', '⚠️', '#f97316'),
        ('Malicious Indicators', malicious_indicators, 'critical + beacon hits', '🚨', '#ef4444'),
        ('Countries Contacted', country_count, 'geo spread', '🛰️', '#14b8a6'),
        ('MITRE Techniques Found', mitre_count, 'mapped behaviors', '🧭', '#eab308'),
    ]
    st.markdown('### Executive Summary')
    rows = [cards[:4], cards[4:]]
    for row in rows:
        cols = st.columns(4)
        for col, card in zip(cols, row):
            title, value, note, icon, color = card
            with col:
                st.markdown(
                    f"""
                    <div class="alert-card" style="min-height:118px;border-left-color:{color};">
                        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;">
                            <div>
                                <div style="font-size:22px;line-height:1;">{icon}</div>
                                <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;margin-top:10px;font-weight:700;">{title}</div>
                                <div style="font-size:30px;font-weight:900;color:#e5eefc;margin-top:4px;">{value}</div>
                                <div style="font-size:12px;color:#94a3b8;margin-top:4px;">{note}</div>
                            </div>
                            <div style="font-size:11px;color:{color};font-weight:800;text-transform:uppercase;letter-spacing:.08em;">{'UP' if value else 'N/A'}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


def section_investigation_timeline(events: list[dict]):
    st.markdown('### Incident Timeline')
    if not events:
        st.info('No investigation events available.')
        return
    c1, c2 = st.columns([1.5, 1])
    with c1:
        st.caption('Chronological attack progression')
    with c2:
        show_all = st.toggle('Show full timeline', value=False)
    shown = events if show_all else events[:8]
    for event in shown:
        color = {'CRITICAL': '#ef4444', 'HIGH': '#f97316', 'MEDIUM': '#eab308', 'LOW': '#22c55e'}.get(event['severity'], '#94a3b8')
        st.markdown(
            f"""
            <div class="alert-card" style="border-left-color:{color};margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;">
                    <div>
                        <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">{event['clock']}</div>
                        <div style="font-size:16px;font-weight:900;color:#e5eefc;margin-top:4px;">{event['title']}</div>
                        <div style="margin-top:8px;font-size:13px;color:#cbd5e1;line-height:1.5;">
                            <div><b>Host:</b> {event['host']}</div>
                            <div><b>Domain:</b> {event['domain']}</div>
                            <div><b>Reason:</b> {event['reason']}</div>
                        </div>
                    </div>
                    <div class="score-badge" style="background:{color}22;color:{color};">{event['severity']}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def section_priority_queue_compact(query_df: pd.DataFrame, beacon_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None, limit: int = 5):
    st.markdown('### Priority Queue')
    st.caption('Top findings only. Expand an item for drilldown. Full evidence lives in the tabs below.')
    if query_df.empty:
        st.info('No DNS records available.')
        return focus_domain

    beacon_pairs = set()
    if not beacon_df.empty:
        for _, b in beacon_df.iterrows():
            if bool(b.get('beacon')):
                beacon_pairs.add((b['src'], b['sld']))

    ranked = query_df.copy()
    ranked['beacon'] = ranked.apply(lambda r: (r['src'], r['sld']) in beacon_pairs, axis=1)
    ranked = ranked.sort_values(['dga_score', 'label_ent', 'time'], ascending=[False, False, True])
    ranked = ranked.drop_duplicates(subset=['sld']).head(limit)

    if ranked.empty:
        st.info('No prioritized findings after deduplication.')
        return focus_domain

    for _, row in ranked.iterrows():
        sev, color = _risk_badge(float(row['dga_score']))
        country = '—'
        if not ip_df.empty and 'IP' in ip_df.columns:
            meta = ip_df.loc[ip_df['IP'] == row['dst'], ['Country', 'CountryCode']].head(1)
            if not meta.empty:
                country = ' / '.join([str(v) for v in meta.iloc[0].tolist() if pd.notna(v)])
        targets = answer_map.get(row['qname'], [])
        reasons = _queue_reasons(row, int(query_df[query_df['sld'] == row['sld']].shape[0]), answer_map, ip_df, beacon_pairs)
        with st.expander(f"{sev} · {row['sld']} · Risk {int(float(row['dga_score']) * 100)}%", expanded=False):
            st.markdown(
                f"""
                <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start;">
                    <div style="min-width:220px;flex:1;">
                        <div class="domain">{row['qname']}</div>
                        <div class="meta">Source host: {row['src']}</div>
                        <div class="meta">Destination: {row['dst']} · {country}</div>
                        <div class="meta">Entropy: {row['label_ent']:.3f}</div>
                        <div class="meta">MITRE: {_derive_technique(row, beacon_pairs)}</div>
                        <div class="meta">Reasoning: {' · '.join(reasons[:4])}</div>
                        <div class="meta">Resolved IPs: {', '.join(targets) if targets else '—'}</div>
                    </div>
                    <div class="score-badge" style="background:{color}22;color:{color};">{row['severity']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    if focus_domain is None and not ranked.empty:
        focus_domain = ranked.iloc[0]['sld']
    st.caption('View full investigation in the tabs below.')
    return focus_domain


def section_threat_triage_queue(query_df: pd.DataFrame, beacon_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None):
    st.markdown('### Threat Triage Queue')
    if query_df.empty:
        st.info('No DNS records available.')
        return query_df, focus_domain

    beacon_pairs = set()
    if not beacon_df.empty:
        for _, b in beacon_df.iterrows():
            if bool(b.get('beacon')):
                beacon_pairs.add((b['src'], b['sld']))

    controls = st.columns([1, 1, 1, 1])
    with controls[0]:
        severities = st.multiselect('Severity', ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], default=['CRITICAL', 'HIGH', 'MEDIUM'])
    with controls[1]:
        source_opts = ['All'] + sorted(query_df['src'].dropna().unique().tolist())
        src = st.selectbox('Source IP', source_opts)
    with controls[2]:
        domain_opts = ['All'] + sorted(query_df['sld'].dropna().unique().tolist())
        domain = st.selectbox('Domain', domain_opts, index=domain_opts.index(focus_domain) if focus_domain in domain_opts else 0)
    with controls[3]:
        technique_opts = ['All', 'T1568.002', 'T1071.004']
        technique = st.selectbox('Technique', technique_opts)

    filt = query_df.copy()
    if severities:
        filt = filt[filt['severity'].isin(severities)]
    if src != 'All':
        filt = filt[filt['src'] == src]
    if domain != 'All':
        filt = filt[filt['sld'] == domain]
    if technique != 'All':
        filt = filt[filt.apply(lambda row: _derive_technique(row, beacon_pairs) == technique, axis=1)]

    st.caption(f'{len(filt)} matching records')
    if filt.empty:
        st.warning('No alerts match the current filters.')
        return filt, domain if domain != 'All' else focus_domain

    top = filt.sort_values(['dga_score', 'label_ent', 'time'], ascending=[False, False, True]).head(8)
    for _, row in top.iterrows():
        sev, color = _risk_badge(float(row['dga_score']))
        reasons = _queue_reasons(row, int(query_df[query_df['sld'] == row['sld']].shape[0]), answer_map, ip_df, beacon_pairs)
        targets = answer_map.get(row['qname'], [])
        st.markdown(
            f"""
            <div class="alert-card" style="border-left-color:{color};">
                <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;">
                    <div>
                        <div class="score-badge" style="background:{color}22;color:{color};">🚨 {sev}</div>
                        <div class="domain" style="margin-top:10px;">{row['qname']}</div>
                        <div class="meta" style="margin-top:8px;">Risk: {row['dga_score']:.2f} · Entropy: {row['label_ent']:.3f}</div>
                        <div class="meta">Source → Destination: {row['src']} → {row['dst']}</div>
                        <div class="meta">Record Type: {_qtype_name(row.get('qtype', 1))}</div>
                        <div class="meta">{' · '.join('✓ ' + r for r in reasons[:4])}</div>
                        <div class="meta" style="margin-top:4px;">Resolved IPs: {', '.join(targets) if targets else '—'}</div>
                    </div>
                    <div class="score-badge" style="background:rgba(148,163,184,0.12);color:#e5eefc;">{row['severity']} · {row['dga_score']:.2f}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    focus_candidates = sorted(top['sld'].unique().tolist())
    return filt, (focus_candidates[0] if focus_candidates else focus_domain)


def section_network_intelligence_graph(query_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None):
    st.markdown('### Network Intelligence Graph')
    fig = _build_network_graph(query_df, ip_df, answer_map, focus_domain)
    st.plotly_chart(fig, use_container_width=True)
    st.caption('Blue = internal assets · Orange = suspicious domains · Red = high-risk infrastructure')


def section_domain_intelligence(query_df: pd.DataFrame, ip_df: pd.DataFrame, answer_map: dict[str, list[str]], focus_domain: str | None):
    st.markdown('### Domain Intelligence Panel')
    intel = _build_domain_intel(query_df, ip_df, answer_map, focus_domain)
    if intel.empty:
        st.info('No suspicious domains available.')
        return
    for _, row in intel.iterrows():
        color = '#f97316' if row['risk'] == 'HIGH' else '#eab308'
        st.markdown(
            f"""
            <div class="alert-card" style="border-left-color:{color};margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;">
                    <div style="min-width:280px;flex:1;">
                        <div class="score-badge" style="background:{color}22;color:{color};">{row['risk']}</div>
                        <div class="domain" style="margin-top:10px;">{row['domain']}</div>
                        <div class="meta" style="margin-top:8px;">Risk: {row['risk']} · DGA Probability: {row['dga_probability']:.0f}% · Entropy: {row['entropy']:.3f}</div>
                        <div class="meta">First Seen: {_fmt_dt(row['first_seen'])} · Queries: {row['queries']}</div>
                        <div class="meta">Associated IPs: {row['ips']}</div>
                        <div class="meta">Geo: {row['countries']} · {row['asn']}</div>
                        <div class="meta" style="margin-top:6px;">{row['reasoning']}</div>
                    </div>
                    <div style="min-width:220px;max-width:280px;color:#cbd5e1;font-size:12px;line-height:1.6;">
                        <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">Observation</div>
                        <div style="margin-top:4px;">{row['sources']}</div>
                        <div style="margin-top:10px;font-size:11px;color:#94a3b8;">Domain intelligence references query entropy, destination IP enrichment, and observed infrastructure.</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def section_dns_forensics(query_df: pd.DataFrame, deep: dict, beacon_df: pd.DataFrame):
    st.markdown('### DNS Forensics View')
    forensic = _build_forensic_df(query_df, deep, beacon_df)
    if forensic.empty:
        st.info('No DNS records to inspect.')
        return
    search = st.text_input('Search query / source / destination', value='')
    severities = st.multiselect('Filter severity', ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
    tfs = forensic.copy()
    if search:
        mask = (
            tfs['Query'].str.contains(search, case=False, na=False) |
            tfs['Source'].str.contains(search, case=False, na=False) |
            tfs['Destination'].str.contains(search, case=False, na=False)
        )
        tfs = tfs[mask]
    if severities:
        tfs = tfs[tfs['Severity'].isin(severities)]
    tfs = tfs[['Time', 'Source', 'Destination', 'Query', 'Record Type', 'Entropy', 'Risk', 'MITRE Technique']].sort_values('Risk', ascending=False)
    st.dataframe(tfs.head(15), use_container_width=True, height=280)
    with st.expander('Show all DNS queries'):
        st.dataframe(tfs, use_container_width=True, height=420)



def section_mitre_matrix(query_df: pd.DataFrame, beacon_df: pd.DataFrame):
    st.markdown('### MITRE ATT&CK Matrix')
    if query_df.empty:
        st.info('No MITRE mappings available.')
        return
    beacon_flag = not beacon_df.empty and beacon_df['beacon'].any()
    cards = [
        ('T1568.002', 'Domain Generation Algorithm', 'Medium' if not (query_df['dga_score'] >= 0.70).any() else 'High', 'High entropy DNS requests detected', 'domains with random labels'),
        ('T1071.004', 'DNS', 'High', 'Command-and-control over DNS observed', 'query / response activity'),
        ('T1071', 'Application Layer Protocol', 'Medium' if beacon_flag else 'Low', 'Repeated cadence consistent with beaconing', 'periodic lookups / jitter'),
    ]
    for tid, name, conf, evidence, artifacts in cards:
        color = {'High': '#ef4444', 'Medium': '#eab308', 'Low': '#22c55e'}.get(conf, '#94a3b8')
        st.markdown(
            f"""
            <div class="alert-card" style="border-left-color:{color};margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;">
                    <div>
                        <div class="score-badge" style="background:{color}22;color:{color};">Technique ID {tid}</div>
                        <div class="domain" style="margin-top:10px;">{name}</div>
                        <div class="meta" style="margin-top:6px;">Confidence: {conf}</div>
                        <div class="meta">Evidence: {evidence}</div>
                        <div class="meta">Observed artifacts: {artifacts}</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def section_geo_threat_map(ip_df: pd.DataFrame):
    st.markdown('### GEO Threat Map')
    df = ip_df.dropna(subset=['Lat', 'Lon'])
    if df.empty:
        st.info('No geo data available.')
        return
    fig = px.scatter_geo(
        df,
        lat='Lat',
        lon='Lon',
        hover_name='IP',
        hover_data={'Country': True, 'City': True, 'ASN': True, 'Org': True, 'Lat': False, 'Lon': False},
        size=[15] * len(df),
        color='CountryCode' if 'CountryCode' in df.columns else None,
        projection='natural earth',
    )
    fig.update_layout(
        geo=dict(
            showframe=False,
            showcoastlines=True,
            coastlinecolor='rgba(148,163,184,0.3)',
            showland=True,
            landcolor='rgba(30,41,59,0.6)',
            showocean=True,
            oceancolor='rgba(15,23,42,0.8)',
            showcountries=True,
            countrycolor='rgba(148,163,184,0.15)',
            bgcolor='rgba(0,0,0,0)',
        ),
        paper_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=0, r=0, t=0, b=0),
        height=380,
    )
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(df[['IP', 'Country', 'ASN', 'Org', 'CountryCode']].drop_duplicates(), use_container_width=True, height=220)


def section_ioc_export_center(report_pkg: dict, query_df: pd.DataFrame, ip_df: pd.DataFrame):
    st.markdown('### IOC Export Center')
    opts = st.multiselect('Threat intelligence package', ['Domains', 'IP addresses', 'DNS evidence', 'MITRE mapping', 'Timeline'], default=['Domains', 'IP addresses', 'DNS evidence', 'MITRE mapping', 'Timeline'])
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button('Download TXT', data=report_pkg['txt'], file_name='pcap_threat_package.txt', mime='text/plain', use_container_width=True)
    with c2:
        st.download_button('Download JSON', data=report_pkg['json'], file_name='pcap_threat_package.json', mime='application/json', use_container_width=True)
    with c3:
        st.download_button('Download STIX', data=report_pkg['stix'], file_name='pcap_threat_package.stix.json', mime='application/json', use_container_width=True)
    st.caption(f'Selected exports: {", ".join(opts)}')


def section_final_report(report_pkg: dict):
    st.markdown('### Final Investigation Report')
    st.markdown(
        f"""
        <div class="alert-card" style="border-left-color:#3b82f6;">
            <div style="font-size:13px;color:#cbd5e1;line-height:1.65;white-space:pre-wrap;">{report_pkg['txt']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ─────────────────────────── main ────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title='PCAP Threat Intelligence Console',
        page_icon='🔍',
        layout='wide',
        initial_sidebar_state='collapsed',
    )
    _inject_theme()

    with st.sidebar:
        st.markdown('## 🔍 PCAP Console')
        st.caption('Support rail — the real work happens in the main workspace.')
        st.markdown(
            """
            <div class="status-rail" style="padding:14px 14px 12px 14px;">
                <div class="workspace-kicker">Current lane</div>
                <div class="workspace-note" style="margin-top:8px">DNS triage, DGA scoring, beacon checks, geo enrichment, and IOC export.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown('---')
        st.markdown(
            """
            <div class="workspace-note" style="font-size:11px;color:#64748b;line-height:1.6">
            <b>Workflow</b><br>
            1. Load inputs<br>
            2. Read verdict<br>
            3. Drill into evidence
            </div>
            """,
            unsafe_allow_html=True,
        )

    clicked, deep_path, enrich_path = section_setup()

    if not clicked:
        st.markdown(
            """
            <div class="command-center">
                <div class="console-kicker">PCAP Threat Intelligence Console</div>
                <div class="console-title">Threat Hunting Workspace</div>
                <div class="console-subtitle">Load a capture or point at the existing analysis JSONs to begin triage.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.info('Pick a source above and hit **Start triage**.')
        return

    for path, label in [(deep_path, 'analysis'), (enrich_path, 'enrichment')]:
        if not Path(path).exists():
            st.error(f'File not found ({label}): `{path}`')
            return

    with st.spinner('Loading and analysing …'):
        deep, enrich = load_data(deep_path, enrich_path)
        query_df = build_query_df(deep.get('dns', []))
        beacon_df = detect_beacons(query_df)
        ip_df = build_ip_df(enrich)
        qtype_map, answer_map = _build_lookup_maps(deep)

    if query_df.empty:
        st.warning('No DNS query records found in the loaded data.')
        return

    risk_ctx = _risk_context(deep, query_df, beacon_df, ip_df)
    report_pkg = _build_report_package(deep, query_df, beacon_df, ip_df, risk_ctx, None, answer_map)
    focus_domain = report_pkg['domains'][0] if report_pkg['domains'] else None
    events = _build_event_rows(query_df, beacon_df, answer_map, ip_df)

    section_command_center(risk_ctx, deep, query_df, beacon_df, ip_df, answer_map, focus_domain, report_pkg)

    tabs = st.tabs(['Investigation Timeline', 'Threat Intelligence', 'DNS Forensics', 'MITRE ATT&CK', 'Report & Export'])
    with tabs[0]:
        section_investigation_timeline(events)
    with tabs[1]:
        col_graph, col_domain = st.columns([1.15, 0.85])
        with col_graph:
            section_network_intelligence_graph(query_df, ip_df, answer_map, focus_domain)
        with col_domain:
            section_domain_intelligence(query_df, ip_df, answer_map, focus_domain)
        st.markdown('---')
        section_geo_threat_map(ip_df)
    with tabs[2]:
        section_dns_forensics(query_df, deep, beacon_df)
    with tabs[3]:
        section_mitre_matrix(query_df, beacon_df)
    with tabs[4]:
        section_ioc_export_center(report_pkg, query_df, ip_df)
        with st.expander('Analyst summary', expanded=True):
            section_final_report(report_pkg)


if __name__ == '__main__':
    main()
