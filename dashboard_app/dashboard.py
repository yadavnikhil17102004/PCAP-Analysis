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


def section_setup() -> tuple[bool, str, str]:
    with st.expander("Data Source", expanded=True):
        mode = st.radio("Load mode", ["Auto-detect", "Upload PCAP", "Custom paths"], horizontal=True)

        if mode == "Auto-detect":
            d_opts = _find_candidates("pcap_deeper_results.json")
            e_opts = _find_candidates("ip_enrichment_results.json")
            dp = st.selectbox("Deep analysis JSON", d_opts or ["pcap_deeper_results.json"])
            ep = st.selectbox("Enrichment JSON",    e_opts or ["ip_enrichment_results.json"])
            clicked = st.button("Run Analysis", type="primary", use_container_width=True)

        elif mode == "Upload PCAP":
            uploaded = st.file_uploader("Select .pcap file", type=["pcap", "pcapng"])
            clicked = st.button("Process & Load", type="primary", use_container_width=True)
            dp, ep = "", ""
            
            if clicked and uploaded:
                with st.spinner("Processing PCAP pipeline (analysis + enrichment)..."):
                    try:
                        tmp_dir = tempfile.mkdtemp(prefix="pcap_dash_")
                        pcap_path = os.path.join(tmp_dir, uploaded.name)
                        with open(pcap_path, "wb") as f:
                            f.write(uploaded.getbuffer())
                        
                        dp, ep = _run_pipeline(pcap_path, tmp_dir)
                        st.success(f"Analysis complete. Loaded generated JSONs from temp.")
                    except subprocess.CalledProcessError as exc:
                        st.error(f"Analysis pipeline failed. Check console logs.")
                        st.code(str(exc))
                        clicked = False
            elif clicked and not uploaded:
                st.warning("Please upload a file first.")
                clicked = False

        else:
            d_opts = _find_candidates("pcap_deeper_results.json")
            e_opts = _find_candidates("ip_enrichment_results.json")
            dp = st.text_input("Deep analysis JSON path",
                               value=d_opts[0] if d_opts else "pcap_deeper_results.json")
            ep = st.text_input("Enrichment JSON path",
                               value=e_opts[0] if e_opts else "ip_enrichment_results.json")
            clicked = st.button("Run Analysis", type="primary", use_container_width=True)
            
    return clicked, dp, ep


def section_verdict(query_df: pd.DataFrame, beacon_df: pd.DataFrame, ip_df: pd.DataFrame):
    critical = int((query_df["severity"] == "CRITICAL").sum())
    high     = int((query_df["severity"] == "HIGH").sum())
    beacons  = int(beacon_df["beacon"].sum()) if not beacon_df.empty else 0
    ru_ips   = int((ip_df["CountryCode"] == "RU").sum()) if not ip_df.empty else 0

    # Overall verdict
    if critical > 0 or beacons > 0:
        verdict, vcolor, vicon = "MALICIOUS", "#ef4444", "🔴"
    elif high > 2:
        verdict, vcolor, vicon = "SUSPICIOUS", "#f97316", "🟠"
    else:
        verdict, vcolor, vicon = "REVIEW", "#eab308", "🟡"

    st.markdown(
        f"""
        <div style="
            border:1px solid {vcolor};
            border-radius:14px;
            padding:20px 24px;
            background:rgba(0,0,0,0.03);
            display:flex;
            align-items:center;
            gap:16px;
            margin-bottom:1.2rem;
        ">
            <div style="font-size:36px">{vicon}</div>
            <div>
                <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.1em;font-weight:700">Analyst Verdict</div>
                <div style="font-size:26px;font-weight:800;color:{vcolor};letter-spacing:.02em">{verdict}</div>
                <div style="font-size:13px;color:#94a3b8;margin-top:2px">
                    {critical} critical domains · {high} high-risk · {beacons} beacon pattern{"s" if beacons!=1 else ""} · {ru_ips} RU-hosted IP{"s" if ru_ips!=1 else ""}
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_metrics(deep: dict, query_df: pd.DataFrame, ip_df: pd.DataFrame):
    cols = st.columns(5)
    metrics = [
        ("Total packets",   deep.get("packets_total", 0),   None,        "#3b82f6"),
        ("DNS queries",     len(query_df),                   None,        "#8b5cf6"),
        ("Unique SLDs",     query_df["sld"].nunique(),       None,        "#06b6d4"),
        ("C2 IPs found",    len(ip_df),                      None,        "#f97316"),
        ("Critical domains",int((query_df["severity"] == "CRITICAL").sum()), None, "#ef4444"),
    ]
    for col, (label, val, delta, color) in zip(cols, metrics):
        with col:
            _metric_card(label, val, delta, color)


def section_timeline(query_df: pd.DataFrame):
    st.markdown("#### DNS Query Timeline")

    c1, c2, c3 = st.columns([2, 2, 1])
    min_ent = c1.slider("Min label entropy", 0.0, 5.0, 2.5, 0.1)
    selected_sev = c2.multiselect(
        "Severity filter",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM"],
    )
    show_labels = c3.toggle("Show domain labels", False)

    df = query_df[
        (query_df["label_ent"] >= min_ent) &
        (query_df["severity"].isin(selected_sev))
    ].copy()

    if df.empty:
        st.warning("No records match current filters.")
        return

    fig = px.scatter(
        df,
        x="time",
        y="label_ent",
        color="severity",
        symbol="src",
        hover_data={"qname": True, "src": True, "sld": True,
                    "dga_score": ":.3f", "label_ent": ":.3f"},
        color_discrete_map=SEVERITY_COLOR,
        size="dga_score",
        size_max=14,
        title="",
    )

    if show_labels:
        for _, row in df.iterrows():
            fig.add_annotation(
                x=row["time"], y=row["label_ent"],
                text=row["sld"], showarrow=False,
                font=dict(size=9, color="#94a3b8"),
                yshift=10,
            )

    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(title="Time", gridcolor="rgba(148,163,184,0.1)"),
        yaxis=dict(title="Label entropy", gridcolor="rgba(148,163,184,0.1)", range=[0, 5.2]),
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        margin=dict(l=0, r=0, t=10, b=0),
        height=360,
    )
    fig.update_traces(marker=dict(line=dict(width=0.5, color="rgba(0,0,0,0.4)")))
    st.plotly_chart(fig, use_container_width=True)


def section_domain_table(query_df: pd.DataFrame):
    st.markdown("#### Domain Analysis")

    display = (
        query_df[["qname", "sld", "src", "label_ent", "dga_score", "severity", "time"]]
        .sort_values("dga_score", ascending=False)
        .rename(columns={
            "qname":     "FQDN",
            "sld":       "SLD",
            "src":       "Source IP",
            "label_ent": "Entropy",
            "dga_score": "DGA Score",
            "severity":  "Severity",
            "time":      "Timestamp",
        })
    )

    def color_severity(val):
        return f"color: {SEVERITY_COLOR.get(val, '#fff')}; font-weight: 700"

    styled = display.style.map(color_severity, subset=["Severity"])
    st.dataframe(styled, use_container_width=True, height=300)


def section_sld_bar(query_df: pd.DataFrame):
    st.markdown("#### SLD Query Frequency")
    top = (
        query_df.groupby("sld", as_index=False)
        .agg(count=("qname", "size"), avg_dga=("dga_score", "mean"))
        .sort_values("count", ascending=False)
        .head(15)
    )
    top["avg_dga"] = top["avg_dga"].round(3)

    fig = px.bar(
        top, x="count", y="sld", orientation="h",
        color="avg_dga",
        color_continuous_scale=["#22c55e", "#eab308", "#ef4444"],
        range_color=[0, 1],
        labels={"count": "Queries", "sld": "", "avg_dga": "Avg DGA"},
        title="",
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        yaxis=dict(autorange="reversed"),
        margin=dict(l=0, r=0, t=0, b=0),
        height=320,
        coloraxis_colorbar=dict(title="DGA Score", len=0.7),
    )
    st.plotly_chart(fig, use_container_width=True)


def section_beacon(beacon_df: pd.DataFrame):
    st.markdown("#### Beacon Detection")
    if beacon_df.empty:
        st.info("Insufficient repeated queries to run beacon analysis (need ≥ 3 queries per src/SLD pair).")
        return

    beacon_count = int(beacon_df["beacon"].sum())
    if beacon_count:
        st.error(f"⚡ {beacon_count} beacon-like pattern{'s' if beacon_count>1 else ''} detected (jitter CV < 0.30)")
    else:
        st.success("No beacon patterns detected in current dataset.")

    display = beacon_df.rename(columns={
        "src":             "Source IP",
        "sld":             "SLD",
        "queries":         "Query count",
        "interval_mean_s": "Mean interval (s)",
        "jitter_cv":       "Jitter (CV)",
        "beacon":          "Beacon flag",
    })

    def flag_beacon(val):
        return "color: #ef4444; font-weight: 700" if val else "color: #22c55e"

    st.dataframe(
        display.style.map(flag_beacon, subset=["Beacon flag"]),
        use_container_width=True,
    )


def section_geo_map(ip_df: pd.DataFrame):
    st.markdown("#### C2 IP Geographic Distribution")
    df = ip_df.dropna(subset=["Lat", "Lon"])
    if df.empty:
        st.info("No geo data available.")
        return

    fig = px.scatter_geo(
        df,
        lat="Lat",
        lon="Lon",
        hover_name="IP",
        hover_data={"Country": True, "Org": True, "ASN": True,
                    "ReverseDNS": True, "Lat": False, "Lon": False},
        size=[15] * len(df),
        color_discrete_sequence=["#ef4444"],
        projection="natural earth",
    )
    fig.update_layout(
        geo=dict(
            showframe=False,
            showcoastlines=True,
            coastlinecolor="rgba(148,163,184,0.3)",
            showland=True,
            landcolor="rgba(30,41,59,0.6)",
            showocean=True,
            oceancolor="rgba(15,23,42,0.8)",
            showlakes=False,
            showcountries=True,
            countrycolor="rgba(148,163,184,0.15)",
            bgcolor="rgba(0,0,0,0)",
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=0, b=0),
        height=340,
    )
    fig.update_traces(marker=dict(size=12, opacity=0.9,
                                  line=dict(width=1.5, color="#fca5a5")))
    st.plotly_chart(fig, use_container_width=True)


def section_ip_table(ip_df: pd.DataFrame):
    st.markdown("#### Enriched C2 IPs")
    display = ip_df[["IP", "Country", "City", "ASN", "Org", "ReverseDNS"]].copy()

    # Flag Russian IPs
    def flag_country(val):
        if val in ("Russia", "Russian Federation"):
            return "color: #ef4444; font-weight: 700"
        return ""

    st.dataframe(
        display.style.map(flag_country, subset=["Country"]),
        use_container_width=True,
    )


def section_mitre(query_df: pd.DataFrame, beacon_df: pd.DataFrame):
    st.markdown("#### MITRE ATT&CK Coverage")
    techniques = [
        ("T1568.002", "Dynamic Resolution: DGA",
         "CRITICAL" if (query_df["severity"] == "CRITICAL").any() else "MEDIUM",
         "Multiple high-entropy subdomains under groupprograms.in / gigapaysun.com"),
        ("T1071.004", "Application Layer Protocol: DNS",
         "HIGH",
         "All C2 contact observed exclusively via DNS A queries"),
        ("T1016",     "System Network Config Discovery",
         "MEDIUM",
         "ip-addr.es query = infected host resolving its external IP"),
        ("T1090",     "Multi-hop Proxy / CDN abuse",
         "MEDIUM",
         "C2 IPs spread across FR / RU / NL / US hosting providers"),
    ]
    if not beacon_df.empty and beacon_df["beacon"].any():
        techniques.append(
            ("T1071", "Application Layer Protocol (beaconing)",
             "HIGH",
             f"Periodic query pattern detected — CV < 0.30")
        )

    for tid, name, sev, evidence in techniques:
        color = SEVERITY_COLOR.get(sev, "#64748b")
        st.markdown(
            f"""
            <div style="
                display:flex;
                align-items:flex-start;
                gap:12px;
                padding:10px 14px;
                border:1px solid rgba(148,163,184,0.15);
                border-left:3px solid {color};
                border-radius:8px;
                margin-bottom:8px;
            ">
                <code style="color:{color};font-size:12px;white-space:nowrap;padding-top:1px">{tid}</code>
                <div>
                    <div style="font-weight:600;font-size:13px">{name}</div>
                    <div style="color:#94a3b8;font-size:12px;margin-top:2px">{evidence}</div>
                </div>
                <div style="margin-left:auto;white-space:nowrap">
                    <span style="
                        background:{color}22;
                        color:{color};
                        font-size:11px;
                        font-weight:700;
                        padding:2px 8px;
                        border-radius:4px;
                    ">{sev}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def section_exports(query_df: pd.DataFrame, ip_df: pd.DataFrame):
    st.markdown("#### Export IOCs")
    c1, c2, c3 = st.columns(3)

    with c1:
        csv_data = export_ioc_csv(query_df, ip_df)
        st.download_button(
            "⬇ IOC List (.csv)",
            data=csv_data,
            file_name="ioc_list.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with c2:
        sigma_data = export_sigma(query_df, ip_df)
        st.download_button(
            "⬇ Sigma Rule (.yml)",
            data=sigma_data,
            file_name="dga_sigma.yml",
            mime="text/plain",
            use_container_width=True,
        )
    with c3:
        suricata_data = export_suricata(query_df, ip_df)
        st.download_button(
            "⬇ Suricata Rules (.rules)",
            data=suricata_data,
            file_name="dga_suricata.rules",
            mime="text/plain",
            use_container_width=True,
        )


# ─────────────────────────── main ────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title="PCAP Investigation Console",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    with st.sidebar:
        st.markdown("## 🔍 PCAP Console")
        st.caption("Load inputs, then triage findings top-to-bottom.")
        clicked, deep_path, enrich_path = section_setup()
        st.markdown("---")
        st.markdown(
            """
            <div style='font-size:11px;color:#64748b;line-height:1.6'>
            <b>Flow</b><br>
            1. Deep analysis<br>
            2. Enrichment<br>
            3. Triage
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        """
        <div style="margin-bottom: 1rem;">
            <h2 style='margin:0 0 4px;font-weight:800;letter-spacing:-.01em'>
                PCAP Investigation Console
            </h2>
            <p style='color:#64748b;margin:0;font-size:14px'>
                DNS anomaly hunting · DGA scoring · beacon detection · IOC exports
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not clicked:
        st.info("Pick a source in the sidebar and hit **Run Analysis**.")
        return

    for path, label in [(deep_path, "deep analysis"), (enrich_path, "enrichment")]:
        if not Path(path).exists():
            st.error(f"File not found ({label}): `{path}`")
            return

    with st.spinner("Loading and analysing …"):
        deep, enrich = load_data(deep_path, enrich_path)
        query_df = build_query_df(deep.get("dns", []))
        beacon_df = detect_beacons(query_df)
        ip_df = build_ip_df(enrich)

    if query_df.empty:
        st.warning("No DNS query records found in the loaded data.")
        return

    section_verdict(query_df, beacon_df, ip_df)
    section_metrics(deep, query_df, ip_df)
    st.markdown("---")

    section_timeline(query_df)
    st.markdown("<br>", unsafe_allow_html=True)
    col_left, col_right = st.columns([3, 2])
    with col_left:
        section_sld_bar(query_df)
    with col_right:
        section_domain_table(query_df)

    st.markdown("---")
    section_geo_map(ip_df)
    st.markdown("<br>", unsafe_allow_html=True)
    section_ip_table(ip_df)

    st.markdown("---")
    section_beacon(beacon_df)

    st.markdown("---")
    section_mitre(query_df, beacon_df)

    st.markdown("---")
    section_exports(query_df, ip_df)


if __name__ == "__main__":
    main()
