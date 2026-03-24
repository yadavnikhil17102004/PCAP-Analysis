import json
import math
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent


def entropy(text):
    if not text:
        return 0.0
    probabilities = [float(text.count(char)) / len(text) for char in set(text)]
    return -sum(prob * math.log(prob, 2) for prob in probabilities)


def sld(domain):
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain


def _find_json_candidates(filename):
    candidates = []
    for folder in [ROOT / "outputs", ROOT, BASE / "outputs", BASE]:
        candidate = folder / filename
        if candidate.exists():
            candidates.append(candidate)
    return list(dict.fromkeys(candidates))


@st.cache_data(show_spinner=False)
def load_data(deep_path, enrich_path):
    with open(deep_path, "r", encoding="utf-8") as f:
        deep = json.load(f)
    with open(enrich_path, "r", encoding="utf-8") as f:
        enrich = json.load(f)
    return deep, enrich


def _style_app():
    st.markdown(
        """
        <style>
        :root {
            --brand-navy: #1d3557;
            --brand-blue: #457b9d;
            --brand-cyan: #a8dadc;
            --brand-cream: #f1faee;
            --brand-red: #e63946;
        }

        .stApp {
            background: radial-gradient(circle at 10% 10%, #f7fbff 0%, #eef5fb 35%, #e8f0f8 100%);
        }

        .hero {
            border: 1px solid rgba(29, 53, 87, 0.2);
            border-radius: 18px;
            padding: 1.25rem 1.4rem;
            background: linear-gradient(135deg, rgba(241, 250, 238, 0.96), rgba(168, 218, 220, 0.5));
            margin-bottom: 1rem;
        }

        .hero h1 {
            margin: 0;
            color: var(--brand-navy);
            font-weight: 800;
            letter-spacing: 0.02em;
        }

        .hero p {
            margin: 0.35rem 0 0;
            color: #16324a;
            font-size: 0.95rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _setup_panel():
    st.subheader("Data Source Setup")
    st.caption("Pick files first, then click Load Dashboard. No hidden defaults are auto-loaded.")

    detected_deep = _find_json_candidates("pcap_deeper_results.json")
    detected_enrich = _find_json_candidates("ip_enrichment_results.json")

    deep_options = [str(p) for p in detected_deep] or [str(ROOT / "outputs" / "pcap_deeper_results.json")]
    enrich_options = [str(p) for p in detected_enrich] or [str(ROOT / "outputs" / "ip_enrichment_results.json")]

    mode = st.radio(
        "Load mode",
        ["Use detected files", "Enter custom file paths"],
        horizontal=True,
    )

    if mode == "Use detected files":
        deep_path = st.selectbox("Deep analysis JSON", deep_options)
        enrich_path = st.selectbox("IP enrichment JSON", enrich_options)
    else:
        deep_path = st.text_input("Deep analysis JSON path", value=deep_options[0])
        enrich_path = st.text_input("IP enrichment JSON path", value=enrich_options[0])

    load_clicked = st.button("Load Dashboard", type="primary", use_container_width=True)
    return load_clicked, deep_path, enrich_path


def main():
    st.set_page_config(page_title="PCAP Investigation Console", layout="wide", page_icon="network")
    _style_app()

    st.markdown(
        """
        <div class="hero">
            <h1>PCAP Investigation Console</h1>
            <p>Signal-first DNS and C2 analysis workspace with entropy and enrichment context.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    load_clicked, deep_path, enrich_path = _setup_panel()

    if not load_clicked:
        st.info("Choose your input files and click Load Dashboard.")
        return

    deep_path = Path(deep_path)
    enrich_path = Path(enrich_path)
    if not deep_path.exists() or not enrich_path.exists():
        st.error("One or both selected files do not exist. Run the pipeline first or provide valid paths.")
        return

    try:
        deep, enrich = load_data(str(deep_path), str(enrich_path))
    except Exception as exc:
        st.error(f"Failed to load JSON data: {exc}")
        return

    dns_records = deep.get("dns", [])
    queries = [r for r in dns_records if r.get("qr") == 0]
    answered = [r for r in dns_records if r.get("qr") == 1 and r.get("answers")]
    c2_ips = list(enrich.get("ips", {}).keys())

    with st.expander("Active Dataset", expanded=False):
        st.write({"deep_json": str(deep_path), "enrichment_json": str(enrich_path)})

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total packets", deep.get("packets_total"))
    col2.metric("DNS queries", len(queries))
    col3.metric("Answered", len(answered))
    col4.metric("Unique C2 IPs", len(c2_ips))

    controls = st.columns(2)
    min_entropy = controls[0].slider("Minimum label entropy", min_value=0.0, max_value=5.0, value=3.0, step=0.1)
    suspicious_only = controls[1].toggle("Show suspicious SLDs only", value=False)

    st.subheader("DNS Signal Timeline")
    timeline_rows = []
    suspicious_slds = set((deep.get("suspicious_slds") or {}).keys())
    for r in queries:
        qname = r.get("qname")
        if not qname:
            continue
        label = qname.split(".")[0]
        row_entropy = entropy(label)
        row_sld = sld(qname)
        timeline_rows.append(
            {
                "time": datetime.fromtimestamp(float(r.get("time", 0))),
                "entropy": row_entropy,
                "domain": qname,
                "src": r.get("src") or "unknown",
                "sld": row_sld,
                "suspicious": row_sld in suspicious_slds,
            }
        )
    if timeline_rows:
        df = pd.DataFrame(timeline_rows)
        df = df[df["entropy"] >= min_entropy]
        if suspicious_only:
            df = df[df["suspicious"]]

        if df.empty:
            st.warning("No records match the current filters.")
        else:
            fig = px.scatter(
                df,
                x="time",
                y="entropy",
                color="suspicious",
                hover_data=["domain", "src", "sld"],
                color_discrete_map={True: "#e63946", False: "#457b9d"},
                title="DNS Query Entropy Over Time",
            )
            fig.update_traces(marker=dict(size=10, opacity=0.82, line=dict(width=0.5, color="#0f172a")))
            fig.update_layout(plot_bgcolor="rgba(255,255,255,0.9)", paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

            top_slds = (
                df.groupby("sld", as_index=False)
                .size()
                .sort_values("size", ascending=False)
                .head(12)
            )
            bar_fig = px.bar(
                top_slds,
                x="sld",
                y="size",
                title="Top Queried SLDs",
                labels={"size": "Query count", "sld": "SLD"},
                color="size",
                color_continuous_scale="Tealgrn",
            )
            bar_fig.update_layout(xaxis_tickangle=-22, plot_bgcolor="rgba(255,255,255,0.9)")
            st.plotly_chart(bar_fig, use_container_width=True)
    else:
        st.info("No DNS queries to display.")

    st.subheader("C2 IP Enrichment")
    ip_rows = []
    for ip, data in enrich.get("ips", {}).items():
        ip_rows.append(
            {
                "IP": ip,
                "Country": data.get("ip_api", {}).get("country", "?"),
                "ASN": data.get("rdap", {}).get("asn", "?"),
                "Org": data.get("ip_api", {}).get("org", "?"),
                "Reverse DNS": data.get("reverse_dns") or "-",
            }
        )
    if ip_rows:
        ip_df = pd.DataFrame(ip_rows)
        st.dataframe(ip_df.sort_values(by=["Country", "ASN"], ascending=[True, True]), use_container_width=True)
    else:
        st.info("No enrichment data loaded.")


if __name__ == "__main__":
    main()
