import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from pcap_toolkit.common import entropy, sld

BASE = Path(__file__).resolve().parent
DEFAULT_DEEP = BASE / "pcap_deeper_results.json"
DEFAULT_ENRICH = BASE / "ip_enrichment_results.json"


@st.cache_data(show_spinner=False)
def load_data(deep_path, enrich_path):
    with open(deep_path, "r", encoding="utf-8") as f:
        deep = json.load(f)
    with open(enrich_path, "r", encoding="utf-8") as f:
        enrich = json.load(f)
    return deep, enrich


def main():
    st.set_page_config(page_title="PCAP Investigator", layout="wide")
    st.title("PCAP Investigator Dashboard")

    deep_path = st.sidebar.text_input("Deep analysis JSON", str(DEFAULT_DEEP))
    enrich_path = st.sidebar.text_input("Enrichment JSON", str(DEFAULT_ENRICH))
    deep, enrich = load_data(deep_path, enrich_path)

    dns_records = deep.get("dns", [])
    queries = [r for r in dns_records if r.get("qr") == 0]
    answered = [r for r in dns_records if r.get("qr") == 1 and r.get("answers")]
    c2_ips = list(enrich.get("ips", {}).keys())

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total packets", deep.get("packets_total"))
    col2.metric("DNS queries", len(queries))
    col3.metric("Answered", len(answered))
    col4.metric("Unique C2 IPs", len(c2_ips))

    # Timeline scatter
    st.subheader("DNS query timeline")
    timeline_rows = []
    suspicious_slds = set((deep.get("suspicious_slds") or {}).keys())
    for r in queries:
        qname = r.get("qname")
        if not qname:
            continue
        label = qname.split(".")[0]
        timeline_rows.append(
            {
                "time": datetime.fromtimestamp(float(r.get("time", 0))),
                "entropy": entropy(label),
                "domain": qname,
                "src": r.get("src") or "unknown",
                "sld": sld(qname),
                "suspicious": sld(qname) in suspicious_slds,
            }
        )
    if timeline_rows:
        df = pd.DataFrame(timeline_rows)
        fig = px.scatter(
            df,
            x="time",
            y="entropy",
            color="suspicious",
            hover_data=["domain", "src", "sld"],
            color_discrete_map={True: "red", False: "steelblue"},
            title="Query entropy over time",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No DNS queries to display.")

    # Enrichment table
    st.subheader("C2 IP enrichment")
    ip_rows = []
    for ip, data in enrich.get("ips", {}).items():
        ip_rows.append(
            {
                "IP": ip,
                "Country": data.get("ip_api", {}).get("country", "?"),
                "ASN": data.get("rdap", {}).get("asn", "?"),
                "Org": data.get("ip_api", {}).get("org", "?"),
                "Reverse DNS": data.get("reverse_dns") or "—",
            }
        )
    if ip_rows:
        st.dataframe(pd.DataFrame(ip_rows), use_container_width=True)
    else:
        st.info("No enrichment data loaded.")


if __name__ == "__main__":
    main()
