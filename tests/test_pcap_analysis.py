from scapy.all import DNS, TCP, UDP, ICMP, rdpcap

from archive.pipeline.pcap_toolkit.analysis import analyze_pcap
from dashboard_app.analysis import build_query_df
from dns_heuristics import DGA_ENTROPY_THRESHOLD, score_dns_entropy


def _raw_dns_query_names(pcap):
    names = set()
    for pkt in pcap:
        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd and getattr(pkt[DNS].qd, "qname", None):
            names.add(pkt[DNS].qd.qname.decode(errors="ignore").rstrip("."))
    return names


def test_report_protocol_counts_match_raw_scapy(sample_pcap_path):
    raw = rdpcap(str(sample_pcap_path))
    raw_tcp = sum(1 for p in raw if p.haslayer(TCP))
    raw_udp = sum(1 for p in raw if p.haslayer(UDP))
    raw_icmp = sum(1 for p in raw if p.haslayer(ICMP))

    report = analyze_pcap(str(sample_pcap_path))

    assert report["tcp_count"] == raw_tcp
    assert report["udp_count"] == raw_udp
    assert report["icmp_count"] == raw_icmp
    assert report["packet_counts"] == {"TCP": raw_tcp, "UDP": raw_udp, "ICMP": raw_icmp}


def test_dns_unique_names_preserved(sample_pcap_path):
    raw = rdpcap(str(sample_pcap_path))
    raw_names = _raw_dns_query_names(raw)
    report = analyze_pcap(str(sample_pcap_path))
    names = {q["name"] for q in report["dns_queries"] if q.get("name")}

    assert len(raw_names) == 10
    assert len(names) == len(raw_names)
    assert names == raw_names


def test_benign_suffixes_not_flagged(sample_pcap_path):
    report = analyze_pcap(str(sample_pcap_path))
    flagged = report["dga_candidates"]
    flagged_names = {item["name"] for item in flagged}

    assert not any(name.endswith(".local") for name in flagged_names)
    assert "accounts.youtube.com" not in flagged_names
    assert "api.github.com" not in flagged_names
    assert all(not item["known_benign_pattern"] for item in flagged)


def test_dashboard_marks_benign_suffixes_and_keeps_tiered_scores(sample_pcap_path):
    report = analyze_pcap(str(sample_pcap_path))
    df = build_query_df(report["dns_queries"])

    local = df[df["qname"].str.endswith(".local", na=False)]
    assert not local.empty
    assert local["known_benign_pattern"].all()
    assert local["entropy_score"].isna().all()
    assert (local["severity"] == "LOW").all()


def test_dga_still_detects_non_benign_high_entropy():
    result = score_dns_entropy("kq3xj9zvbp1mfe.com")

    assert result["known_benign_pattern"] is False
    assert result["entropy_score"] is not None
    assert result["entropy_score"] > DGA_ENTROPY_THRESHOLD
