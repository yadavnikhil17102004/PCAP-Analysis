"""PCAP triage helpers."""

import re

from scapy.all import Raw, rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, TCP, UDP

from dns_heuristics import DGA_ENTROPY_THRESHOLD, DGA_LABEL_LENGTH_THRESHOLD, score_dns_entropy


HOST_HEADER_PATTERN = re.compile(br"Host:\s*([^\r\n]+)")
ASCII_DOMAIN_PATTERN = re.compile(rb"[a-zA-Z0-9][-a-zA-Z0-9\.]{2,}\.[a-zA-Z]{2,}")
IPV4_PATTERN = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def _decode_name(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode(errors="ignore").rstrip(".")
    return str(value).rstrip(".")


def _score_qname(qname):
    return score_dns_entropy(qname)


def analyze_pcap(pcap_path):
    packets = rdpcap(pcap_path)

    packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
    dns_queries = []
    dns_responses = []
    hosts_http = set()
    sni_tls = set()

    for pkt in packets:
        try:
            if TCP in pkt:
                packet_counts["TCP"] += 1
            if UDP in pkt:
                packet_counts["UDP"] += 1
            if ICMP in pkt:
                packet_counts["ICMP"] += 1

            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qdcount > 0 and dns.qd:
                    qname = _decode_name(getattr(dns.qd, "qname", None))
                    info = {
                        "time": getattr(pkt, "time", None),
                        "src": pkt[0].src if hasattr(pkt[0], "src") else None,
                        "dst": pkt[0].dst if hasattr(pkt[0], "dst") else None,
                        "name": qname,
                        "qname": qname,
                        "tx_id": int(getattr(dns, "id", 0) or 0),
                        "rcode": int(getattr(dns, "rcode", 0) or 0),
                        "qr": int(getattr(dns, "qr", 0) or 0),
                    }
                    if dns.qr == 0:
                        dns_queries.append(info)
                    else:
                        dns_responses.append(info)

            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                try:
                    if b"Host:" in payload:
                        host_match = HOST_HEADER_PATTERN.search(payload)
                        if host_match:
                            hosts_http.add(host_match.group(1).decode(errors="ignore").strip())
                except Exception:
                    pass

                try:
                    if b"." in payload:
                        ascii_domains = ASCII_DOMAIN_PATTERN.findall(payload)
                        for candidate in ascii_domains:
                            domain = candidate.decode(errors="ignore")
                            if not IPV4_PATTERN.match(domain):
                                sni_tls.add(domain)
                except Exception:
                    pass
        except Exception:
            continue

    unique_qnames = list(dict.fromkeys(query["name"] for query in dns_queries if query.get("name")))

    qname_stats = []
    dga_candidates = []
    for name in unique_qnames:
        scored = _score_qname(name)
        qname_stats.append(scored)
        if not scored["known_benign_pattern"] and scored["entropy_score"] is not None:
            if scored["entropy_score"] > DGA_ENTROPY_THRESHOLD and scored["label_length"] > DGA_LABEL_LENGTH_THRESHOLD:
                dga_candidates.append(scored)

    return {
        "packets_total": len(packets),
        "packet_counts": packet_counts,
        "tcp_count": packet_counts["TCP"],
        "udp_count": packet_counts["UDP"],
        "icmp_count": packet_counts["ICMP"],
        "dns_queries": dns_queries,
        "dns_responses": dns_responses,
        "unique_qnames": unique_qnames,
        "qname_stats": qname_stats,
        "dga_candidates": dga_candidates,
        "hosts_http": hosts_http,
        "sni_tls": sni_tls,
    }


def print_summary(results, top_domains=20, sample_queries=30):
    qname_stats_sorted = sorted(
        (item for item in results["qname_stats"] if item.get("entropy_score") is not None),
        key=lambda item: item["entropy_score"],
        reverse=True,
    )
    nxdomain_count = sum(1 for resp in results["dns_responses"] if resp.get("rcode", 0) != 0)

    print("SUMMARY")
    print("Packets total:", results["packets_total"])
    print("TCP packets:", results.get("tcp_count", results.get("packet_counts", {}).get("TCP", 0)))
    print("UDP packets:", results.get("udp_count", results.get("packet_counts", {}).get("UDP", 0)))
    print("ICMP packets:", results.get("icmp_count", results.get("packet_counts", {}).get("ICMP", 0)))
    print("DNS queries total:", len(results["dns_queries"]))
    print("DNS responses total:", len(results["dns_responses"]))
    print("Unique DNS query names:", len(results["unique_qnames"]))
    print("NXDOMAIN-like responses (rcode != 0):", nxdomain_count)

    print("\nTop domains by entropy (heuristic for randomness):")
    for item in qname_stats_sorted[:top_domains]:
        print(f"- {item['name']} (len={item['label_length']}, entropy={item['entropy_score']:.3f})")

    print("\nTop HTTP Host headers:")
    for host in sorted(results["hosts_http"]):
        print("-", host)

    print("\nTLS SNI-like strings found:")
    for sni in sorted(results["sni_tls"]):
        print("-", sni)

    print("\nDGA-like domains (entropy>3.5 and length>12):", len(results.get("dga_candidates", [])))

    print("\nSample DNS queries (first 30):")
    for query in results["dns_queries"][:sample_queries]:
        print("-", query.get("name") or query.get("qname"), "from", query.get("src"))
