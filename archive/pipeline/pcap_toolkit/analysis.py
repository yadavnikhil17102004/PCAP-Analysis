import re

from scapy.all import Raw, rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP

from pcap_toolkit.common import entropy


def analyze_pcap(pcap_path):
    packets = rdpcap(pcap_path)

    dns_queries = []
    dns_responses = []
    hosts_http = set()
    sni_tls = set()

    for pkt in packets:
        try:
            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qdcount > 0 and dns.qd:
                    qname = dns.qd.qname.decode().rstrip(".") if hasattr(dns.qd, "qname") else None
                    info = {
                        "time": getattr(pkt, "time", None),
                        "src": pkt[0].src if hasattr(pkt[0], "src") else None,
                        "dst": pkt[0].dst if hasattr(pkt[0], "dst") else None,
                        "qname": qname,
                        "rcode": dns.rcode,
                        "qr": dns.qr,
                    }
                    if dns.qr == 0:
                        dns_queries.append(info)
                    else:
                        dns_responses.append(info)

            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                try:
                    if b"Host:" in payload:
                        host_match = re.search(br"Host:\s*([^\r\n]+)", payload)
                        if host_match:
                            hosts_http.add(host_match.group(1).decode(errors="ignore").strip())
                except Exception:
                    pass

                try:
                    ascii_domains = re.findall(rb"[a-zA-Z0-9][-a-zA-Z0-9\.]{2,}\.[a-zA-Z]{2,}", payload)
                    for candidate in ascii_domains:
                        domain = candidate.decode(errors="ignore")
                        if not re.match(r"\d+\.\d+\.\d+\.\d+", domain):
                            sni_tls.add(domain)
                except Exception:
                    pass
        except Exception:
            continue

    unique_qnames = set(query["qname"] for query in dns_queries if query.get("qname"))

    qname_stats = []
    for name in unique_qnames:
        ent = entropy(name.replace(".", ""))
        qname_stats.append((name, len(name), ent))

    return {
        "packets_total": len(packets),
        "dns_queries": dns_queries,
        "dns_responses": dns_responses,
        "unique_qnames": unique_qnames,
        "qname_stats": qname_stats,
        "hosts_http": hosts_http,
        "sni_tls": sni_tls,
    }


def print_summary(results, top_domains=20, sample_queries=30):
    qname_stats_sorted = sorted(results["qname_stats"], key=lambda item: item[2], reverse=True)
    nxdomain_count = sum(1 for resp in results["dns_responses"] if resp.get("rcode", 0) != 0)

    print("SUMMARY")
    print("Packets total:", results["packets_total"])
    print("DNS queries total:", len(results["dns_queries"]))
    print("DNS responses total:", len(results["dns_responses"]))
    print("Unique DNS query names:", len(results["unique_qnames"]))
    print("NXDOMAIN-like responses (rcode != 0):", nxdomain_count)

    print("\nTop domains by entropy (heuristic for randomness):")
    for name, length, ent in qname_stats_sorted[:top_domains]:
        print(f"- {name} (len={length}, entropy={ent:.3f})")

    print("\nTop HTTP Host headers:")
    for host in sorted(results["hosts_http"]):
        print("-", host)

    print("\nTLS SNI-like strings found:")
    for sni in sorted(results["sni_tls"]):
        print("-", sni)

    high_entropy_count = sum(
        1 for _, length, ent in results["qname_stats"] if ent > 3.5 and length > 12
    )
    print("\nDGA-like domains (entropy>3.5 and length>12):", high_entropy_count)

    print("\nSample DNS queries (first 30):")
    for query in results["dns_queries"][:sample_queries]:
        print("-", query.get("qname"), "from", query.get("src"))
