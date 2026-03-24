import json
from pathlib import Path

import dns.resolver
import whois
from scapy.all import rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import IP

from pcap_toolkit.common import entropy, sld


def _extract_answers(dns_pkt):
    answers = []
    try:
        for index in range(dns_pkt.ancount):
            rr = dns_pkt.an[index]
            answers.append(
                {
                    "rrname": rr.rrname.decode().rstrip(".") if hasattr(rr, "rrname") else None,
                    "type": int(rr.type) if hasattr(rr, "type") else None,
                    "rdata": str(rr.rdata) if hasattr(rr, "rdata") else None,
                }
            )
    except Exception:
        try:
            for rr in dns_pkt.an:
                answers.append(
                    {
                        "rrname": getattr(rr, "rrname", None),
                        "type": getattr(rr, "type", None),
                        "rdata": getattr(rr, "rdata", None),
                    }
                )
        except Exception:
            pass
    return answers


def _enrich_whois(domain):
    try:
        whois_result = whois.whois(domain)
        try:
            whois_dict = dict(whois_result)
        except Exception:
            try:
                whois_dict = {k: v for k, v in whois_result.items()}
            except Exception:
                whois_dict = {}

        converted = {}
        for key, value in whois_dict.items():
            if value is None:
                converted[key] = None
            elif isinstance(value, (list, tuple, set)):
                converted[key] = [str(item) for item in value]
            else:
                converted[key] = str(value)
        return converted
    except Exception as exc:
        return {"error": str(exc)}


def run_deep_analysis(pcap_path, out_json=None):
    packets = rdpcap(pcap_path)
    results = {"packets_total": len(packets), "dns": [], "suspicious_slds": {}}

    for pkt in packets:
        try:
            if DNS not in pkt:
                continue

            dns_pkt = pkt[DNS]
            record = {
                "time": getattr(pkt, "time", None),
                "src": pkt[IP].src if IP in pkt else None,
                "dst": pkt[IP].dst if IP in pkt else None,
                "id": dns_pkt.id,
                "qr": int(dns_pkt.qr),
                "qdcount": int(dns_pkt.qdcount),
                "ancount": int(dns_pkt.ancount),
                "rcode": int(dns_pkt.rcode),
            }

            try:
                if dns_pkt.qd and hasattr(dns_pkt.qd, "qname"):
                    record["qname"] = dns_pkt.qd.qname.decode().rstrip(".")
                    record["qtype"] = int(dns_pkt.qd.qtype)
                else:
                    record["qname"] = None
                    record["qtype"] = None
            except Exception:
                record["qname"] = None
                record["qtype"] = None

            record["answers"] = _extract_answers(dns_pkt)
            results["dns"].append(record)
        except Exception:
            continue

    unique_qnames = set(item["qname"] for item in results["dns"] if item.get("qname"))
    sld_map = {}
    for qname in unique_qnames:
        top_domain = sld(qname)
        sld_map.setdefault(top_domain, []).append(qname)

    suspicious = {}
    for top_domain, qname_list in sld_map.items():
        high_entropy_examples = []
        for qname in qname_list:
            label = qname.split(".")[0] if "." in qname else qname
            ent = entropy(label)
            if ent > 3.5 and len(label) > 10:
                high_entropy_examples.append(
                    {"qname": qname, "label_entropy": ent, "label_len": len(label)}
                )

        if high_entropy_examples or len(qname_list) > 5:
            suspicious[top_domain] = {
                "count_subdomains": len(qname_list),
                "high_entropy_examples": high_entropy_examples[:5],
            }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    for top_domain in suspicious.keys():
        enrichment = {"a_records": [], "ns_records": [], "whois": None}

        try:
            a_answers = resolver.resolve(top_domain, "A")
            enrichment["a_records"] = [record.to_text() for record in a_answers]
        except Exception:
            enrichment["a_records"] = []

        try:
            ns_answers = resolver.resolve(top_domain, "NS")
            enrichment["ns_records"] = [record.to_text() for record in ns_answers]
        except Exception:
            enrichment["ns_records"] = []

        enrichment["whois"] = _enrich_whois(top_domain)
        results["suspicious_slds"][top_domain] = enrichment

    if out_json:
        Path(out_json).parent.mkdir(parents=True, exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2, ensure_ascii=False, default=lambda value: str(value))

    return results
