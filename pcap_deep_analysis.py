from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP, TCP
import socket
import whois
import dns.resolver
import re
import json
import sys
from pathlib import Path

# Prefer a workspace-local PCAP named `Evidence.pcap` if present, otherwise fall back to original path
base = Path(__file__).parent
local_pcap = base / 'Evidence.pcap'
PCAP_PATH = str(local_pcap) if local_pcap.exists() else r"d:\TY CDS\Take Home Test.pcap"
# Write deeper results into repository folder by default
OUT_JSON = str(base / 'pcap_deeper_results.json')

packets = rdpcap(PCAP_PATH)
results = {
    'packets_total': len(packets),
    'dns': [],
    'suspicious_slds': {}
}

# helper to extract SLD+TLD from a domain
def sld(domain):
    parts = domain.rstrip('.').split('.')
    if len(parts) >= 2:
        return parts[-2] + '.' + parts[-1]
    return domain

for pkt in packets:
    try:
        if DNS in pkt:
            dns_pkt = pkt[DNS]
            record = {
                'time': getattr(pkt, 'time', None),
                'src': pkt[IP].src if IP in pkt else None,
                'dst': pkt[IP].dst if IP in pkt else None,
                'id': dns_pkt.id,
                'qr': int(dns_pkt.qr),
                'qdcount': int(dns_pkt.qdcount),
                'ancount': int(dns_pkt.ancount),
                'rcode': int(dns_pkt.rcode)
            }
            # question
            try:
                if dns_pkt.qd and hasattr(dns_pkt.qd, 'qname'):
                    record['qname'] = dns_pkt.qd.qname.decode().rstrip('.')
                    record['qtype'] = int(dns_pkt.qd.qtype)
                else:
                    record['qname'] = None
                    record['qtype'] = None
            except Exception:
                record['qname'] = None
                record['qtype'] = None
            # answers
            answers = []
            try:
                for i in range(dns_pkt.ancount):
                    rr = dns_pkt.an[i]
                    ans = {
                        'rrname': rr.rrname.decode().rstrip('.') if hasattr(rr, 'rrname') else None,
                        'type': int(rr.type) if hasattr(rr, 'type') else None,
                        'rdata': str(rr.rdata) if hasattr(rr, 'rdata') else None
                    }
                    answers.append(ans)
            except Exception:
                # fallback: iterate rrrecords if available
                try:
                    for rr in dns_pkt.an:
                        ans = {
                            'rrname': getattr(rr, 'rrname', None),
                            'type': getattr(rr, 'type', None),
                            'rdata': getattr(rr, 'rdata', None)
                        }
                        answers.append(ans)
                except Exception:
                    pass
            record['answers'] = answers
            results['dns'].append(record)
    except Exception:
        continue

# Collect unique query names and compute suspicious SLDs
unique_qnames = set([d['qname'] for d in results['dns'] if d.get('qname')])
sld_map = {}
for q in unique_qnames:
    s = sld(q)
    sld_map.setdefault(s, []).append(q)

# Heuristic: consider slds with at least one high-entropy subdomain or many unique subdomains suspicious
import math

def entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum([p * math.log(p, 2) for p in prob])

suspicious = {}
for s, qlist in sld_map.items():
    high_ent = []
    for q in qlist:
        label = q.split('.')[0] if '.' in q else q
        ent = entropy(label)
        if ent > 3.5 and len(label) > 10:
            high_ent.append({'qname': q, 'label_entropy': ent, 'label_len': len(label)})
    if high_ent or len(qlist) > 5:
        suspicious[s] = {'count_subdomains': len(qlist), 'high_entropy_examples': high_ent[:5]}

# Enrichment: for each suspicious SLD perform DNS A/NS and WHOIS (best-effort)
resolver = dns.resolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 8

for s in suspicious.keys():
    enrich = {'a_records': [], 'ns_records': [], 'whois': None}
    try:
        answers = resolver.resolve(s, 'A')
        enrich['a_records'] = [r.to_text() for r in answers]
    except Exception as e:
        enrich['a_records'] = []
    try:
        answers = resolver.resolve(s, 'NS')
        enrich['ns_records'] = [r.to_text() for r in answers]
    except Exception:
        enrich['ns_records'] = []
    # WHOIS
    try:
        w = whois.whois(s)
        try:
            wdict = dict(w)
        except Exception:
            # fall back to items() iterator
            try:
                wdict = {k: v for k, v in w.items()}
            except Exception:
                wdict = {}
        conv = {}
        for k, v in wdict.items():
            if v is None:
                conv[k] = None
            elif isinstance(v, (list, tuple, set)):
                conv[k] = [str(x) for x in v]
            else:
                conv[k] = str(v)
        enrich['whois'] = conv
    except Exception as e:
        enrich['whois'] = {'error': str(e)}
    results['suspicious_slds'][s] = enrich

# Save results to JSON
with open(OUT_JSON, 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=2, ensure_ascii=False, default=lambda o: str(o))

print('Deeper analysis complete. Results written to', OUT_JSON)
print('Suspicious SLDs:', list(results['suspicious_slds'].keys()))
sys.exit(0)
