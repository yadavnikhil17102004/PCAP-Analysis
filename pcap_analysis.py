from scapy.all import rdpcap, Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, UDP
import re
import sys
import math
from pathlib import Path

# Prefer a workspace-local PCAP named `Evidence.pcap` if present, otherwise fall back to original path
local_pcap = Path(__file__).parent / 'Evidence.pcap'
PCAP_PATH = str(local_pcap) if local_pcap.exists() else r"d:\TY CDS\Take Home Test.pcap"

def entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum([p * math.log(p, 2) for p in prob])

packets = rdpcap(PCAP_PATH)

dns_queries = []
dns_responses = []
hosts_http = set()
sni_tls = set()

for pkt in packets:
    try:
        if DNS in pkt:
            dns = pkt[DNS]
            # Support queries with multiple QD
            if dns.qdcount > 0 and dns.qd:
                qname = dns.qd.qname.decode().rstrip('.') if hasattr(dns.qd, 'qname') else None
                info = {
                    'time': getattr(pkt, 'time', None),
                    'src': pkt[0].src if hasattr(pkt[0], 'src') else None,
                    'dst': pkt[0].dst if hasattr(pkt[0], 'dst') else None,
                    'qname': qname,
                    'rcode': dns.rcode,
                    'qr': dns.qr,
                }
                if dns.qr == 0:
                    dns_queries.append(info)
                else:
                    dns_responses.append(info)
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            # HTTP Host header
            try:
                if b'Host:' in payload:
                    m = re.search(br'Host:\s*([^\r\n]+)', payload)
                    if m:
                        hosts_http.add(m.group(1).decode(errors='ignore').strip())
            except Exception:
                pass
            # TLS SNI heuristic: search for domain-like ASCII in the payload near typical ClientHello
            try:
                # look for ASCII domain patterns in payload
                ascii_strs = re.findall(rb'[a-zA-Z0-9][-a-zA-Z0-9\.]{2,}\.[a-zA-Z]{2,}', payload)
                for s in ascii_strs:
                    s_dec = s.decode(errors='ignore')
                    # filter out IPs-like
                    if not re.match(r'\d+\.\d+\.\d+\.\d+', s_dec):
                        sni_tls.add(s_dec)
            except Exception:
                pass
    except Exception:
        continue

# Compute DNS domain stats
unique_qnames = set([q['qname'] for q in dns_queries if q['qname']])
unique_resp_qnames = set([r['qname'] for r in dns_responses if r['qname']])

qname_stats = []
for name in unique_qnames:
    ent = entropy(name.replace('.', ''))
    qname_stats.append((name, len(name), ent))

qname_stats_sorted = sorted(qname_stats, key=lambda x: x[2], reverse=True)[:30]

# NXDOMAIN heuristic: count responses with rcode != 0
nxdomain_count = sum(1 for r in dns_responses if r.get('rcode', 0) != 0)

print('SUMMARY')
print('Packets total:', len(packets))
print('DNS queries total:', len(dns_queries))
print('DNS responses total:', len(dns_responses))
print('Unique DNS query names:', len(unique_qnames))
print('NXDOMAIN-like responses (rcode != 0):', nxdomain_count)
print('\nTop domains by entropy (heuristic for randomness):')
for name, ln, ent in qname_stats_sorted[:20]:
    print(f"- {name} (len={ln}, entropy={ent:.3f})")

print('\nTop HTTP Host headers:')
for h in sorted(hosts_http):
    print('-', h)

print('\nTLS SNI-like strings found:')
for s in sorted(sni_tls):
    print('-', s)

# Provide simple DGA heuristic:
high_entropy_count = sum(1 for _, ln, ent in qname_stats if ent > 3.5 and ln > 12)
print('\nDGA-like domains (entropy>3.5 and length>12):', high_entropy_count)

# Small sample of queries (first 30)
print('\nSample DNS queries (first 30):')
for q in dns_queries[:30]:
    print('-', q.get('qname'), 'from', q.get('src'))

# Exit
sys.exit(0)
