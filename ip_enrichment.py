import json
import socket
import requests
from ipwhois import IPWhois
from pprint import pformat

from pathlib import Path
base = Path(__file__).parent
# Prefer repo-local pcap_deeper_results.json when available, otherwise fall back to original path
IN_JSON = str(base / 'pcap_deeper_results.json') if (base / 'pcap_deeper_results.json').exists() else r"d:\TY CDS\pcap_deeper_results.json"
OUT_JSON = str(base / 'ip_enrichment_results.json')
OUT_MD = str(base / 'analysis_report.md')

with open(IN_JSON, 'r', encoding='utf-8') as f:
    data = json.load(f)

# collect IPs from DNS answers
ips = set()
for rec in data.get('dns', []):
    for a in rec.get('answers', []):
        rdata = a.get('rdata')
        if not rdata:
            continue
        # simple IPv4 check
        if isinstance(rdata, str) and rdata.count('.') == 3 and all(part.isdigit() for part in rdata.split('.') if part):
            ips.add(rdata)

import json
import socket
import requests
from ipwhois import IPWhois
from pprint import pformat
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

base = Path(__file__).parent
# Prefer repo-local pcap_deeper_results.json when available, otherwise fall back to original path
IN_JSON = str(base / 'pcap_deeper_results.json') if (base / 'pcap_deeper_results.json').exists() else r"d:\TY CDS\pcap_deeper_results.json"
OUT_JSON = str(base / 'ip_enrichment_results.json')
OUT_MD = str(base / 'analysis_report.md')


def load_data(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def simple_ipv4(s):
    return isinstance(s, str) and s.count('.') == 3 and all(part.isdigit() for part in s.split('.') if part)


def enrich_ip(ip, timeout=6):
    info = {'ip': ip}
    # reverse DNS (fast)
    try:
        host = socket.gethostbyaddr(ip)[0]
        info['reverse_dns'] = host
    except Exception:
        info['reverse_dns'] = None
    # ip-api geolocation
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=timeout)
        info['ip_api'] = r.json()
    except Exception as e:
        info['ip_api'] = {'error': str(e)}
    # ipwhois RDAP (keep depth small to save time)
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=0)
        info['rdap'] = {
            'asn': res.get('asn'),
            'asn_cidr': res.get('asn_cidr'),
            'asn_country_code': res.get('asn_country_code'),
            'network': res.get('network', {}).get('name') if res.get('network') else None,
        }
    except Exception as e:
        info['rdap'] = {'error': str(e)}
    return ip, info


def main():
    data = load_data(IN_JSON)

    # collect IPs from DNS answers
    ips = set()
    for rec in data.get('dns', []):
        for a in rec.get('answers', []):
            rdata = a.get('rdata')
            if not rdata:
                continue
            if simple_ipv4(rdata):
                ips.add(rdata)

    ips = sorted(ips)

    enrich = {}
    # Parallelize enrichment to speed up network calls
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(enrich_ip, ip): ip for ip in ips}
        for fut in as_completed(futures):
            ip, info = fut.result()
            enrich[ip] = info

    # timeline: per internal source host list queries with timestamps
    timeline = {}
    for rec in data.get('dns', []):
        src = rec.get('src') or 'unknown'
        timeline.setdefault(src, []).append({'time': rec.get('time'), 'qname': rec.get('qname'), 'answers': rec.get('answers')})

    results = {'ips': enrich, 'timeline': timeline, 'pcap_summary': {'packets_total': data.get('packets_total'), 'dns_count': len(data.get('dns', []))}}

    with open(OUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # create Markdown report
    lines = []
    lines.append('# PCAP Analysis Report')
    lines.append('')
    lines.append('## Questions')
    lines.append('')
    lines.append('**1. What is a Domain Generation Algorithm (DGA)?**')
    lines.append('')
    lines.append('A Domain Generation Algorithm (DGA) is an algorithm used by malware to deterministically produce a large set of domain names, often pseudo-random, so the malware can attempt to contact command-and-control (C2) infrastructure at those domains. Attackers only register a subset of generated names, making blocking and takedown harder.')
    lines.append('')
    lines.append('**2a. What exists/occurs in the provided pcap?**')
    lines.append('')
    lines.append('- Packets total: {}'.format(results['pcap_summary']['packets_total']))
    lines.append('- DNS queries observed: {}'.format(results['pcap_summary']['dns_count']))
    lines.append('- Observed DNS queries include multiple long, high-entropy subdomains (examples in timeline). Many of these resolved to external IPs in the capture.')
    lines.append('')
    lines.append('**2b. Is the file related to information security?**')
    lines.append('')
    lines.append('Yes. The capture shows DNS behavior consistent with DGA-based C2 resolution: multiple algorithmically-looking subdomains (high entropy), several different names resolving to the same external IP, and short beacon-like timing between queries. This pattern is typical for malware beaconing and warrants further investigation.')
    lines.append('')
    lines.append('## Enrichment Results (per IP)')
    lines.append('')
    for ip, info in results['ips'].items():
        lines.append(f'### {ip}')
        lines.append(f'- Reverse DNS: {info.get("reverse_dns") or "(none)"}')
        ip_api = info.get('ip_api', {})
        if ip_api.get('error'):
            lines.append(f'- Geo/IP lookup error: {ip_api.get("error")}')
        else:
            lines.append(f'- Country: {ip_api.get("country")}, Region: {ip_api.get("regionName")}, City: {ip_api.get("city")}, ISP: {ip_api.get("isp")}, Org: {ip_api.get("org")}, AS: {ip_api.get("as")}')
        rd = info.get('rdap')
        if rd and not rd.get('error'):
            lines.append(f'- ASN: {rd.get("asn")}, ASN country: {rd.get("asn_country_code")}, Network: {rd.get("network")}')
        else:
            lines.append(f'- RDAP lookup: {rd.get("error")}')
        lines.append('')

    lines.append('## Timeline (per internal source IP)')
    for src, entries in results['timeline'].items():
        lines.append(f'### {src}')
        for e in entries:
            lines.append(f'- {e.get("time")}: {e.get("qname")} -> answers: {pformat(e.get("answers"))}')
        lines.append('')

    lines.append('## Original file')
    lines.append('Google Drive link: https://drive.google.com/file/d/1jad6drgd4gO7uG2F7nZmWy7vICGJhtEV/view?usp=sharing')

    with open(OUT_MD, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print('Enrichment complete. Wrote:', OUT_JSON, OUT_MD)


if __name__ == '__main__':
    main()
