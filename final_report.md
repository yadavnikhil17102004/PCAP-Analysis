# PCAP Technical Test — Final Report

## Summary

This report answers the test questions and provides a detailed analysis of the provided pcap (`Take Home Test.pcap`). The capture shows DNS activity consistent with algorithmic domain generation and likely malware beaconing to command-and-control infrastructure. The original Google Drive link is provided in the Answer section.

## Question 1 — What is a Domain Generation Algorithm (DGA)?

- Definition: A Domain Generation Algorithm (DGA) is a deterministic algorithm used by malware to programmatically generate many domain names, typically pseudo-random, so the malware can attempt to contact a command-and-control (C2) server at those names. Only a small subset are registered by the attacker, making defense and takedown harder.
- Purpose: Avoid static IOCs by rotating domains; increase resilience of C2 infrastructure; frustrate defenders by creating a large search space of possible contact points.
- How it works (brief): The malware uses inputs (e.g., date, seed, algorithm parameters) to compute domain strings. Both the bot and attacker can compute the same sequence; attacker registers one or more of the generated names to host C2.
- Common signatures/indicators:
  - Many unique subdomains in a short period
  - Long, random-looking labels and high character entropy
  - Many NXDOMAIN responses or short TTLs
  - Multiple different labels resolving to the same IP (attacker controls SLD or many generated subdomains under an attacker-owned SLD)
  - Repeating timing/beacon intervals from infected hosts
- Detection approaches:
  - Lexical analysis (length, entropy, vowel/consonant patterns)
  - NXDOMAIN ratio and query volume monitoring
  - Passive DNS and WHOIS correlation (identify common second-level domains)
  - Machine learning using features from known DGA families
  - Sinkholing and reverse DNS/hosting analysis for clusters of suspicious names

## Question 2 — Analysis of supplied pcap

### Methodology

- Tools used: Python with Scapy to parse the pcap, `dnspython` + `whois` for lookups, and `ipwhois` + `ip-api.com` for IP enrichment. Scripts created in the workspace: `pcap_analysis.py`, `pcap_deep_analysis.py`, `ip_enrichment.py`.
- Output files: `pcap_deeper_results.json`, `ip_enrichment_results.json`, and `analysis_report.md` (human-readable). A final report is saved as `final_report.md` (this file).

### High-level facts

- Packets in capture: 16
- DNS queries: 8 (paired with 8 responses in capture)
- Unique DNS query names seen: 8
- NXDOMAIN responses in this capture: 0 (rcodes were 0 for the shown responses)

### Observed DNS queries and responses (selected)

From the capture (queries and the A answers observed inside the capture):

- va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in → A: 62.75.195.236
- ubb67.3c147o.u806a4.w07d919.o5f.f1.b80w.r0faf9.e8mfzdgrf7g0.groupprograms.in → A: 62.75.195.236
- r03afd2.c3008e.xc07r.b0f.a39.h7f0fa5eu.vb8fbl.e8mfzdgrf7g0.groupprograms.in → A: 62.75.195.236
- 7oqnsnzwwnm6zb7y.gigapaysun.com → A: 95.163.121.204
- ip-addr.es → A: 188.165.164.184
- runlove.us → A: 204.152.254.221
- comarksecurity.com → A: 72.34.49.86
- kritischerkonsum.uni-koeln.de → (no A recorded in the capture answers)

### Heuristics and DGA indicators

- Multiple queries contain long, high-entropy labels (measured entropy > 4.0 for the longest examples). Example: the long `groupprograms.in` subdomains have entropy ~4.6 — typical for algorithmically-generated labels.
- Several different generated labels (different subdomains) under the same second-level domain `groupprograms.in` resolve to the same IP `62.75.195.236` within the capture. This pattern is a strong signal of automated generation where the attacker registers one SLD and uses many generated subdomains.
- The capture timestamps show multiple queries in short intervals from the same internal host (see timeline below), which is consistent with periodic beaconing.

### Timeline (per internal host)

(Unix epoch timestamps are present in the pcap JSON results produced by the parsing script.)

- Internal host `192.168.138.158` issued queries for the high-entropy subdomains and normal domains. The local recursive resolver `192.168.138.2` answered with the A records as recorded in the capture.
- See `analysis_report.md` and `pcap_deeper_results.json` for the full timestamped list; the workspace file `analysis_report.md` contains the formatted timeline.

### Enrichment results (IP geolocation / RDAP)

Enrichment performed for IPs observed in answers (results from `ip_enrichment.py`):

- 62.75.195.236 — Reverse DNS: static-ip-62-75-195-236.inaddr.ip-pool.com; Country: France; ASN: AS29066 (velia.net)
- 95.163.121.204 — Reverse DNS: insconsulting.ru; Country: Russia; ASN: AS12695
- 188.165.164.184 — Reverse DNS: dynamicplus.it; Country: NL; ASN: AS16276 (OVH)
- 204.152.254.221 — No reverse DNS; Country: US; ASN: AS33055 (Brinkster)
- 72.34.49.86 — Reverse DNS: mail86.pi.elinuxservers.com; Country: US; ASN: AS33494

Note: Some live DNS/WHOIS queries executed from this environment returned NXDOMAIN or timed out for a subset of domains (possibly because domains were not registered at the public registrar at the time, or environment DNS restrictions apply). However, the capture itself includes authoritative answers for several of the queries which we used for enrichment.

## Interpretation — Is this related to information security?

Yes. The pcap contains DNS behavior strongly suggestive of malware-related C2 activity using DGA-like domains. Evidence:

- Lexical: Multiple long, random-looking subdomain labels with high entropy (not human-chosen names).
- Behavioral: Several generated-looking names resolved to the same external IP within seconds/minutes — consistent with attacker-controlled name registrations or wildcard DNS pointing to a C2 host.
- Temporal: Repeated queries from the same internal IP in a short timeframe (beacon-like pattern).

Taken together, the most likely explanation is that a host inside the captured network attempted to resolve algorithmically-generated domain names to contact a C2 server. Even though NXDOMAIN counts are low in this capture (rcodes were 0 when answers existed), the lexical and resolution patterns are independently strong indicators.

## Evidence / IOCs

- Suspicious domain patterns (examples observed in the pcap):
  - va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in
  - ubb67.3c147o.u806a4.w07d919.o5f.f1.b80w.r0faf9.e8mfzdgrf7g0.groupprograms.in
  - r03afd2.c3008e.xc07r.b0f.a39.h7f0fa5eu.vb8fbl.e8mfzdgrf7g0.groupprograms.in
  - 7oqnsnzwwnm6zb7y.gigapaysun.com
- IPs observed from DNS answers (take action to block/investigate):
  - 62.75.195.236
  - 95.163.121.204
  - 188.165.164.184
  - 204.152.254.221
  - 72.34.49.86

## Recommendations

1. Immediate containment:
   - Isolate the internal host `192.168.138.158` (source of the suspicious queries) from the network for further forensic analysis.
   - Block outbound connections to the listed IPs at the firewall and block DNS resolution to suspicious SLDs if possible.
2. Investigation:
   - Pull endpoint artifacts (autoruns, scheduled tasks, binaries, network connections) from the host `192.168.138.158`.
   - Query internal DNS logs and proxy logs for other hosts contacting the same domains or IPs.
   - Perform full AV/EDR scan and hunt for persistence mechanisms.
3. Enrichment & follow-up:
   - Query passive DNS and threat intel feeds for historical resolutions for `groupprograms.in`, `gigapaysun.com`, and the other SLDs; this may require API keys (e.g., VirusTotal, RiskIQ, PassiveTotal).
   - Check the registrant WHOIS and hosting providers for takedown or further action.
4. Remediation:
   - If compromise is confirmed, rebuild the affected host from a known-good image after evidence collection.
   - Rotate credentials that may have been exposed.

## Files produced (in workspace)

- `pcap_analysis.py` — initial parsing script
- `pcap_deep_analysis.py` — deeper DNS parsing and WHOIS attempts
- `pcap_deeper_results.json` — parsed pcap JSON results
- `ip_enrichment.py` — enrichment script
- `ip_enrichment_results.json` — IP enrichment output
- `analysis_report.md` — intermediate human-readable report
- `final_report.md` — this file (detailed answers and recommendations)

## Answer section (to be submitted)

1. Domain Generation Algorithm (DGA): see the dedicated section above ("Question 1").
   2a. Explanation of the pcap: see the "Analysis of supplied pcap" section above; summary: the capture shows DNS queries for multiple high-entropy subdomains and matching A answers for several names.
   2b. Is the file related to information security? Yes — it strongly indicates DGA-like malware beaconing; details and evidence are provided above.

Google Drive link (original pcap):
https://drive.google.com/file/d/1jad6drgd4gO7uG2F7nZmWy7vICGJhtEV/view?usp=sharing

---

Report generated from local analysis tools. If you want, I can also:

- Export a CSV of IOCs (domains + IPs),
- Generate YARA rules or Snort/Suricata rules for detected indicators,
- Run passive DNS lookups (requires API key) and integrate historical data.
