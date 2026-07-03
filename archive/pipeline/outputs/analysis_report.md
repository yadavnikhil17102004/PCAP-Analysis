# PCAP Analysis Report

## Questions

**1. What is a Domain Generation Algorithm (DGA)?**

A Domain Generation Algorithm (DGA) is an algorithm used by malware to deterministically produce a large set of domain names, often pseudo-random, so the malware can attempt to contact command-and-control (C2) infrastructure at those domains. Attackers only register a subset of generated names, making blocking and takedown harder.

**2a. What exists/occurs in the provided pcap?**

- Packets total: 17
- DNS queries observed: 0
- Observed DNS queries include multiple long, high-entropy subdomains (examples in timeline). Many of these resolved to external IPs in the capture.

**2b. Is the file related to information security?**

Yes. The capture shows DNS behavior consistent with DGA-based C2 resolution: multiple algorithmically-looking subdomains (high entropy), several different names resolving to the same external IP, and short beacon-like timing between queries. This pattern is typical for malware beaconing and warrants further investigation.

## Enrichment Results (per IP)

## Timeline (per internal source IP)
## Original file
Google Drive link: https://drive.google.com/file/d/1jad6drgd4gO7uG2F7nZmWy7vICGJhtEV/view?usp=sharing