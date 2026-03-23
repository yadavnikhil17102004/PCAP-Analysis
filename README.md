# PCAP Analysis

Brief collection of scripts to analyze a provided PCAP for DNS/DGA-like activity and enrich results with IP/WHOIS data.

**Contents**

- `pcap_analysis.py` — quick scan: DNS queries, HTTP Host headers, TLS SNI-like strings, and simple DGA heuristics.
- `pcap_deep_analysis.py` — parses DNS records from the PCAP, aggregates SLDs, applies entropy heuristics, performs DNS/WHOIS enrichment and writes `pcap_deeper_results.json`.
- `ip_enrichment.py` — reads `pcap_deeper_results.json`, collects A records IPs, performs reverse DNS, geo/IP (ip-api), and RDAP (`ipwhois`) lookups, writes `ip_enrichment_results.json` and `analysis_report.md`.
- `whois_test.py` — small WHOIS test script used during development.
- `Evidence.pcap` — (example PCAP file; replace with your capture).

**Quick start / prerequisites**

- Requires Python 3.8+ and internet access for enrichment lookups.
- Recommended packages:

```bash
pip install scapy whois dnspython ipwhois requests ip-api-python
# or the minimal set:
pip install scapy python-whois dnspython ipwhois requests
```

Note: package names vary (e.g. `whois` vs `python-whois`). If a script errors on import, try the alternate package name.

**Usage**

1. Edit hardcoded paths inside the scripts if needed (variables like `PCAP_PATH`, `OUT_JSON`, `OUT_MD` point to `d:\TY CDS\...` in the current files). Update to your local paths or place the PCAP at the expected path.

2. Run the scripts in order for a full pipeline:

```bash
python pcap_analysis.py
python pcap_deep_analysis.py
python ip_enrichment.py
```

3. Outputs produced by the pipeline (defaults shown in the scripts):

- `pcap_deeper_results.json` — parsed DNS records and enrichment for suspicious SLDs
- `ip_enrichment_results.json` — per-IP enrichment (RDAP, geo, reverse DNS)
- `analysis_report.md` — human-readable Markdown report summarizing findings

**Notes & caveats**

- The scripts use simple heuristics (label entropy and subdomain counts) to flag suspicious domains — treat results as investigative leads, not definitive indicators.
- Many paths are hardcoded; for repeatable use, parameterize paths or wrap scripts with a small runner that accepts command-line arguments.
- Enrichment steps perform external network calls and may be rate-limited by services (e.g., `ip-api.com`) or require API keys for production-grade use.

**Next suggestions**

- Add CLI flags (`--pcap`, `--out-dir`) to avoid editing source files.
- Add unit tests around parsing helpers when refactoring.

---

Generated README for the repository. Update any paths before running the scripts.
