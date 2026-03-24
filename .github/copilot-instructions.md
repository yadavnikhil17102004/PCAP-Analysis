# Project Guidelines

## Architecture
- This repository is a sequential analysis pipeline, not a package or service.
- Script order matters:
  1. `pcap_analysis.py` for quick DNS/HTTP/TLS reconnaissance.
  2. `pcap_deep_analysis.py` to produce `pcap_deeper_results.json`.
  3. `ip_enrichment.py` to produce `ip_enrichment_results.json` and `analysis_report.md`.
- Downstream scripts depend on upstream JSON structure. Preserve existing keys unless all dependent scripts are updated together.

## Build And Test
- Environment setup:
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt`
- Run pipeline:
  - `python pcap_analysis.py`
  - `python pcap_deep_analysis.py`
  - `python ip_enrichment.py`
- There is no formal automated test suite. Validate changes by running the pipeline and checking output artifacts are generated and parse correctly.

## Conventions
- Keep scripts executable as standalone files with a `main()` entrypoint where practical.
- Prefer workspace-relative paths via `Path(__file__).parent` with safe fallbacks instead of hardcoded machine-specific paths.
- Use defensive parsing for packet fields (best-effort extraction with graceful failure) because malformed PCAP data is expected.
- External enrichment calls (DNS/WHOIS/RDAP/GeoIP) must be timeout-bounded and failure-tolerant.
- Avoid large refactors that change output semantics unless explicitly requested.

## References
- Setup and usage details: `README.md`
- Analysis context and expected reporting style: `final_report.md`