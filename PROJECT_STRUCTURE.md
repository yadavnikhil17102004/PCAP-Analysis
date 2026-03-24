# Project Structure

## Active Source

- `dashboard.py`
  - Root launcher for Streamlit command compatibility.
- `dashboard_app/dashboard.py`
  - Main Streamlit investigation console.
- `dashboard_app/RUNTIME_REQUIRED.md`
  - Runtime dependency manifest for dashboard mode.
- `wireshark/`
  - Lua post-dissector and coloring rules for packet-level triage.

## Inputs

- `Evidence.pcap`
  - Default input used when no `--pcap` override is supplied.

## Generated Artifacts

- `outputs/pcap_deeper_results.json`
- `outputs/ip_enrichment_results.json`
- `outputs/analysis_report.md`

Generated artifacts are intentionally separated from source files to keep root navigation clean.

## Reference / Supporting Docs

- `README.md`
  - Setup, execution, and dashboard usage.
- `final_report.md`
  - Narrative investigation report.
- `plan.md`
  - Roadmap and implementation notes.

## Archived Pipeline Source

- `archive/pipeline/pcap_analysis.py`
- `archive/pipeline/pcap_deep_analysis.py`
- `archive/pipeline/ip_enrichment.py`
- `archive/pipeline/pcap_toolkit/`

These files are preserved but not required for running `streamlit run dashboard.py`.
