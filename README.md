# PCAP Analysis Toolkit

Sequential DNS-focused investigation pipeline for PCAP triage, enrichment, and reporting.

## What Is Active

### Dashboard runtime (current active mode)
- `dashboard.py`: root launcher, keeps command `streamlit run dashboard.py` working.
- `dashboard_app/dashboard.py`: main Streamlit investigation app.
- `dashboard_app/RUNTIME_REQUIRED.md`: exact runtime file list.

### Wireshark integration
- `wireshark/dga_dns_postdissector.lua`
- `wireshark/dga_coloring.xml`
- `wireshark/README.md`

## Repository Layout

- `Evidence.pcap`: sample input (not required for dashboard-only mode).
- `outputs/`: generated pipeline artifacts (active output location).
- `final_report.md`: standalone narrative report/reference.
- `plan.md`: roadmap notes.
- `archive/pipeline/`: archived pipeline Python source.

The repository root should mainly contain source and entry scripts. Generated artifacts are written under `outputs/` by default.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Dashboard Inputs

Default expected files:
- `outputs/pcap_deeper_results.json`
- `outputs/ip_enrichment_results.json`

You can also provide custom JSON paths from the app setup panel.

## Launch Dashboard

```bash
streamlit run dashboard.py
```

Dashboard behavior:
- Does not auto-load hidden defaults.
- Prompts you to choose detected files or provide custom paths.
- Loads data only after explicit confirmation.

## Archived Pipeline

Pipeline scripts and toolkit were moved to `archive/pipeline/` so the root is dashboard-focused.
