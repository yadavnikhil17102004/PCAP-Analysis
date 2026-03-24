# Files Required For `streamlit run dashboard.py`

The command `streamlit run dashboard.py` now uses the launcher in repository root and runs the dashboard app in this folder.

## Required Python Files (active)

- `dashboard.py` (root launcher)
- `dashboard_app/dashboard.py` (actual Streamlit app)

## Required Data Files

At least one valid pair of JSON inputs must exist and be selected in UI:

- Preferred defaults:
  - `outputs/pcap_deeper_results.json`
  - `outputs/ip_enrichment_results.json`

The app can also load custom JSON paths through the setup panel.

## Required Packages

- `streamlit`
- `plotly`
- `pandas`

## Archived (not needed to run dashboard)

Moved to `archive/pipeline/`:
- `pcap_analysis.py`
- `pcap_deep_analysis.py`
- `ip_enrichment.py`
- `pcap_toolkit/`
