# 📡 PCAP Investigation Console

A **signal-first**, Python-based threat hunting dashboard for PCAP analysis. Detects **DNS tunneling**, **DGA domains**, **Beaconing C2 callbacks**, and **Geo-distributed infrastructure**.

[![Watch the Demo](assets/demo/Screen_Recording.mov)](assets/demo/Screen_Recording.mov)

---

## 🚀 Key Features

| Feature | Description |
| :--- | :--- |
| **DGA Detection** | Real-time heuristic scoring (Entropy + Consonant Ratio + Label Count). |
| **Beacon Analysis** | Identifies periodic `C2` callbacks using jitter analysis (CV < 0.30). |
| **Threat Intelligence** | Auto-enrichment with **GeoIP**, **ASN**, and **MITRE ATT&CK** mapping. |
| **Interactive Timeline** | Zoomable scatter plot of DNS query entropy over time. |
| **Full Pipeline in Browser** | **Upload .pcap files directly** to analyze without touching the CLI. |
| **IOC Export** | One-click export to **CSV**, **Sigma Rules**, and **Suricata Rules**. |

---

## 🛠 Installation

Start by cloning the repository and setting up the environment:

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/PCAP-Analysis.git
cd PCAP-Analysis

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

## 🖥 Usage

Run the dashboard with a single command:

```bash
streamlit run dashboard.py
```

### Analysis Modes
1.  **Upload PCAP**: Drag & drop any `.pcap` or `.pcapng` file. The dashboard runs the full analysis pipeline in the background.
2.  **Auto-detect**: Loads pre-processed JSONs from the `outputs/` directory (great for sharing results).


## 📂 Project Structure

```bash
.
├── dashboard.py           # Launcher (Start here)
├── dashboard_app/         # Dashboard Source Code
│   └── dashboard.py       # Main Application Logic
├── archive/pipeline/      # Backend Analysis Engine
│   ├── pcap_deep_analysis.py  # DGA parser
│   └── ip_enrichment.py       # GeoIP/RDAP enricher
├── outputs/               # Analysis Artifacts (JSONs)
├── assets/                # Demo & Media
└── Evidence.pcap          # Sample Capture File
```

## 🛡 Validated Against
- **Python 3.10+**
- **Streamlit 1.30+**
- **MacOS / Linux / Windows**

> **Note**: For best performance with large PCAPs (>100MB), run the backend scripts manually from `archive/pipeline/` and load the JSONs.
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
