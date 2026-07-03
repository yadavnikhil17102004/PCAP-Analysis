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

## Performance

Benchmarked on Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, 17179869184 bytes RAM, synthetic PCAPs, `analyze_pcap()` light path.

| File Size | Parse Time | Peak RSS |
|-----------|-----------|----------|
| 25 MB     | 5.666s    | 264.45 MiB |
| 50 MB     | 11.501s   | 454.39 MiB |
| 75 MB     | 17.903s   | 644.26 MiB |
| 100 MB    | 23.169s   | 833.92 MiB |
| 150 MB    | 38.931s   | 1213.60 MiB |

Optimization note: commit `74ede43` removed a per-packet regex hotspot by precompiling regex patterns and prefiltering payload scans (`b"." in payload`) before domain extraction. This reduced `analyze_pcap()` runtime by ~16x on the 25MB benchmark while preserving output parity on reference captures.

Known constraints:
- Upload gate remains 100MB for Streamlit Cloud memory safety (current parser uses full-capture `rdpcap()` load, not streaming).
- IP enrichment (reverse DNS / GeoIP / RDAP) scales with unique IP count, not file size, and can dominate runtime on high-diversity captures.
- Future work: streaming parser refactor (`PcapReader`) to reduce memory ceiling pressure.

### Analysis Modes
1.  **Upload PCAP**: Drag & drop any `.pcap` or `.pcapng` file. The dashboard runs the full analysis pipeline in the background.
2.  **Auto-detect**: Loads pre-processed JSONs from the `outputs/` directory (great for sharing results).


## 📂 Project Structure

```bash
.
├── dashboard.py           # Launcher (Start here)
├── dashboard_app/         # Dashboard source code
│   ├── dashboard.py       # Main Streamlit application
│   ├── analysis.py        # DGA scoring, beaconing, and data frames
│   └── exports.py         # IOC / Sigma / Suricata export helpers
├── archive/pipeline/      # Backend analysis engine
│   ├── pcap_deep_analysis.py  # PCAP parsing / DGA inputs
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

```bash
source venv/bin/activate
pip install -r requirements.txt
```

## Dashboard Inputs

Default expected files:
- `outputs/pcap_deeper_results.json`
- `outputs/ip_enrichment_results.json`

You can also provide custom JSON paths from the app setup panel.

## Faster Testing Without the UI

Use the smoke-test helper to pull curated PCAP fixtures from `markofu/pcaps`, run the deep-analysis pipeline, and optionally run enrichment + dashboard parsing.

```bash
# See the built-in fixture catalog
venv/bin/python scripts/pcap_smoke.py --list

# Fast path: mixed protocol coverage
venv/bin/python scripts/pcap_smoke.py --sample dns --sample http --sample ftp --sample telnet --sample portscan

# Full path: includes enrichment and markdown report generation
venv/bin/python scripts/pcap_smoke.py --sample dns --sample ftp --full
```

Built-in fixtures now cover a lot more than DNS-only captures:
- DNS, HTTP, FTP, Telnet
- Port scan / ICMP / DHCP / ARP
- Email trouble, Gnutella, Blaster
- Optional heavier samples like `slowdownload` and `80211traffic`

Outputs land in `.cache/pcap-smoke/` so you can inspect the generated JSON/MD files later.

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
