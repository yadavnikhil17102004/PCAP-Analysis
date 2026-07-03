#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_DIR = REPO_ROOT / "archive" / "pipeline"
DEEP_SCRIPT = PIPELINE_DIR / "pcap_deep_analysis.py"
ENRICH_SCRIPT = PIPELINE_DIR / "ip_enrichment.py"

SAMPLES = {
    "dns": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/dns.cap",
        "notes": "DNS-heavy baseline; good for DGA/beacon checks.",
    },
    "http": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/http.cap",
        "notes": "Simple web traffic baseline.",
    },
    "ftp": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/ftp.pcap",
        "notes": "Credentialed file-transfer traffic.",
    },
    "telnet": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/telnet.pcap",
        "notes": "Plaintext remote shell traffic.",
    },
    "portscan": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/portscan.pcap",
        "notes": "Scan/noise sample; usually sparse DNS.",
    },
    "dhcp": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/dhcp.pcap",
        "notes": "Local network setup chatter.",
    },
    "icmp": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/icmp.pcap",
        "notes": "ICMP-only control traffic.",
    },
    "email_troubles": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/email-troubles.pcap",
        "notes": "Bulkier mixed traffic sample.",
    },
    "gnutella": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/gnutella.pcap",
        "notes": "P2P-style traffic with different packet mix.",
    },
    "blaster": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/blaster.pcap",
        "notes": "Malware-like traffic / worm-era sample.",
    },
    "slowdownload": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/slowdownload.pcap",
        "notes": "Large transfer sample; opt-in because it is big.",
    },
    "arp": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/arp.pcap",
        "notes": "Link-layer neighbor discovery noise.",
    },
    "80211traffic": {
        "path": "PracticalPacketAnalysis/ppa-capture-files/80211traffic.pcap",
        "notes": "802.11 capture; useful for parser resilience.",
    },
}

sys.path.insert(0, str(REPO_ROOT))
try:
    from dashboard_app.analysis import build_ip_df, build_query_df, detect_beacons  # noqa: E402
except ModuleNotFoundError as exc:  # pragma: no cover - friendlier runtime error
    if exc.name == "pandas":
        print(
            "Missing Python dependencies. Run this helper with the project venv, for example:\n"
            "  venv/bin/python scripts/pcap_smoke.py --sample dns\n"
            "or install requirements first with:\n"
            "  venv/bin/pip install -r requirements.txt",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
    raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fast non-UI smoke test for the PCAP pipeline using fixtures from markofu/pcaps."
    )
    parser.add_argument(
        "--sample",
        action="append",
        choices=sorted(SAMPLES),
        help="Named fixture to run. Can be repeated. Default: dns, http",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run every built-in fixture sample.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Show the built-in fixture catalog and exit.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Also run IP enrichment and dashboard table parsing. This is slower and hits the network.",
    )
    parser.add_argument(
        "--repo",
        default="markofu/pcaps",
        help="GitHub repo that hosts the fixture PCAPs.",
    )
    parser.add_argument(
        "--branch",
        default="master",
        help="Git branch or ref in the fixture repo.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPO_ROOT / ".cache" / "pcap-smoke"),
        help="Directory for downloaded PCAPs and generated outputs.",
    )
    return parser.parse_args()


def fixture_url(repo: str, branch: str, fixture_path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{branch}/{fixture_path}"


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response, dest.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def run_command(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(args)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def run_deep_analysis(pcap_path: Path, out_dir: Path) -> Path:
    deep_json = out_dir / "pcap_deeper_results.json"
    run_command([sys.executable, str(DEEP_SCRIPT), "--pcap", str(pcap_path), "--out-json", str(deep_json)], cwd=REPO_ROOT)
    return deep_json


def run_enrichment(deep_json: Path, out_dir: Path) -> tuple[Path, Path]:
    enrich_json = out_dir / "ip_enrichment_results.json"
    enrich_md = out_dir / "analysis_report.md"
    run_command(
        [
            sys.executable,
            str(ENRICH_SCRIPT),
            "--in-json",
            str(deep_json),
            "--out-json",
            str(enrich_json),
            "--out-md",
            str(enrich_md),
        ],
        cwd=REPO_ROOT,
    )
    return enrich_json, enrich_md


def summarize_deep(deep_json: Path) -> dict:
    data = json.loads(deep_json.read_text(encoding="utf-8"))
    query_df = build_query_df(data.get("dns", []))
    beacon_df = detect_beacons(query_df)
    suspicious_slds = data.get("suspicious_slds", {})
    return {
        "packets_total": data.get("packets_total", 0),
        "dns_records": len(data.get("dns", [])),
        "query_rows": len(query_df),
        "beacons": int(beacon_df.get("beacon", []).sum()) if not beacon_df.empty else 0,
        "suspicious_slds": len(suspicious_slds),
        "top_slds": sorted(suspicious_slds.keys())[:5],
    }


def summarize_enrichment(enrich_json: Path) -> dict:
    data = json.loads(enrich_json.read_text(encoding="utf-8"))
    ip_df = build_ip_df(data)
    return {
        "enriched_ips": len(ip_df),
        "timeline_hosts": len(data.get("timeline", {})),
    }


def main() -> int:
    args = parse_args()

    if args.list:
        for name, meta in SAMPLES.items():
            print(f"{name:16} {meta['path']}  -- {meta['notes']}")
        return 0

    if args.all:
        selected = list(SAMPLES)
    elif args.sample:
        selected = args.sample
    else:
        selected = ["dns", "http"]

    out_root = Path(args.output_dir)
    out_root.mkdir(parents=True, exist_ok=True)

    print(f"Fixture repo: {args.repo}@{args.branch}")
    print(f"Mode: {'full' if args.full else 'deep-only'}")
    print(f"Output dir: {out_root}")
    print("")

    results = []
    for name in selected:
        fixture = SAMPLES[name]
        fixture_path = fixture["path"]
        sample_dir = out_root / name
        sample_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = sample_dir / Path(fixture_path).name
        url = fixture_url(args.repo, args.branch, fixture_path)

        print(f"[{name}] downloading {fixture_path}")
        download(url, pcap_path)
        print(f"[{name}] saved {pcap_path.relative_to(REPO_ROOT)} ({pcap_path.stat().st_size} bytes)")

        deep_json = run_deep_analysis(pcap_path, sample_dir)
        deep_summary = summarize_deep(deep_json)
        line = (
            f"[{name}] packets={deep_summary['packets_total']} dns={deep_summary['dns_records']} "
            f"queries={deep_summary['query_rows']} beacons={deep_summary['beacons']} "
            f"suspicious_slds={deep_summary['suspicious_slds']}"
        )

        if args.full:
            enrich_json, enrich_md = run_enrichment(deep_json, sample_dir)
            enrich_summary = summarize_enrichment(enrich_json)
            line += (
                f" enriched_ips={enrich_summary['enriched_ips']}"
                f" timeline_hosts={enrich_summary['timeline_hosts']}"
            )
            line += f" md={enrich_md.relative_to(REPO_ROOT)}"
            results.append({"sample": name, **deep_summary, **enrich_summary})
        else:
            results.append({"sample": name, **deep_summary})

        print(line)

    print("")
    print(json.dumps({"repo": args.repo, "branch": args.branch, "mode": "full" if args.full else "deep-only", "samples": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
