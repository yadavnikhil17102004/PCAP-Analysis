import argparse
import json
import sys

from pcap_toolkit.common import (
    default_deep_results_input,
    default_output_path,
)
from pcap_toolkit.enrichment import export_lua_ioc_table, run_ip_enrichment


def parse_args():
    parser = argparse.ArgumentParser(description="Enrich DNS answer IPs with reverse DNS, Geo/IP, and RDAP.")
    parser.add_argument(
        "--in-json",
        default=default_deep_results_input(__file__),
        help="Input JSON path from pcap_deep_analysis.py.",
    )
    parser.add_argument(
        "--out-json",
        default=default_output_path(__file__, "ip_enrichment_results.json"),
        help="Output JSON path for enrichment results.",
    )
    parser.add_argument(
        "--out-md",
        default=default_output_path(__file__, "analysis_report.md"),
        help="Output markdown report path.",
    )
    parser.add_argument(
        "--lua-ioc-out",
        default=None,
        help="Optional path to write Wireshark Lua IOC table (dga_ioc_table.lua).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Thread pool size for enrichment lookups.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=6,
        help="Timeout (seconds) for Geo/IP HTTP lookups.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        results = run_ip_enrichment(
            in_json=args.in_json,
            out_json=args.out_json,
            out_md=args.out_md,
            max_workers=args.workers,
            timeout=args.timeout,
        )

        if args.lua_ioc_out:
            # Collect SLDs from suspicious_slds keys in the deep analysis input
            input_data = json.load(open(args.in_json, "r", encoding="utf-8"))
            slds = set((input_data.get("suspicious_slds") or {}).keys())

            # Collect IPs from enrichment results
            ioc_ips = set(results.get("ips", {}).keys())

            export_lua_ioc_table(slds, ioc_ips, args.lua_ioc_out)
    except Exception as exc:
        print(f"Error running enrichment: {exc}", file=sys.stderr)
        return 1

    print("Enrichment complete. Wrote:", args.out_json, args.out_md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
