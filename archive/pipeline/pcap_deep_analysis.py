import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pcap_toolkit.common import default_output_path, default_pcap_path
from pcap_toolkit.deep_analysis import run_deep_analysis
from utils.pcap_guard import check_pcap_size


def parse_args():
    parser = argparse.ArgumentParser(description="Deep DNS parsing and enrichment for suspicious SLDs.")
    parser.add_argument(
        "--pcap",
        default=default_pcap_path(__file__),
        help="Path to input PCAP. Defaults to local Evidence.pcap when present.",
    )
    parser.add_argument(
        "--out-json",
        default=default_output_path(__file__, "pcap_deeper_results.json"),
        help="Output path for deep analysis JSON results.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    is_safe, size_mb, message = check_pcap_size(args.pcap)
    if not is_safe:
        print(message, file=sys.stderr)
        return 2

    try:
        results = run_deep_analysis(args.pcap, out_json=args.out_json)
    except Exception as exc:
        print(f"Error running deep analysis: {exc}", file=sys.stderr)
        return 1

    print("Deeper analysis complete. Results written to", args.out_json)
    print("Suspicious SLDs:", list(results["suspicious_slds"].keys()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
