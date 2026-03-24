import argparse
import sys

from pcap_toolkit.analysis import analyze_pcap, print_summary
from pcap_toolkit.common import default_pcap_path


def parse_args():
    parser = argparse.ArgumentParser(description="Quick DNS/HTTP/TLS reconnaissance from a PCAP file.")
    parser.add_argument(
        "--pcap",
        default=default_pcap_path(__file__),
        help="Path to input PCAP. Defaults to local Evidence.pcap when present.",
    )
    parser.add_argument(
        "--top-domains",
        type=int,
        default=20,
        help="Number of high-entropy domains to print.",
    )
    parser.add_argument(
        "--sample-queries",
        type=int,
        default=30,
        help="Number of DNS queries to print as sample output.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        results = analyze_pcap(args.pcap)
    except Exception as exc:
        print(f"Error analyzing PCAP: {exc}", file=sys.stderr)
        return 1

    print_summary(results, top_domains=args.top_domains, sample_queries=args.sample_queries)
    return 0


if __name__ == "__main__":
    sys.exit(main())
