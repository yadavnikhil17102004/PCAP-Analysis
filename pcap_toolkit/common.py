import math
from pathlib import Path


LEGACY_PCAP_PATH = r"d:\TY CDS\Take Home Test.pcap"
LEGACY_DEEP_JSON_PATH = r"d:\TY CDS\pcap_deeper_results.json"


def default_pcap_path(script_file):
    base = Path(script_file).resolve().parent
    local_pcap = base / "Evidence.pcap"
    if local_pcap.exists():
        return str(local_pcap)
    return LEGACY_PCAP_PATH


def default_deep_results_input(script_file):
    base = Path(script_file).resolve().parent
    local_json = base / "pcap_deeper_results.json"
    if local_json.exists():
        return str(local_json)
    return LEGACY_DEEP_JSON_PATH


def default_output_path(script_file, filename):
    return str(Path(script_file).resolve().parent / filename)


def entropy(text):
    if not text:
        return 0.0
    probabilities = [float(text.count(char)) / len(text) for char in set(text)]
    return -sum(prob * math.log(prob, 2) for prob in probabilities)


def sld(domain):
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain


def is_ipv4(value):
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    if not all(part.isdigit() for part in parts):
        return False
    return all(0 <= int(part) <= 255 for part in parts)
