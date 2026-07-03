from __future__ import annotations

import csv
import hashlib
import io

import pandas as pd


def _stable_sid(value: str) -> int:
    digest = hashlib.blake2s(value.encode("utf-8"), digest_size=4).digest()
    return 1_000_000 + (int.from_bytes(digest, "big") % 9_000_000)


def _yaml_list_block(values: list[str]) -> str:
    if not values:
        return "[]"
    return "\n            - ".join(values)


def export_ioc_csv(query_df: pd.DataFrame, ip_df: pd.DataFrame) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "indicator", "severity", "context"])
    for _, row in query_df[query_df["severity"].isin(["CRITICAL", "HIGH"])].iterrows():
        w.writerow(["domain", row["qname"], row["severity"],
                    f"dga_score={row['dga_score']} src={row['src']}"])
    for _, row in ip_df.iterrows():
        w.writerow(["ip", row["IP"], "HIGH",
                    f"{row['Country']} ASN={row['ASN']} org={row['Org']}"])
    return buf.getvalue()


def export_sigma(query_df: pd.DataFrame, ip_df: pd.DataFrame) -> str:
    slds = sorted({r["sld"] for _, r in query_df.iterrows()
                   if r["severity"] in ("CRITICAL", "HIGH")})
    ips = sorted(ip_df["IP"].tolist())
    sld_block = _yaml_list_block([f"'.{s}'" for s in slds])
    ip_block = _yaml_list_block([f"'{ip}'" for ip in ips])
    return f"""title: DGA C2 beacon activity
status: experimental
description: Detected DGA-like domains and known C2 IPs from pcap analysis
logsource:
    category: dns
detection:
    selection_domain:
        dns.query|endswith:
            {sld_block}
    selection_ip:
        dst_ip:
            {ip_block}
    condition: selection_domain or selection_ip
level: high
tags:
    - attack.command_and_control
    - attack.t1568.002
    - attack.t1071.004
"""


def export_suricata(query_df: pd.DataFrame, ip_df: pd.DataFrame) -> str:
    lines = []
    for ip in sorted(ip_df["IP"].tolist()):
        sid = _stable_sid(f"ip:{ip}")
        lines.append(
            f'alert ip $HOME_NET any -> {ip} any '
            f'(msg:"PCAP-TOOLKIT C2 IP {ip}"; '
            f'classtype:trojan-activity; sid:{sid}; rev:1;)'
        )
    for _, row in query_df[query_df["severity"] == "CRITICAL"].drop_duplicates("sld").sort_values("sld").iterrows():
        sid = _stable_sid(f"sld:{row['sld']}")
        lines.append(
            f'alert dns $HOME_NET any -> any 53 '
            f'(msg:"PCAP-TOOLKIT DGA domain {row["sld"]}"; '
            f'dns.query; content:"{row["sld"]}"; nocase; '
            f'classtype:trojan-activity; sid:{sid}; rev:1;)'
        )
    return "\n".join(lines)
