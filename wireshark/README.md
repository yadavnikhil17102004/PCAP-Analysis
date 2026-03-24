# Wireshark DGA Detection Companion

This folder contains everything to flag DGA-like DNS queries directly inside Wireshark.

## Files
- `dga_dns_postdissector.lua` — Lua post-dissector that scores DNS queries, tags suspicious packets, and prepends `[DGA]` / `[IOC]` in the Info column.
- `dga_coloring.xml` — Coloring rules to highlight known DGA SLDs and C2 IPs.
- `dga_ioc_table.lua` — (optional, generated) IOC table produced by `ip_enrichment.py --lua-ioc-out wireshark/dga_ioc_table.lua`.

## Install
1) Copy the Lua files into your Wireshark plugins directory:
   - macOS/Linux: `~/.config/wireshark/plugins/`
   - Windows: `%APPDATA%\Wireshark\plugins\`
2) Restart Wireshark.
3) Import coloring rules: View → Coloring Rules → Import → select `dga_coloring.xml`.

## Generate IOC table from your analysis
After running the pipeline:
```bash
python ip_enrichment.py --lua-ioc-out wireshark/dga_ioc_table.lua
```
Then copy `dga_ioc_table.lua` next to `dga_dns_postdissector.lua` in your plugin folder. Generated IOCs will override the static tables.

## How it works
- Entropy > 4.0 or SLD matches the IOC table triggers an alert.
- Packets with endpoints matching known C2 IPs get `[IOC]` in Info.
- Registering as a post-dissector means DNS is already decoded before scoring.

## Quick display filters
- `dga_detect` (field exists when plugin runs)
- `dns.qry.name contains "groupprograms.in"`
- `ip.addr == 62.75.195.236`

## Uninstall
Remove the Lua file from the plugins directory and restart Wireshark.
