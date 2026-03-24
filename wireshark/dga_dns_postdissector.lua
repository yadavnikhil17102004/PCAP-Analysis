-- Wireshark post-dissector for DGA-like DNS queries.
-- Copy this file to your Wireshark plugin directory (e.g., ~/.config/wireshark/plugins/ on macOS/Linux).
-- Optionally place a generated dga_ioc_table.lua in the same directory to override the static IOC lists.

local dns_proto = Proto("dga_detect", "DGA Detector")
local f_dns_qry = Field.new("dns.qry.name")

-- Static baseline IOCs; can be replaced/augmented by dga_ioc_table.lua
local suspicious_slds = {
    ["groupprograms.in"] = true,
    ["gigapaysun.com"] = true,
    ["runlove.us"] = true,
}
local c2_ips = {
    ["62.75.195.236"] = true,
    ["95.163.121.204"] = true,
    ["188.165.164.184"] = true,
    ["204.152.254.221"] = true,
    ["72.34.49.86"] = true,
}

-- Attempt to load generated IOC tables (if present in the same directory)
local status, generated = pcall(dofile, "dga_ioc_table.lua")
if status and generated then
    if generated.slds then suspicious_slds = generated.slds end
    if generated.c2_ips then c2_ips = generated.c2_ips end
end

local function calc_entropy(text)
    if not text or #text == 0 then return 0 end
    local freq, entropy = {}, 0
    for i = 1, #text do
        local c = text:sub(i, i)
        freq[c] = (freq[c] or 0) + 1
    end
    for _, v in pairs(freq) do
        local p = v / #text
        entropy = entropy - p * math.log(p, 2)
    end
    return entropy
end

local function extract_sld(qname)
    if not qname then return nil end
    local sld = qname:match("([^.]+%.[^.]+)$")
    return sld
end

function dns_proto.dissector(_, pinfo, tree)
    local qfield = f_dns_qry()
    if not qfield then return end

    local qname = tostring(qfield)
    if not qname then return end

    local entropy = calc_entropy(qname)
    local sld = extract_sld(qname)

    local dns_tree = tree:add(dns_proto, "DGA Analysis")
    dns_tree:add(string.format("Entropy: %.2f", entropy))

    local flagged = false
    local reasons = {}
    if entropy > 4.0 then
        flagged = true
        table.insert(reasons, "entropy>4.0")
    end
    if sld and suspicious_slds[sld] then
        flagged = true
        table.insert(reasons, "known SLD")
    end

    if flagged then
        dns_tree:add(string.format("[ALERT] Likely DGA domain (%s)", table.concat(reasons, ","))):set_generated()
        pinfo.cols.info:prepend("[DGA] ")
    end

    -- IP highlight: mark if packet endpoints match C2 IPs
    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    if c2_ips[src_ip] or c2_ips[dst_ip] then
        dns_tree:add("[IOC] Matches known C2 IP"):set_generated()
        pinfo.cols.info:prepend("[IOC] ")
    end
end

-- Register as post-dissector so DNS is already decoded
register_postdissector(dns_proto)
