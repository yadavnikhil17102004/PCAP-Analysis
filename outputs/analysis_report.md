# PCAP Analysis Report

## Questions

**1. What is a Domain Generation Algorithm (DGA)?**

A Domain Generation Algorithm (DGA) is an algorithm used by malware to deterministically produce a large set of domain names, often pseudo-random, so the malware can attempt to contact command-and-control (C2) infrastructure at those domains. Attackers only register a subset of generated names, making blocking and takedown harder.

**2a. What exists/occurs in the provided pcap?**

- Packets total: 16
- DNS queries observed: 16
- Observed DNS queries include multiple long, high-entropy subdomains (examples in timeline). Many of these resolved to external IPs in the capture.

**2b. Is the file related to information security?**

Yes. The capture shows DNS behavior consistent with DGA-based C2 resolution: multiple algorithmically-looking subdomains (high entropy), several different names resolving to the same external IP, and short beacon-like timing between queries. This pattern is typical for malware beaconing and warrants further investigation.

## Enrichment Results (per IP)

### 95.163.121.204
- Reverse DNS: insconsulting.ru
- Country: Russia, Region: Moscow, City: Moscow, ISP: LLC Digital Network, Org: DINET-HOSTING, AS: AS12695 LLC Digital Network
- ASN: 12695, ASN country: RU, Network: RU-DINET-20081230

### 188.165.164.184
- Reverse DNS: dynamicplus.it
- Country: The Netherlands, Region: South Holland, City: Rotterdam, ISP: OVH SAS, Org: OVH BV, AS: AS16276 OVH SAS
- ASN: 16276, ASN country: FR, Network: NL-OVH

### 62.75.195.236
- Reverse DNS: static-ip-62-75-195-236.inaddr.ip-pool.com
- Country: France, Region: Grand Est, City: Strasbourg, ISP: velia.net Internetdienste GmbH, Org: Ripe, AS: AS29066 velia.net Internetdienste GmbH
- ASN: 29066, ASN country: DE, Network: ripe-62-75-195-236-32

### 72.34.49.86
- Reverse DNS: mail86.pi.elinuxservers.com
- Country: United States, Region: California, City: Los Angeles, ISP: IHNetworks, LLC, Org: IHNetworks, LLC, AS: AS33494 IHNetworks, LLC
- ASN: 33494, ASN country: US, Network: IHNET-PI-1

### 204.152.254.221
- Reverse DNS: (none)
- Country: United States, Region: Arizona, City: Phoenix, ISP: Brinkster Communications Corporation, Org: Brinkster Communications Corporation, AS: AS33055 Brinkster Communications Corporation
- ASN: 33055, ASN country: US, Network: ORF-BRINKSTER-COM

## Timeline (per internal source IP)
### 192.168.138.158
- 1431031896.723375: va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in -> answers: []
- 1431031897.512327: ubb67.3c147o.u806a4.w07d919.o5f.f1.b80w.r0faf9.e8mfzdgrf7g0.groupprograms.in -> answers: []
- 1431031897.512469: r03afd2.c3008e.xc07r.b0f.a39.h7f0fa5eu.vb8fbl.e8mfzdgrf7g0.groupprograms.in -> answers: []
- 1431031902.637356: ip-addr.es -> answers: []
- 1431031903.052371: runlove.us -> answers: []
- 1431031903.289815: kritischerkonsum.uni-koeln.de -> answers: []
- 1431031903.475416: comarksecurity.com -> answers: []
- 1431031941.332372: 7oqnsnzwwnm6zb7y.gigapaysun.com -> answers: []

### 192.168.138.2
- 1431031896.874326: va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in -> answers: [{'rdata': '62.75.195.236',
  'rrname': 'va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in',
  'type': 1}]
- 1431031897.655926: ubb67.3c147o.u806a4.w07d919.o5f.f1.b80w.r0faf9.e8mfzdgrf7g0.groupprograms.in -> answers: [{'rdata': '62.75.195.236',
  'rrname': 'ubb67.3c147o.u806a4.w07d919.o5f.f1.b80w.r0faf9.e8mfzdgrf7g0.groupprograms.in',
  'type': 1}]
- 1431031897.669844: r03afd2.c3008e.xc07r.b0f.a39.h7f0fa5eu.vb8fbl.e8mfzdgrf7g0.groupprograms.in -> answers: [{'rdata': '62.75.195.236',
  'rrname': 'r03afd2.c3008e.xc07r.b0f.a39.h7f0fa5eu.vb8fbl.e8mfzdgrf7g0.groupprograms.in',
  'type': 1}]
- 1431031902.778136: ip-addr.es -> answers: [{'rdata': '188.165.164.184', 'rrname': 'ip-addr.es', 'type': 1}]
- 1431031903.089942: runlove.us -> answers: [{'rdata': '204.152.254.221', 'rrname': 'runlove.us', 'type': 1}]
- 1431031903.474197: kritischerkonsum.uni-koeln.de -> answers: []
- 1431031903.507883: comarksecurity.com -> answers: [{'rdata': '72.34.49.86', 'rrname': 'comarksecurity.com', 'type': 1}]
- 1431031941.364104: 7oqnsnzwwnm6zb7y.gigapaysun.com -> answers: [{'rdata': '95.163.121.204',
  'rrname': '7oqnsnzwwnm6zb7y.gigapaysun.com',
  'type': 1}]

## Original file
Google Drive link: https://drive.google.com/file/d/1jad6drgd4gO7uG2F7nZmWy7vICGJhtEV/view?usp=sharing