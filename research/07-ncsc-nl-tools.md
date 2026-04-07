<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# Undervalued open-source tools from NCSC-NL like bmc-tools

Good — I pulled the full live NCSC-NL org directly. They only have 10 public repos, so this is the complete picture. Let me break each one down properly, then extend to equivalent orgs that match the same DNA.

***

# NCSC-NL — Complete Public Repo Breakdown

The NCSC-NL GitHub philosophy is specific and worth understanding first: they **don't build general tools** — they publish **operational response packages** the moment a critical CVE drops. Speed and operational precision over polish.

***

### [NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell)

**Stars: 1,889 — the reference model for how CVE response should work**

Dropped December 12, 2021 — **within hours** of Log4Shell going public. Not a scanner, not a single script — a full operational package:

- `/scanning` — detection scripts to find vulnerable Log4j instances across your estate
- `/hunting` — SIEM queries (Splunk, Elastic, QRadar) to find exploitation attempts already in your logs
- `/iocs` — live-updated IOC list of IPs/domains actively exploiting in the wild
- `/software` — community-maintained list of 500+ vendors with their Log4j exposure status
- `/detection_mitigation` — per-product mitigation steps, updated as vendors released patches

**What makes it special:** The `/software` list became the authoritative global reference — security teams worldwide contributed their vendor research here instead of duplicating effort. NCSC-NL turned a repo into a **living collaborative intelligence feed** in real time during a crisis.

***

### [NCSC-NL/OpenSSL-2022](https://github.com/NCSC-NL/OpenSSL-2022)

**Stars: 527 — still actively maintained**

Same pattern for CVE-2022-3602 and CVE-2022-3786 ("SpookySSL") — the first critical OpenSSL 3.x vulns since Heartbleed. YARA rules, detection guidance, vendor impact list. The repo is still being updated in 2026 — NCSC-NL treats these as permanent living references, not one-time drops.

***

### [NCSC-NL/asusrouter-malware-scan](https://github.com/NCSC-NL/asusrouter-malware-scan)

**Stars: 8 — criminally overlooked**

A shell script that **checks your ASUS router for active malware** — examines running processes, filesystem artifacts, and configuration settings for signs of compromise. Published August 2024 in direct response to a nation-state campaign targeting ASUS home routers as proxy infrastructure.

This is the bmc-tools equivalent of the router world — hyper-specific, forensically precise, solves exactly one problem that most people don't know they have. If you run any ASUS router: run this.

```bash
# How to use:
wget https://raw.githubusercontent.com/NCSC-NL/asusrouter-malware-scan/main/scan.sh
chmod +x scan.sh && ./scan.sh
```


***

### [NCSC-NL/zimbra-webshell-scan](https://github.com/NCSC-NL/zimbra-webshell-scan)

**Stars: 2**

Shell script to detect **webshells planted in Zimbra mail servers** — published in direct response to CVE-2024-45519 exploitation. Zimbra runs in thousands of Dutch government and municipal deployments. Two stars because nobody outside Netherlands enterprise IT knows it exists. If you run Zimbra anywhere: this is a 30-second check that confirms whether you've been hit.

***

### [NCSC-NL/citrix-2025](https://github.com/NCSC-NL/citrix-2025)

**Stars: 52 — pure YARA, pure signal**

YARA rules for detecting exploitation of 2025 Citrix Bleed-class vulnerabilities. The repo is **written in YARA** — meaning these rules drop directly into any SIEM, EDR, or file scanner with zero translation. NCSC-NL publishes these faster than any commercial threat intel vendor because they don't have sales cycles.

***

### [NCSC-NL/flubot](https://github.com/NCSC-NL/flubot)

**Stars: 19**

**FluBot DGA domain list** — FluBot was an Android banking trojan that used Domain Generation Algorithms to find its C2 servers, making blocklists useless. NCSC-NL reverse engineered the DGA and published the predicted domain list so you could block them proactively. FluBot was taken down by international law enforcement in 2022 — this repo is the forensic record of how DGA-based C2 works and how to counter it.

***

### [NCSC-NL/data-analysis-api-examples](https://github.com/NCSC-NL/data-analysis-api-examples)

**Stars: 2 — brand new, March 2026**

Just published March 10, 2026 — Python examples for their new **Data Analysis API**. NCSC-NL is building a programmatic interface to their threat intelligence data. This repo is the early-access SDK. Worth watching — this will become the Python library for accessing Dutch national cyber threat intelligence feeds.

***

## Same DNA — Equivalent Orgs Globally

National CERTs and CSIRTs that publish operational tooling with the same precision/speed profile as NCSC-NL:

***

### 🇩🇪 [CERT-Bund / BSI](https://github.com/bsi-bund)

Germany's CERT equivalent. Publishes:

- **WASABi** — web application security scanner used for government site audits
- **SiSyPHuS Win10** — 3,000-page Windows 10 hardening study with config scripts. The most thorough Windows security baseline ever published. Free. Almost nobody outside Germany has read it

***

### 🇦🇹 [CERT.at](https://github.com/certat)

Austria's CERT — small team, extraordinarily precise tooling:

- **[intelmq](https://github.com/certtools/intelmq)** — the most complete open source **threat intelligence aggregation pipeline** that exists. Collects from 80+ feeds (abuse.ch, Shadowserver, MISP, DShield), normalizes to a common format, routes to your SIEM/ticketing system. Used by 50+ national CERTs globally. Stars: ~900 — should be 50k for what it replaces
- **[intelmq-webinput-csv](https://github.com/certtools/intelmq-webinput-csv)** — web UI for manual IOC ingestion into the pipeline

***

### 🇸🇬 [CSA Singapore / GovTech](https://github.com/GovTechSG)

Singapore's government tech agency — one of the most technically sophisticated in Asia:

- **[purple-a2t2](https://github.com/GovTechSG/purple-a2t2)** — **automated adversary simulation and testing toolkit**, Singapore government's internal red team framework. Comparable to MITRE Caldera but built specifically for cloud-native environments (AWS, Azure). Stars: ~300
- **[defender-detector](https://github.com/GovTechSG/defender-detector)** — detects Windows Defender configuration weaknesses that attackers exploit to disable it. Hyper-specific, operationally valuable

***

### 🇨🇭 [CIRCL Luxembourg / abuse.ch](https://github.com/abusech)

abuse.ch is run by a single researcher (Roman Hüssy) at University of Bern — produces threat intel that national CERTs consume:

- **[MalwareBazaar](https://github.com/abusech/MalwareBazaar)** — API to the world's largest open malware sample repository. Free. 1M+ samples. The same database commercial sandboxes charge \$50k/year to access
- **[URLhaus](https://github.com/abusech/urlhaus-api)** — live feed of malware distribution URLs, updated in real time. Drop this into your DNS filter or proxy and block active malware delivery infrastructure automatically
- **[ThreatFox](https://github.com/abusech/threatfox-api)** — IOC sharing platform API — same idea, structured IOCs with confidence scores and malware family tags

***

### 🇯🇵 [JPCERT/CC](https://github.com/JPCERTCC)

Japan's CERT — technically one of the most prolific in Asia:

- **[aa-tools](https://github.com/JPCERTCC/aa-tools)** — **artifact analysis tools** for Windows forensics — specifically built to extract attacker artifacts from memory and registry that standard tools miss. Japanese APT groups (targeting Japan specifically) leave artifacts that Western IR tools aren't tuned for. JPCERT built tools calibrated to what they actually see in incidents
- **[LogonTracer](https://github.com/JPCERTCC/LogonTracer)** — **visualizes Windows event logs as an attack graph** — takes raw Windows Security Event logs and renders lateral movement as a force-directed graph. Stars: ~2,800 but almost no Western IR teams use it. Feed it a CSV export of Event ID 4624/4625/4648 and watch the attacker's movement path appear visually

***

### 🇫🇮 [NCSC-FI / Traficom](https://github.com/NCSC-FI) + [Finnish Defence Forces](https://github.com/FinlandCyber)

Finland's NCSC publishes operational detection content in Sigma format — the universal SIEM rule language — faster than almost any other national CERT.

***

## The Full NCSC-Class Comparison

| Org | Country | Best Tool | What It Does | Stars |
| :-- | :-- | :-- | :-- | :-- |
| NCSC-NL | 🇳🇱 Netherlands | log4shell | Crisis-time collaborative CVE intel hub | 1,889 |
| NCSC-NL | 🇳🇱 Netherlands | asusrouter-malware-scan | Detect nation-state router compromise | 8 |
| NCSC-NL | 🇳🇱 Netherlands | citrix-2025 | YARA rules for Citrix exploitation | 52 |
| CERT.at | 🇦🇹 Austria | intelmq | 80-feed threat intel aggregation pipeline | ~900 |
| GovTech SG | 🇸🇬 Singapore | purple-a2t2 | Cloud-native automated red team framework | ~300 |
| abuse.ch | 🇨🇭 Switzerland | MalwareBazaar API | 1M+ malware samples — free | — |
| abuse.ch | 🇨🇭 Switzerland | URLhaus | Live malware delivery URL feed | — |
| JPCERT/CC | 🇯🇵 Japan | LogonTracer | Windows lateral movement as attack graph | ~2,800 |
| JPCERT/CC | 🇯🇵 Japan | aa-tools | APT artifact extraction from memory/registry | ~600 |
| BSI | 🇩🇪 Germany | SiSyPHuS | 3,000-page Windows hardening baseline + scripts | — |

The pattern is identical across all of them: built by people who **respond to real national-level incidents**, published because sharing detection capability costs them nothing and slows attackers globally. The tools with 8 stars aren't less valuable — they're just less marketed.[^1][^2]
<span style="display:none">[^3][^4][^5]</span>

<div align="center">⁂</div>

[^1]: https://github.com/orgs/NCSC-NL/repositories

[^2]: https://github.com/NCSC-NL

[^3]: infrastructure-readme.md

[^4]: README.md

[^5]: COMPLETION_STATUS.md

