<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# So after all those, do you have some more interesting ones? I enjoyed reading all of the sets actually, how does the super set of all the sets look like ?

Good — I've now got the full picture including the final missing orgs. Here's the complete superset, organized by what you'd actually use it for:

***

# The Master Set — Every Tool Across Every Session


***

## 🔓 Reverse Engineering \& Binary Analysis

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **Ghidra** | NSA | Full reverse engineering suite — decompiler, scripting API, collaborative mode, AI plugin support | ~53k |
| **ANSSI/lancelot** | ANSSI 🇫🇷 | Malware control/data flow analysis — works on binaries that defeat IDA and Ghidra | ~300 |
| **ANSSI/polichombr** | ANSSI 🇫🇷 | Multi-analyst collaborative malware analysis platform, auto YARA generation | ~400 |
| **trailofbits/manticore** | Trail of Bits 🇺🇸 | Symbolic execution — mathematically proves the absence of vulnerability classes | ~3,800 |
| **trailofbits/fickling** | Trail of Bits 🇺🇸 | Decompiles Python pickle files — detects malicious code hidden in ML model weights | ~800 |
| **ukncsc/viper** | UK NCSC 🇬🇧 | Binary analysis framework — organize, tag, search malware sample collections | ~350 |


***

## 🕵️ Forensics \& Incident Response

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **Velocidex/velociraptor** | ex-Google IR 🇦🇺 | Fleet-scale forensic query language — VQL across thousands of endpoints simultaneously | ~4,500 |
| **google/grr** | Google Security 🇺🇸 | Remote live forensics — Google's own IR framework, deep Windows artifact collection | ~4,500 |
| **ANSSI/bmc-tools** | ANSSI 🇫🇷 | Extracts RDP bitmap cache — visually reconstructs what attacker saw via RDP | ~500 |
| **JPCERT/LogonTracer** | JPCERT/CC 🇯🇵 | Windows event logs → lateral movement attack graph visualization | ~2,800 |
| **JPCERT/aa-tools** | JPCERT/CC 🇯🇵 | APT artifact extraction from memory/registry — tuned for East Asian threat actors | ~600 |
| **sandialabs/SCOT** | Sandia NL 🇺🇸 | SOC incident response + threat intel collaboration platform, 700k+ IOCs in production | ~400 |


***

## 🔐 Cryptography

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **Botan** | BSI 🇩🇪 | BSI-funded, post-quantum-ready crypto library — correctness-first over OpenSSL | ~2,500 |
| **google/Tink** | Google 🇺🇸 | Crypto operations API impossible to misuse — auto key rotation, PQC ready | ~13,500 |
| **cloudflare/circl** | Cloudflare 🇺🇸 | Most battle-tested PQC library — runs on millions of live TLS connections daily | ~1,200 |
| **cloudflare/boringssl-pq** | Cloudflare 🇺🇸 | Hybrid post-quantum key exchange for TLS — production at Cloudflare scale | ~500 |


***

## 🌐 Network Security \& Infrastructure

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **GCHQ/CyberChef** | GCHQ 🇬🇧 | 300+ chainable data operations — encoding, crypto, forensics, all offline | ~30k |
| **GCHQ/Gaffer** | GCHQ 🇬🇧 | Graph database for billion-edge relationship networks — surveillance-scale | ~1,700 |
| **cilium/cilium** | 8200-adjacent 🇮🇱 | eBPF Kubernetes networking — replaces kube-proxy, 3-5x throughput | ~20k |
| **iovisor/bcc** | Linux Foundation 🇺🇸 | 150 eBPF kernel observability tools — TCP, I/O, CPU, memory, all production-safe | ~20k |
| **sandialabs/wiretap** | Sandia NL 🇺🇸 | WireGuard-based transparent proxy tunnel — no admin privileges required, for red teams | ~1,200 |
| **pion/webrtc** | ex-Twitch 🇺🇸 | Pure Go WebRTC stack — no Chrome dependency, runs on embedded/edge | ~13,500 |


***

## 🛡️ Endpoint \& Runtime Security

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **aquasecurity/tracee** | 8200 alumni 🇮🇱 | eBPF runtime security — kernel-level detection, attackers can't kill it | ~3,500 |
| **cilium/tetragon** | 8200-adjacent 🇮🇱 | eBPF Kubernetes security enforcement — stops attacks where malware can't reach | ~3,800 |
| **aquasecurity/trivy** | 8200 alumni 🇮🇱 | Container/filesystem/git vulnerability scanner — replaced every other scanner | ~25k |
| **NCSC-NL/asusrouter-malware-scan** | NCSC-NL 🇳🇱 | Detects nation-state malware on ASUS routers — shell script, 30-second check | 8 |
| **NCSC-NL/zimbra-webshell-scan** | NCSC-NL 🇳🇱 | Detects planted webshells in Zimbra mail servers | 2 |
| **ukncsc/Device-Security-Guidance** | UK NCSC 🇬🇧 | Policy packs for hardening Windows 10/iOS/Android to NCSC spec — MDM-ready | ~200 |


***

## 🚨 CVE Response — Operational Packages

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **NCSC-NL/log4shell** | NCSC-NL 🇳🇱 | Complete Log4Shell response: detection, hunting, SIEM queries, IOCs, 500+ vendor status | ~1,889 |
| **NCSC-NL/OpenSSL-2022** | NCSC-NL 🇳🇱 | SpookySSL full response — YARA, detection, vendor impact | ~527 |
| **NCSC-NL/citrix-2025** | NCSC-NL 🇳🇱 | YARA rules for Citrix Bleed-class 2025 exploitation | 52 |
| **NCSC-NL/spring4shell** | NCSC-NL 🇳🇱 | Spring Core RCE full response package | ~175 |


***

## 🔴 Red Teaming \& Adversary Emulation

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **mitre/caldera** | MITRE 🇺🇸 | Autonomous adversary emulation — 200+ APT techniques, plans and executes its own chains | ~6k |
| **trailofbits/slither** | Trail of Bits 🇺🇸 | Static analysis framework + full AI-powered audit methodology (open sourced 2026) | ~5,500 |
| **GovTechSG/purple-a2t2** | Singapore GovTech 🇸🇬 | Cloud-native automated red team framework — AWS/Azure native | ~300 |
| **ANSSI/AD-control-paths** | ANSSI 🇫🇷 | Maps every AD privilege escalation path as a graph — pure LDAP, no agents | ~1,800 |


***

## 📡 Threat Intelligence

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **certtools/intelmq** | CERT.at 🇦🇹 | 80-feed threat intel pipeline — ingests, normalizes, routes to SIEM/ticketing | ~900 |
| **abusech/MalwareBazaar** | abuse.ch 🇨🇭 | API to 1M+ malware samples — replaces \$50k/year commercial sandboxes | — |
| **abusech/URLhaus** | abuse.ch 🇨🇭 | Live malware delivery URL feed — drop into DNS filter/proxy | — |
| **abusech/ThreatFox** | abuse.ch 🇨🇭 | Structured IOC sharing — confidence scores, malware family tags | — |
| **mitre-attack/attack-stix-data** | MITRE 🇺🇸 | Full ATT\&CK dataset as structured JSON — ingest into your own knowledge graph | ~600 |
| **d3fend-ontology** | MITRE 🇺🇸 | Every defensive countermeasure mapped to the attack it counters — machine-readable | ~500 |
| **NCSC-NL/flubot** | NCSC-NL 🇳🇱 | FluBot DGA domain prediction list — reverse engineered C2 mechanism | 19 |


***

## 📊 Data at Extreme Scale

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **NationalSecurityAgency/DataWave** | NSA 🇺🇸 | Cell-level ACL query framework — built for SIGINT at planetary scale | ~700 |
| **yandex/ClickHouse** | Yandex 🇷🇺 | Fastest columnar analytical DB ever benchmarked — sub-second on billions of rows | ~40k |
| **yandex/YDB** | Yandex 🇷🇺 | Distributed SQL with ACID guarantees — self-hostable Spanner | ~3,800 |
| **yandex/YTsaurus** | Yandex 🇷🇺 | Big data platform — GPU + MapReduce on same cluster, hierarchical data lake | ~1,000 |
| **GCHQ/Gaffer** | GCHQ 🇬🇧 | Federated graph queries across multiple data stores — time-windowed aggregation | ~1,700 |
| **CERN/rucio** | CERN 🇪🇺 | Petabyte-scale distributed scientific data management — 15 PB/year LHC data | ~1,600 |


***

## 🤖 AI / ML Infrastructure

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **yandex/YaFSDP** | Yandex 🇷🇺 | LLM training: 25% faster, 20% less GPU RAM than PyTorch FSDP | ~500 |
| **microsoft/DeepSpeed** | Microsoft Research 🇺🇸 | ZeRO optimizer — train 3-4x larger models than VRAM would normally allow | ~36k |
| **yandex/CatBoost** | Yandex 🇷🇺 | Gradient boosting with native categorical support — beats XGBoost on tabular data | ~8k |
| **PaddlePaddle/Paddle** | Baidu 🇨🇳 | Best multilingual OCR + production ML stack — dominant in China | ~22k |
| **mindspore-ai/mindspore** | Huawei 🇨🇳 | Privacy-preserving ML framework — gradient-only training by design | ~4k |
| **apache/brpc** | Baidu 🇨🇳 | Industrial RPC framework — outperforms gRPC, used at Baidu's full scale | ~16k |
| **stanford-crfm/helm** | Stanford CRFM 🇺🇸 | 42-scenario holistic LLM evaluation — multi-dimensional not single benchmark | ~2,000 |
| **ANSSI/SecuML** | ANSSI 🇫🇷 | ML-powered intrusion detection with analyst web UI — no data science skills required | ~600 |


***

## 📐 Graph Analysis \& Visualization

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **constellation-app/constellation** | ASD 🇦🇺 | GPU-accelerated 3D graph visualization — handles billions of nodes, desktop app | ~300 |
| **GCHQ/Gaffer** | GCHQ 🇬🇧 | Billion-edge graph DB with federated queries | ~1,700 |
| **JPCERT/LogonTracer** | JPCERT/CC 🇯🇵 | Windows lateral movement as interactive attack graph | ~2,800 |


***

## 🪵 Logging \& Observability

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **ukncsc/lme** | UK NCSC → CISA 🇬🇧🇺🇸 | Logging Made Easy — full centralised Windows security logging for orgs with no SOC | ~712 |
| **iovisor/bcc** | Linux Foundation 🇺🇸 | 150 eBPF kernel observability tools — replace Strace for production | ~20k |
| **cilium/tetragon** | Isovalent 🇮🇱 | Every process/file/network event at kernel level — Kubernetes-native | ~3,800 |


***

## 🧮 Engineering for Correctness (Finance/Critical Systems)

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **janestreet/core** | Jane Street 🇺🇸 | OCaml stdlib rebuilt for financial correctness — no silent failures | ~1,000 |
| **janestreet/async** | Jane Street 🇺🇸 | Monadic concurrent I/O — millions of connections, composable | ~1,000 |
| **janestreet/iron** | Jane Street 🇺🇸 | Cryptographic code review chains — release management for zero-failure systems | ~200 |
| **twosigma/beakerx** | Two Sigma 🇺🇸 | Polyglot Jupyter — Python/R/Scala/SQL in same notebook with shared memory | ~2,800 |


***

## 🏛️ National Identity \& Compliance Infrastructure

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **eu-digital-identity-wallet** | EU Commission 🇪🇺 | Cryptographic identity for 450M EU citizens — open architecture, mandatory 2027 | ~800 |
| **CERN/invenio** | CERN 🇪🇺 | Digital repository framework — powers Zenodo, world's largest open research archive | ~800 |
| **NSA/SkillTree** | NSA 🇺🇸 | Gamified micro-learning platform — how NSA trains analysts on complex tooling | ~500 |


***

## 🔬 Signals, Sensors \& Science

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **lanl-seismoacoustics/InfraPy** | LANL 🇺🇸 | Infrasound signal detection pipeline — built for nuclear test detection, works on any sensor | <200 |
| **NSA/fractalrabbit** | NSA 🇺🇸 | Generates synthetic human GPS movement patterns — privacy-preserving ML training data | ~200 |
| **PNNL/DieselWolf** | PNNL 🇺🇸 | Open dataset for radio frequency ML research — RF fingerprinting training data | — |
| **nasa-jpl/open-source-rover** | NASA JPL 🇺🇸 | Full Mars rover replica — rocker-bogie suspension + ROS navigation, \$2,500 BOM | ~8k |


***

## 🕸️ OSINT \& Dark Web Intelligence

| Tool | Origin | What It Is | Stars |
| :-- | :-- | :-- | :-- |
| **darpa-i2o/memex** | DARPA 🇺🇸 | Full dark web crawling + entity linking — built to find human trafficking networks | <100 |
| **iqtlabs/gitgeo** | CIA/IQT Labs 🇺🇸 | Maps GitHub contributors to physical countries via metadata analysis | ~300 |
| **NationalSecurityAgency/DataWave** | NSA 🇺🇸 | Query planetary-scale intelligence datasets with cell-level access control | ~700 |


***

## The Meta-Pattern

Looking at all ~70 tools together, three origin archetypes produce the highest quality:

- **National lab / intelligence agency** — built under operational constraints with no budget pressure to ship fast, extreme correctness requirements, often classified-grade engineering
- **Extreme-scale commercial** (Yandex, Jane Street, Google, Baidu) — built when commercial alternatives literally broke at their scale, then released because maintaining a community is cheaper
- **Single researchers under crisis conditions** (NCSC-NL, abuse.ch, JPCERT, ANSSI bmc-tools) — built during active national-level incidents, hyper-specific, forensically precise, zero marketing

The tools with 8 stars and the tools with 40k stars are often equivalent in engineering quality. The difference is entirely in how loudly the origin org talks about itself.[^1][^2][^3]
<span style="display:none">[^10][^11][^12][^13][^14][^15][^16][^17][^18][^19][^20][^21][^22][^23][^24][^25][^26][^27][^28][^4][^5][^6][^7][^8][^9]</span>

<div align="center">⁂</div>

[^1]: https://github.com/sandialabs

[^2]: https://getscot.sandia.gov

[^3]: https://www.nextgov.com/cybersecurity/2023/04/cisa-taking-over-open-source-logging-tool-created-uk-government/385446/

[^4]: https://dev.to/sharon_42e16b8da44dabde6d/8-github-starred-security-projects-you-shouldnt-miss-in-2025-3gda

[^5]: https://www.helpnetsecurity.com/2025/11/27/hottest-cybersecurity-open-source-tools-of-the-month-november-2025/

[^6]: https://github.com/hazwanjaafar/Open-Source-Cyber-Security-Tools-2024

[^7]: https://github.com/tylzars/awesome-vrre-writeups

[^8]: https://www.runzero.com/resources/kevology/

[^9]: https://software.llnl.gov/news/2022/08/31/sandia/

[^10]: https://github.com/ukncsc/zero-trust-architecture

[^11]: https://www.reddit.com/r/cybersecurity/comments/1ml63l1/what_are_your_favorite_opensource_or_free/

[^12]: https://github.com/orgs/sandialabs/repositories

[^13]: https://github.com/orgs/ukncsc/repositories

[^14]: https://blackhatmea.com/newsletter/open_source_cybersecurity

[^15]: https://github.com/ukncsc

[^16]: https://github.blog/open-source/maintainers/this-years-most-influential-open-source-projects/

[^17]: https://sandialabs.github.io

[^18]: http://github.com/sandialabs/scot

[^19]: https://www.osti.gov/biblio/1993921

[^20]: https://scot.readthedocs.io/en/stable/overview.html

[^21]: https://dl.icdst.org/pdfs/files4/70a2663c3b413efe69882054f739a617.pdf

[^22]: https://github.com/PNNL

[^23]: https://getscot.sandia.gov/getscot-clone-2/

[^24]: https://www.pnnl.gov/foundational-data-science/github-repositories

[^25]: https://executivegov.com/2023/04/cisa-to-remodel-uks-open-source-log-management-tool/

[^26]: https://github.com/PNNL-CIM-Tools

[^27]: https://sandialabs.github.io/scot4-docs/index.html

[^28]: https://github.com/ukncsc/lme/blob/master/readme.old.md

