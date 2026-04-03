<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# That’s actually a  wild list I will note it to look later at,  this was more USA focused,  if we do global EU, Russia, others that could have a entry into the list, you can create again a  detailed list, exatensive, country, agency’s and what it actually is

Here's the full global map — every country and agency worth knowing:

***

# Global Government \& State-Affiliated Open Source — Full List


***

## 🇫🇷 France — ANSSI (National Cybersecurity Agency)

**GitHub:** [github.com/anssi-fr](https://github.com/ANSSI-FR) — 60+ repos, actively maintained[^1]

France's ANSSI is one of the most technically prolific intelligence agencies publishing open source. By law since 2016, all code written by French public agencies must be published.[^1]

### [ANSSI-FR/AD-control-paths](https://github.com/ANSSI-FR/AD-control-paths)

**Stars: ~1,800 — the most underused enterprise security tool**
Maps every **Active Directory privilege escalation path** as a graph — who can control what, through how many hops. ANSSI built this to audit French government AD forests. Point it at any Windows domain and get a complete graph of every path to Domain Admin. Infinitely more useful than BloodHound for static auditing — no agent required, pure LDAP queries.

### [ANSSI-FR/polichombr](https://github.com/ANSSI-FR/polichombr)

**Stars: ~400**
**Collaborative malware analysis platform** — multi-analyst, shared workspace for reverse engineering malware families. Built for ANSSI's incident response teams to coordinate during national-level breaches. Features: shared IDA Pro-like analysis, automatic family clustering, yara rule generation, API for automation. Most commercial alternatives cost \$50k/year.[^2]

### [ANSSI-FR/lancelot](https://github.com/ANSSI-FR/lancelot)

**Stars: ~300**
A **malware code analysis framework** specifically for extracting control flow and data flow from obfuscated binaries — built because Ghidra and IDA Pro both fail on heavily obfuscated modern malware. Pure Rust. Works on binaries where standard disassemblers give up.

### [ANSSI-FR/SecuML](https://github.com/ANSSI-FR/SecuML)

**Stars: ~600**
**Machine learning for intrusion detection** — a full training pipeline with a web UI for security analysts who aren't data scientists. You feed it labeled network logs, it trains detection models, visualizes results, lets you interactively refine classifications. ANSSI uses this internally to build custom detection for nation-state TTPs.[^3]

### [ANSSI-FR/bmc-tools](https://github.com/ANSSI-FR/bmc-tools)

**Stars: ~500 — forensically invaluable**
Parses **RDP Bitmap Cache** files — Windows stores thumbnails of every Remote Desktop session in a hidden binary cache. This tool extracts and reconstructs those images. In incident response: you can visually reconstruct what an attacker saw on a compromised machine they accessed via RDP, even after logs are wiped.

***

## 🇩🇪 Germany — BSI + Sovereign Tech Agency

### [BSI/Botan](https://github.com/randombit/botan) (BSI-funded)

**Stars: ~2,500 — the most serious crypto library nobody uses**
Germany's BSI funded the development of Botan — a cryptographic library designed from scratch to be **auditable, correct, and maintainable** rather than fast-first. Written in C++, covers TLS 1.3, post-quantum algorithms (Kyber, Dilithium), X.509 — everything. The BSI doesn't just fund it — they mandate it for German government systems. If you're building anything that touches crypto and correctness matters more than raw throughput, this is what you should be using instead of OpenSSL.[^4]

### German Sovereign Tech Agency Portfolio

**~€23 million invested across 60 OSS projects (2022–2024)**[^5]
The STF publishes a list of every project they fund — almost all criminally undervalued:

- **curl** (yes, the curl) — got STF funding for a full security audit
- **Sequoia-PGP** — modern PGP implementation in Rust, funded to replace GnuPG
- **OpenMLS** — Messaging Layer Security protocol implementation, the foundation for post-Signal secure group messaging
- **Fortran stdlib** — funded because nuclear simulation and climate modeling run on Fortran and nobody was maintaining it
- **opencode.de** — Germany's government-wide GitLab instance for sharing public sector code[^6]

***

## 🇳🇱 Netherlands — NCSC-NL

**GitHub:** [github.com/NCSC-NL](https://github.com/NCSC-NL)[^7]

### [NCSC-NL/taranis3](https://github.com/markov2/taranis3) (now community maintained)

**Stars: ~100 — operational threat intelligence platform**
The Dutch NCSC's internal **threat intelligence aggregation and dissemination platform** — collects feeds, correlates IOCs, creates advisories, pushes to subscribers. Now maintained by community after NCSC handed it off. Built for national-level threat intel ops. Most comparable commercial products (Anomali, ThreatConnect) cost \$100k+/year.[^8]

### NCSC-NL Vulnerability Response Repos

NCSC-NL publishes **rapid detection scripts** for every major CVE within hours of disclosure — MoveIT, Spring4Shell, OpenSSL. These are operationally-ready shell scripts and YARA rules, not theoretical advisories. Better than any commercial vendor's response speed.[^7]

***

## 🇷🇺 Russia — Yandex

**GitHub:** [github.com/yandex](https://github.com/yandex) — 148 repos[^9]

Yandex is Russia's Google — but their engineering culture produced tools that are **technically superior to Western equivalents** in specific domains. These were built to handle Yandex-scale problems: 100M+ daily users, petabytes of logs, real-time ad bidding at sub-millisecond latency.

### [yandex/ClickHouse](https://github.com/ClickHouse/ClickHouse)

**Stars: ~40k — known but still massively underused**
The fastest **columnar analytical database** ever benchmarked. Yandex built it because no existing DB could handle their web analytics at scale. Now used by Cloudflare, ByteDance, Uber, Spotify. Most people still use Postgres or BigQuery for analytics workloads that ClickHouse would run 100–1000x faster. Sub-second queries on billions of rows on a single machine. For your telemetry and ablation study pipeline — this is the correct database.[^10]

### [yandex/CatBoost](https://github.com/catboost/catboost)

**Stars: ~8k**
Yandex's **gradient boosting library** — built specifically to handle categorical features natively (hence Cat-Boost) without one-hot encoding. Outperforms XGBoost and LightGBM on tabular datasets with high-cardinality categoricals. Yandex uses it to rank 100M+ search results. Most ML practitioners haven't touched it because XGBoost got there first. For any structured data ML problem — benchmark CatBoost first.[^10]

### [yandex/YaLM-100B](https://github.com/yandex/YaLM-100B)

**Stars: ~4k — geopolitically interesting**
Yandex's **100B parameter LLM** released in 2022  — trained on Russian + English text, 65 days on 800 A100s. One of the first 100B+ open-weight models. Most Western researchers never looked at it because it's Russian. The Russian-language capability is unmatched in open weights — if you ever need Cyrillic NLP, this is the only serious option in open source.[^11]

### [yandex/YaFSDP](https://github.com/yandex/YaFSDP)

**Stars: ~500**
Yandex's **LLM training optimization framework** — 25% faster training, 20% less GPU memory than PyTorch FSDP. Released 2024. Almost nobody outside Russia's ML community knows it exists. For anyone training LLMs on limited GPU budgets — this is free performance on the table.[^12]

***

## 🇨🇳 China — Huawei / Baidu / State-Backed Ecosystem

China treats open source as national infrastructure strategy — government-backed labs publish tools built at China-internet scale.[^13]

### [mindspore-ai/mindspore](https://github.com/mindspore-ai/mindspore)

**Stars: ~4k — geopolitically sandbagged**
Huawei's **deep learning framework** built to run on their Ascend NPU hardware — but also runs on GPU/CPU. Key advantage: **privacy-preserving training** — the framework processes only gradients, never raw training data. Built this way because Chinese regulation requires data sovereignty. For federated learning or privacy-sensitive ML — this is more thoughtfully designed than PyTorch from a data-privacy architecture perspective. Western ML community ignores it entirely because of Huawei's US blacklist status.[^14][^15]

### [PaddlePaddle/Paddle](https://github.com/PaddlePaddle/PaddlePaddle)

**Stars: ~22k — seriously undervalued outside China**
Baidu's ML framework — **dominant in China's production AI systems**. The OCR models (PaddleOCR), NLP models (ERNIE), and CV models (PaddleDetection) built on it are state-of-the-art and completely open. PaddleOCR specifically handles Chinese, Japanese, Korean text recognition better than anything in the Western ML ecosystem. For any multilingual document processing pipeline — mandatory to benchmark.[^13]

### [apache/incubator-brpc](https://github.com/apache/brpc) (Baidu origin)

**Stars: ~16k**
Baidu's **industrial-grade RPC framework** — what Baidu's entire internal service mesh runs on. Handles millions of QPS, has built-in load balancing, circuit breaking, and a web dashboard for real-time service inspection. Donated to Apache. Outperforms gRPC in most benchmarks. The fact that gRPC is the default choice for most people while brpc exists is purely a marketing gap.

***

## 🇮🇱 Israel — Unit 8200 Alumni Ecosystem

Unit 8200 doesn't have a GitHub. What it has instead is an **alumni network that produces the majority of Israel's cybersecurity unicorns**. Average acquisition value of 8200-founded company: \$317M. Notable exits: Wiz (\$32B to Google — largest cybersecurity acquisition ever), Check Point, CyberArk, Palo Alto Networks.[^16][^17]

The open source they publish comes through their companies:

### [aquasecurity/trivy](https://github.com/aquasecurity/trivy)

**Stars: ~25k — the correct container security scanner**
Aqua Security (8200 alumni-founded) — **comprehensive vulnerability scanner** for containers, filesystems, git repos, cloud configs. Finds CVEs, misconfigs, secrets, SBOM. Replaced everything else in this category. If you're running Docker containers and not scanning with Trivy in CI, you have unknown vulnerabilities in production.

### [aquasecurity/tracee](https://github.com/aquasecurity/tracee)

**Stars: ~3,500 — criminally underused**
**Runtime security and forensics using eBPF** — hooks into the Linux kernel at runtime to detect malicious behavior without agents or kernel modules. Built by 8200 alumni who understand exactly how nation-state malware operates at the kernel level. Detects: privilege escalation, lateral movement, data exfiltration — in real time, with cryptographic event trails. The Transparent Computing architecture (DARPA) meets real-time production security.

***

## 🇪🇺 EU Institutions

### [eu-digital-identity-wallet](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)

**Stars: ~800 — the most important identity project in the world right now**
The EU is building a **universal digital identity wallet** — every EU citizen gets a cryptographic identity that works for banking, government services, healthcare, border control across all 27 member states. The entire architecture and reference implementation is open source. This will cover 450M people. The cryptographic design, the credential format (mdoc/CBOR), the trust framework — all published. For anyone building identity, authentication, or credential systems — this is the architecture you'll be complying with by 2027 under EU regulation.[^18]

### [CERN/invenio](https://github.com/inveniosoftware/invenio) + [CERN/rucio](https://github.com/rucio/rucio)

**Stars: ~800 / ~1,600**
CERN's **research data management** systems. Rucio manages petabyte-scale distributed scientific data — it coordinates data placement across hundreds of grid sites globally (the LHC produces 15 petabytes/year). Invenio is the digital repository framework behind Zenodo (the world's largest open research data archive). For any project dealing with large-scale distributed file management or research data — these are the reference implementations.[^19]

***

## 🇸🇪 Sweden — FRA / NCSC

Sweden's NCSC merged into FRA (signals intelligence) in 2022. They published a paper in March 2026 proving open source infrastructure can meet classified security requirements  — which means their open source tooling is now being built to signals-intelligence security standards.[^20][^21]

Watch [github.com/ncsc-se](https://github.com/ncsc-se) — actively publishing post-quantum cryptography tooling and network monitoring infrastructure built to FRA standards.

***

## 🌍 The Full Country-Agency-Tool Map

| Country | Agency | Key Tool | What It Actually Does |
| :-- | :-- | :-- | :-- |
| 🇫🇷 France | ANSSI | AD-control-paths | Full AD privilege graph — every path to Domain Admin |
| 🇫🇷 France | ANSSI | Polichombr | Collaborative malware analysis platform |
| 🇫🇷 France | ANSSI | bmc-tools | Recover attacker's RDP session visuals from cache |
| 🇫🇷 France | ANSSI | SecuML | ML-powered intrusion detection with analyst UI |
| 🇩🇪 Germany | BSI | Botan | BSI-audited cryptographic library — post-quantum ready |
| 🇩🇪 Germany | STF | OpenMLS | Post-Signal secure group messaging protocol |
| 🇳🇱 Netherlands | NCSC-NL | Taranis3 | National-grade threat intelligence platform |
| 🇷🇺 Russia | Yandex | ClickHouse | Fastest analytical DB ever benchmarked |
| 🇷🇺 Russia | Yandex | CatBoost | Gradient boosting that beats XGBoost on categoricals |
| 🇷🇺 Russia | Yandex | YaLM-100B | Only serious open-weight Russian-language LLM |
| 🇷🇺 Russia | Yandex | YaFSDP | 25% faster LLM training, 20% less GPU RAM |
| 🇨🇳 China | Huawei | MindSpore | Privacy-preserving ML framework for Ascend + GPU |
| 🇨🇳 China | Baidu | PaddlePaddle + PaddleOCR | Best multilingual OCR + production ML stack |
| 🇨🇳 China | Baidu | brpc | Industrial RPC framework — outperforms gRPC |
| 🇮🇱 Israel | 8200 alumni | Trivy | Best container/filesystem vulnerability scanner |
| 🇮🇱 Israel | 8200 alumni | Tracee | eBPF runtime security — kernel-level threat detection |
| 🇪🇺 EU | Commission | EUDI Wallet | Universal cryptographic identity for 450M EU citizens |
| 🇪🇺 EU | CERN | Rucio | Petabyte-scale distributed data management |
| 🇸🇪 Sweden | FRA/NCSC | Post-quantum tooling | Signals-intelligence-grade crypto infrastructure |
| 🇦🇺 Australia | ASD | Constellation | Billion-node graph visualization — GPU accelerated |

The common thread globally: every state-funded tool was built under **constraints no commercial team ever faces** — national scale, classified requirements, adversarial operators, or physics experiment data volumes. Then open sourced because the problem was solved and maintenance is cheaper with community help.[^5][^13][^1]
<span style="display:none">[^22][^23][^24][^25][^26][^27][^28][^29][^30][^31][^32][^33][^34][^35][^36][^37][^38][^39][^40][^41][^42][^43][^44]</span>

<div align="center">⁂</div>

[^1]: https://github.com/anssi-fr

[^2]: https://github.com/anssi-fr/polichombr/pulls

[^3]: https://github.com/ANSSI-FR/SecuML

[^4]: https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Kryptografie/Kryptobibliothek-Botan/kryptobibliothek-botan_dvl.html

[^5]: https://github.blog/open-source/maintainers/we-need-a-european-sovereign-tech-fund/

[^6]: https://www.opensourcerers.org/2024/03/18/open-source-in-the-public-sector-germany/

[^7]: https://github.com/NCSC-NL

[^8]: https://github.com/orgs/NCSC-NL/repositories

[^9]: https://github.com/yandex

[^10]: https://www.hkml.ai/2019/10/hong-kong-machine-learning-season-2-episode-2/

[^11]: https://github.com/yandex/YaLM-100B

[^12]: https://opensource.yandex/en/projects/

[^13]: https://theconversation.com/deepseek-how-chinas-embrace-of-open-source-ai-caused-a-geopolitical-earthquake-249563

[^14]: https://github.com/mindspore-ai/mindspore

[^15]: https://viso.ai/deep-learning/mindspore-ai/

[^16]: https://israeltech.com/blog/8200-alumni-association-powering-israels-startup-nation/

[^17]: https://www.stacksync.com/blog/the-bigquery-engineer-who-left-google-the-origin-story-of-firebolt

[^18]: https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework

[^19]: https://github.com/CERN/awesome-cern

[^20]: https://therecord.media/sweden-ncsc-moving-under-signals-intelligence-agency-fra

[^21]: https://www.sans.org/white-papers/open-source-national-security-infrastructure-swedens-national-security-apparatus

[^22]: https://interoperable-europe.ec.europa.eu/sites/default/files/inline-files/Croatia 2025 - Country Intelligence Report_1.pdf

[^23]: https://www.realinstitutoelcano.org/en/analyses/can-open-source-secure-europes-digital-infrastructure/

[^24]: https://github.com/GeiserX/awesome-europe

[^25]: https://www.theregister.com/2025/07/24/microsoftowned_github_says_open_source/

[^26]: https://money.usnews.com/investing/news/articles/2026-03-20/russia-to-give-itself-sweeping-powers-to-ban-or-restrict-foreign-ai-tools

[^27]: https://www.siliconrepublic.com/business/alibaba-latest-to-take-advantage-of-chinas-openclaw-frenzy

[^28]: https://github.com/paulpogoda/OSINT-Tools-Russia

[^29]: https://www.techradar.com/pro/security/alibaba-reveals-openclaw-app-despite-the-chinese-government-recently-cracking-down-on-the-platform

[^30]: https://omega-x.eu/2025/04/29/omega-x-launches-public-github-to-share-open-source-tools-and-insights/

[^31]: https://www.ssoar.info/ssoar/bitstream/handle/document/86775/ssoar-russanald-2023-293-limonier-What_Open_Source_Investigations_OSINT.pdf?sequence=1

[^32]: https://www.ssoar.info/ssoar/bitstream/handle/document/86775/ssoar-russanald-2023-293-limonier-What_Open_Source_Investigations_OSINT.pdf?isAllowed=y\&lnkname=ssoar-russanald-2023-293-limonier-What_Open_Source_Investigations_OSINT.pdf\&sequence=1

[^33]: https://github.com/MorvanZhou/NLP-Tutorials/projects

[^34]: https://blog.krybot.com/t/unlock-the-power-of-natural-language-understanding-with-yandexs-new-course/36298

[^35]: https://indico.cern.ch/event/514434/contributions/2141751/attachments/1266238/1874521/Yandex-ML-solutions.pdf

[^36]: https://github.com/yandexdataschool/nlp_course

[^37]: https://github.com/mindspore-ai

[^38]: https://www.mindspore.cn/tutorials/en/r1.7/beginner/introduction.html

[^39]: https://siliconangle.com/2020/03/30/huawei-open-sourced-ai-framework-called-mindspore-rival-googles-tensorflow/

[^40]: https://github.com/ANSSI-FR/polichombr/issues

[^41]: https://techcrunch.com/2020/08/21/china-is-building-its-github-alternative-gitee/

[^42]: https://consumer.huawei.com/en/community/details/topicId-104024/

[^43]: https://github.com/DeJuPo/TSE-Simulator

[^44]: https://github.com/mindspore-ai/mindspore-lite

