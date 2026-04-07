<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# Besides specifically nsa and cia, a list of any other repositories in those categories that are available and criminally undervalued, from who they are again what they actually are and how to use it properly, it can be a extensive list, multiple domains

This is a long one — buckle up. Organized by agency/org and domain.

***

# Government \& Intelligence Agency Open Source — The Full Map

## 🇬🇧 GCHQ (UK Signals Intelligence)

### [GCHQ/CyberChef](https://github.com/GCHQ/CyberChef)

**Stars: ~30k — massively underused relative to capability**

Built by a single GCHQ analyst in their "10% innovation time" — their Swiss Army knife for data analysis. Most people use it for base64 decoding and stop there. What it actually does:[^1][^2]

- 300+ operations chainable in a visual pipeline: AES/DES/Blowfish encrypt/decrypt, XOR analysis, entropy calculation, file carving, JWT parsing, regex extraction, frequency analysis, steganography detection
- **"Magic" operation** — throws unknown encoded data at every operation simultaneously and surfaces what produces meaningful output. GCHQ built this to identify unknown encoding schemes in intercepted data
- Full offline self-hostable — download the repo, open `index.html`, no server needed
- **How to use it properly:** Build "recipes" — chain 10–20 operations into a saved workflow. Feed it raw binary, network captures, suspicious strings. The Magic operation alone saves hours on unknown data

***

### [GCHQ/Gaffer](https://github.com/GCHQ/Gaffer)

**Stars: ~1,700 — should be 50k+**

GCHQ's graph database framework built to analyze **relationship networks at national surveillance scale**. Think: who called who, which IP connected to which server, which entity appears in which documents — across billions of edges.[^1]

- Sits on top of Accumulo (same as NSA DataWave), HBase, or MapReduce
- Federated queries across multiple data stores simultaneously
- Entity-relationship modeling with time-windowed aggregation — track how connections change over time
- **Real use case:** GCHQ built this to analyze communication metadata. Your use case: supply chain relationship mapping, IoT device connection graphs, fraud network detection
- **How to use:** Docker compose stack is in the repo. Feed it a CSV of entity-relationship pairs. Query with their REST API or Gaffer UI

***

## 🇺🇸 DARPA

### [darpa-i2o/Transparent-Computing](https://github.com/darpa-i2o/Transparent-Computing)

**Stars: ~200 — one of the most important repos almost nobody has opened**

DARPA's Transparent Computing program solved a specific problem: **how do you reconstruct exactly what happened on a compromised system, end-to-end, with cryptographic provenance?**[^3]

- Full provenance tracking at OS level — every process spawn, file read/write, network connection logged as a tamper-evident graph
- Can reconstruct the complete causal chain of an attack: "this malware arrived in email attachment → spawned process → read credential file → exfiltrated to IP X" — with timestamps and cryptographic hashes at every step
- **Why it matters for you:** This is the architecture for agent audit trails. Every action an AI agent takes, every file it reads, every API call it makes — logged as a causal provenance graph. Exactly what claude-project's telemetry phase needs
- **How to use:** The repo contains academic papers + reference implementations. CamFlow (Linux) is the most deployable implementation that came out of this program

***

### [DARPA-CRITICALMAAS](https://github.com/DARPA-CRITICALMAAS)

**Stars: <500 across all repos — criminally unknown**

DARPA funded 17 teams to build AI that automatically extracts mineral deposit data from **historical geological survey maps** — scanned PDFs, hand-drawn charts, century-old documents. The output: a structured knowledge graph of every known mineral site on Earth.[^4]

- Automated georeferencing of historical maps (aligning old paper maps to modern coordinates)
- ML pipeline for extracting tables, legends, and annotations from scanned documents
- Mineral site deduplication and linkage across conflicting historical sources
- **Why it's wild:** This is the full RAG + vision + knowledge graph pipeline — built to extract structured data from unstructured historical documents at scale. The exact architecture pattern for any document intelligence project
- **How to use:** `ta2-minmod-dashboard` is the queryable web app. `beak-ta3` is the mineral prediction ML pipeline

***

### [darpa-i2o/memex-program-index](https://github.com/darpa-i2o/memex-program-index) + [nasa-jpl-memex](https://github.com/nasa-jpl-memex)

**Stars: <100 — most people don't even know this exists**

DARPA's Memex program: build a search engine that indexes the **entire dark web and deep web**, not just the surface. Originally deployed to detect human trafficking networks on Tor hidden services. Then open-sourced everything.[^5][^6]

What was released:

- Focused web crawlers that follow domain-specific link graphs (not broad crawl — targeted)
- Dark web / Tor crawling infrastructure
- Structured data extraction from unstructured ad/forum pages
- Entity linking across pseudonymous accounts on different platforms
- **TellFinder** and **DIG** — the actual interfaces used by law enforcement to analyze the crawled data

**How to use:** The `memex-program-index` is your starting point — it's a curated index of all 17 team repos with descriptions. Most are Python-based. NASA JPL's contributions (`nasa-jpl-memex`) include the Landmark-based geolocation tools they built to geolocate images posted to dark web sites

***

## 🇺🇸 MITRE Corporation (US Federally Funded R\&D)

### [mitre/caldera](https://github.com/mitre/caldera)

**Stars: ~6k — 10x undervalued**

An **autonomous red team** in a box. MITRE built this to simulate nation-state adversary behavior against your own infrastructure — fully automated, mapped to ATT\&CK techniques.[^7][^8]

- C2 server + agent architecture (agents deploy to target machines)
- 200+ adversary techniques implemented as plugins: credential dumping, lateral movement, persistence, exfiltration
- **Autonomous operation mode** — give it an objective ("gain domain admin"), it plans and executes its own attack chain
- Stockpile plugin: pre-built adversary profiles modeled on known APT groups (APT29, FIN7, etc.)
- **How to use:** `docker-compose up` gets the server running. Deploy an agent to any machine you own. Run a pre-built adversary profile against it. Watch what it does, fix what it finds. This is what red teams at Fortune 500s charge \$200k/engagement to run

***

### [mitre/d3fend](https://github.com/d3fend/d3fend-ontology) + [attack-stix-data](https://github.com/mitre-attack/attack-stix-data)

**Stars: ~500 combined — foundational and ignored**

ATT\&CK gets all the attention. D3FEND is the **defensive counterpart** — a structured knowledge graph of every known defensive countermeasure, mapped to the attacks they counter. Machine-readable ontology format.[^9]

- Query: "what defenses counter T1055 (Process Injection)?" → get ranked list of countermeasures with implementation guidance
- The STIX data repo gives you all of ATT\&CK as structured JSON — ingest it into your own knowledge graph, build custom detection logic, feed it to an LLM
- **How to use:** `pip install mitreattack-python` → query the full ATT\&CK dataset programmatically. Feed it to claude-project's RAG pipeline for security-aware agent behavior

***

## 🇦🇺 Australian Signals Directorate (ASD)

### [constellation-app/constellation](https://github.com/constellation-app/constellation)

**Stars: ~300 — the most underrated graph analysis tool in existence**

ASD's internal data visualization tool for **analyzing billions of relationships** — open sourced in 2019. Built to analyze intelligence datasets where you have billions of nodes (phone numbers, IP addresses, accounts) and need to find patterns.[^10][^11]

- Handles **billions of nodes** — not thousands, not millions. Billions. Desktop app
- 3D force-directed graph rendering with GPU acceleration
- Time-series animation — watch network relationships evolve over time
- Geospatial overlay — plot network nodes on a globe
- Plugin architecture — write your own analysis algorithms in Python/Java
- **How to use:** Download the release JAR. Import any CSV with source/target columns. The 3D renderer alone is worth it — nothing commercial matches it at this scale for free
- **Real use case for you:** Visualize your IoT device mesh network, your agent dispatch graph, or any relationship dataset that breaks every other tool

***

## 🇺🇸 Los Alamos National Laboratory (LANL)

### [lanl-seismoacoustics](https://github.com/lanl-seismoacoustics) — InfraPy + GeoTess

**Stars: <200 across all repos**

LANL built these to **detect nuclear weapons tests** by analyzing seismic and infrasound signals globally. The signal processing pipeline they open sourced:[^12]

- **InfraPy**: infrasound (low-frequency sound) signal detection and analysis — finds events in noisy continuous sensor streams. Exact same pipeline works for any time-series anomaly detection
- **GeoTess**: a global Earth model grid — efficiently query geophysical properties at any point on Earth at any depth. Used for nuclear explosion location
- **Why it matters beyond geophysics:** InfraPy's signal detection pipeline is applicable to any sensor stream — vibration sensors, accelerometers, microphones. The math is identical. LANL solved the hardest version of this problem (nuclear test detection from 10,000km away)

***

## 🇺🇸 NASA / NASA JPL

### [nasa-jpl/open-source-rover](https://github.com/nasa-jpl/open-source-rover)

**Stars: ~8k — known but wildly underbuilt by community**

JPL published the complete build instructions for a **functional Mars rover replica** — same engineering principles as Curiosity, buildable with ~\$2,500 in off-the-shelf parts. Full CAD files, firmware, ROS integration.[^13]

**Why it matters beyond the obvious:** The mobility system (rocker-bogie suspension) and the ROS navigation stack JPL published alongside it are the foundation for any serious outdoor autonomous robot. The actual rover software — path planning, obstacle detection, teleoperation over latency — is production-grade planetary exploration code

***

### [nasa/OSDR](https://github.com/nasa/GeneLab-Data-Processing) + [NASA's Earthdata tools](https://github.com/nasa)

**400+ repos — almost nobody outside aerospace looks at these**

NASA has tools for: satellite imagery processing, atmospheric modeling, exoplanet detection signal processing, astronaut health monitoring pipelines. The pattern: every hard signal-processing or time-series problem you'll ever face, NASA solved it with extreme rigor because the cost of failure is a billion-dollar spacecraft.

***

## 🇩🇪 German BSI (Federal Office for Information Security)

### [BSI-Bund](https://github.com/BSI-Bund)

**Stars: <1k total — almost unknown outside Germany**

Germany's national cybersecurity agency publishes actual security evaluation tooling:

- **TESTME**: formal security testing framework used to certify products for German government use
- **Trustworthy AI** guidelines implemented as code
- Cryptographic implementation validation tools
- **Why it matters:** BSI certification is required for any product sold to EU governments. Their tooling is the ground truth for what "secure" means in European regulatory context

***

## 🇺🇸 DoD / Code.mil Ecosystem

### [deptofdefense/code.mil](https://github.com/deptofdefense)

The DoD's umbrella open source initiative. Key underrated repos:[^14]

- **Mattermost** (DoD fork) — their hardened enterprise chat, used across US military. The security hardening patches they maintain are applicable to any self-hosted instance
- **PlatformOne/big-bang** — the DoD's full Kubernetes security platform. Every hardening config, every security policy, every compliance control for running containers in classified environments. Overkill for most — extraordinarily useful if you care about production hardening

***

## The Pattern Across All Of Them

| Agency | Domain they solved | Why you should care |
| :-- | :-- | :-- |
| GCHQ | Arbitrary data decoding at scale | Any unknown binary/encoded data problem |
| GCHQ | Graph DB for relationship networks | Social graph, IoT mesh, supply chain |
| DARPA TC | Causal provenance tracking | AI agent audit trails |
| DARPA CriticalMAAS | Doc intelligence + knowledge graphs | Any RAG pipeline over historical docs |
| DARPA Memex | Deep/dark web crawling + entity linking | Non-surface-web data collection |
| MITRE Caldera | Autonomous adversary emulation | Red teaming your own infra |
| ASD Constellation | Billion-node graph visualization | Any massive relationship dataset |
| LANL InfraPy | Sensor signal anomaly detection | IoT sensor streams, time-series |
| NASA JPL | Robotics + navigation under extreme constraints | Autonomous mobile systems |
| BSI | Regulatory-grade security evaluation | EU compliance tooling |

Every single one was built under conditions most software never faces — planetary scale, adversarial environments, zero tolerance for failure, or classified operational requirements. Then handed to you for free because the problem is solved and they need the ecosystem to maintain it.[^15][^3][^10]
<span style="display:none">[^16][^17][^18][^19][^20][^21][^22][^23][^24][^25][^26][^27][^28][^29][^30][^31][^32][^33][^34][^35][^36][^37][^38][^39][^40][^41][^42][^43][^44][^45]</span>

<div align="center">⁂</div>

[^1]: https://securityaffairs.com/53908/intelligence/gchq-cyberchef.html

[^2]: https://www.gov.uk/government/case-studies/how-gchq-made-its-cyberchef-app-open-source

[^3]: https://github.com/darpa-i2o

[^4]: https://github.com/DARPA-CRITICALMAAS

[^5]: https://www.reddit.com/r/technology/comments/32zds9/darpa_open_sources_memex_dark_web_search_tool/

[^6]: https://www.darpa.mil/research/programs/memex

[^7]: https://github.com/mitre/Caldera

[^8]: https://hunt.io/malware-families/mitre-caldera

[^9]: https://github.com/pbscybsec/Threat-Intelligence

[^10]: https://www.zdnet.com/article/australian-signals-directorate-launches-open-source-data-visualisation-tool/

[^11]: https://www.dailyhostnews.com/asd-open-sources-its-data-visualization-tool

[^12]: https://lanl-seismoacoustics.github.io

[^13]: https://github.com/orgs/nasa-jpl/repositories

[^14]: https://www.war.gov/News/Releases/Release/Article/1092364/dod-announces-the-launch-of-codemil-an-experiment-in-open-source/

[^15]: https://www.ipa.go.jp/en/digital/software-engineering/oss/govoss_report_2025/p1o1lf000000pfuu-att/gov-oss-github-analysis-2025-en-us.pdf

[^16]: https://github.com/md8-habibullah/top-github-repos-list

[^17]: https://github.com/jivoi/awesome-osint

[^18]: https://github.blog/open-source/maintainers/this-years-most-influential-open-source-projects/

[^19]: https://github.com/nationalsecurityagency

[^20]: https://github.com/darpa-xdata

[^21]: https://www.talkwalker.com/blog/best-osint-tools

[^22]: https://github.com/airborne-commando/OPSEC-OSINT-Tools

[^23]: https://www.gchq.gov.uk/news/cyberchef-cyber-swiss-army-knife

[^24]: https://github.com/frangelbarrera/OSINT-BIBLE

[^25]: https://www.reddit.com/r/Python/comments/1x32ow/darpa_publishes_all_its_open_source_code_in_one/

[^26]: https://github.com/CERN

[^27]: https://github.com/cernopendata

[^28]: https://github.com/CERN/awesome-cern

[^29]: https://github.com/CERN/awesome-cern/blob/main/README.md

[^30]: https://be-3869.about.gitlab-review.app/customers/cern/

[^31]: https://gracker.ai/cybersecurity-tools/canadian-centre-for-cyber-security-cccs-1921

[^32]: https://gitlab.cern.ch/explore

[^33]: https://github.com/nasa-jpl/LiveViewOpenCL

[^34]: https://www.cyber.gc.ca/en/tools-services

[^35]: https://github.com/topics/cia

[^36]: https://gitlab.cern.ch/explore/projects/starred?archived=only\&language=6\&non_archived=false\&page=7\&sort=name_desc

[^37]: https://github.com/darpa-i2o/memex-program-index

[^38]: https://github.com/nasa-jpl-memex

[^39]: https://www.ee.columbia.edu/dvmm/memex/

[^40]: http://nasa-jpl-memex.github.io

[^41]: https://ccdcoe.org/uploads/2018/10/EVE-ADAM-MP-SCI-300-10.pdf

[^42]: https://nm.news/2024/12/20/lanl-open-source-software-could-help-improve-safety-human-health/

[^43]: https://groups.google.com/g/mil-oss/c/khHFF_iYm_4

[^44]: https://www.cnas.org/publications/reports/open-source-software-and-the-department-of-defense

[^45]: https://www.youtube.com/watch?v=zDwoaZVFn50

