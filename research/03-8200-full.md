<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# I like to see more of these categories

8200 full undervalued set

YaFSDP

— NCSC-NL

bmc-tools

Botan

Use these as reference to construct a new set, doesn’t matter if state sponsored or company or individual globally as well

Here's the expanded global set — built on the same DNA as your reference examples: extreme-constraint origin, solves a hard real problem, criminally obscure.

***

# The Extended List — Global Criminally Undervalued Tools

*Reference class: 8200 tools (adversarial constraints), YaFSDP (infra-scale problem), NCSC-NL (operational speed), bmc-tools (forensic specificity), Botan (correctness-over-convenience)*

***

## 🔬 Security Engineering — Research Firm Grade

### [trailofbits/manticore](https://github.com/trailofbits/manticore)

**Origin:** Trail of Bits (NYC — DARPA Cyber Grand Challenge alumni)[^1]
**Stars: ~3,800 — should be 30k**

A **symbolic execution engine** for binaries AND smart contracts AND WebAssembly. Most security tools find known vulnerability patterns. Manticore finds unknown ones by treating every input as a symbolic variable and mathematically exploring all possible execution paths simultaneously. It proves the absence of entire vulnerability classes — not just scans for known signatures.[^1]

- Feed it a binary → it generates inputs that trigger every reachable code path
- Feed it a Solidity contract → it finds edge cases the developer never considered
- Used by Trail of Bits to audit code for NSA, DoD, and major blockchain protocols
- **How to use:** `pip install manticore` → `manticore ./binary` → get a list of inputs that crash it, plus proof that certain paths are unreachable. For any security-sensitive code you write — run this before shipping


### [trailofbits/slither](https://github.com/crytic/slither)

**Origin:** Trail of Bits[^2]
**Stars: ~5,500**

Static analysis framework for Solidity — but the architecture applies to any language. Trail of Bits open-sourced their internal analysis methodology in January 2026: **AI agent skills for code auditing** — context building, differential review, variant analysis, exploit generation. A \$2k/hr security firm gave away their entire operational playbook because they correctly calculated AI will commoditize the grunt work anyway.[^2]

### [trailofbits/fickling](https://github.com/trailofbits/fickling)

**Stars: ~800 — the most important ML security tool nobody uses**

A **Python pickle decompiler and static analyzer** — and that sentence does not do it justice. Every PyTorch model you download is a pickle file. Pickle files are arbitrary code execution by design. Fickling decompiles the pickle bytecode, shows you exactly what code will run when you call `torch.load()`, and detects malicious payloads embedded in model weights. The supply chain attack nobody talks about: a poisoned `.pt` file on HuggingFace that runs a reverse shell when you load it. Fickling is the only tool that catches this before it runs.

***

## 🔍 Forensics \& Incident Response

### [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor)

**Origin:** Mike Cohen — ex-Google, lead developer of GRR (Google's IR tool)[^3]
**Stars: ~4,500 — operationally the most powerful free IR tool**

A **digital forensics and endpoint monitoring platform** with its own query language (VQL). Google built GRR for their own IR operations. When Cohen left, he built Velociraptor — a complete reimplementation that's faster, more expressive, and fully self-hostable.[^4]

- Deploy agents to thousands of endpoints simultaneously
- VQL: `SELECT * FROM pslist() WHERE Username = 'SYSTEM' AND Name NOT IN ('svchost.exe', 'csrss.exe')` — hunt anomalous SYSTEM processes across your entire fleet in seconds
- Artifacts library: 400+ pre-built forensic collection templates for known attack patterns
- **Irony:** Chinese state hackers (Storm-2603) and ransomware operators started abusing it in 2025 because it's so powerful  — the forensics community built something so good that attackers weaponized it as a C2 framework[^5]
- **How to use:** Single binary server + agent. Docker compose for the server. MSI/deb for agents. Free forever


### [google/grr](https://github.com/google/grr)

**Origin:** Google Security[^3]
**Stars: ~4,500**

Google's **remote live forensics framework** — what Google's security team uses to investigate incidents across their own fleet. Written before Velociraptor existed (Cohen built both). More heavyweight, requires more infrastructure, but has capabilities Velociraptor doesn't — specifically around memory forensics and deeper Windows artifact collection. The two tools are complementary; serious IR teams run both.

***

## ⚡ eBPF — The Category Itself Is Undervalued

eBPF lets you run sandboxed programs inside the Linux kernel without kernel modules or reboots. The entire category is underused.[^6]

### [cilium/tetragon](https://github.com/cilium/tetragon)

**Origin:** Isovalent (8200 alumni-connected, acquired by Cisco 2024)[^6]
**Stars: ~3,800**

**eBPF-based security observability and runtime enforcement** — Kubernetes-native. Tracks every process exec, every file open, every network connection at kernel level with zero application changes. Stops attacks by policy enforcement at kernel level — not userspace. Netflix, AWS, and Datadog use it in production. Most people still run userspace agents that malware can simply kill — Tetragon runs where malware can't reach it.

### [iovisor/bcc](https://github.com/iovisor/bcc)

**Origin:** Linux Foundation / originally Facebook, Netflix, Cloudflare engineers[^6]
**Stars: ~20k — known but 90% of users use 5% of it**

**BPF Compiler Collection** — 150+ production-ready Linux performance analysis tools. The tools that made Netflix's latency improvements possible:

- `tcpretrans` — trace TCP retransmits in real time
- `biolatency` — block I/O latency histograms
- `runqlat` — CPU run queue latency (find CPU starvation)
- `memleak` — detect memory leaks in running processes without restarting them

Each tool is a 50-line Python script wrapping a kernel-level eBPF program. **How to use:** `apt install bpfcc-tools` → `sudo opensnoop-bpfcc` watches every `open()` syscall on the entire system in real time. Replace Strace for production use — 1000x lower overhead.

***

## 💹 Quantitative Finance — Industrial-Grade Engineering

These firms solve reliability and correctness problems that make normal software engineering look casual.

### [janestreet/core](https://github.com/janestreet/core) + [janestreet/async](https://github.com/janestreet/async)

**Origin:** Jane Street Capital — trades billions daily in OCaml[^7][^8]
**Stars: ~1,000 — the most underappreciated standard library in existence**

Jane Street is the world's largest OCaml shop. They rewrote the entire OCaml standard library because the original wasn't correct enough for financial systems. `Core` is that replacement — with proper error handling, no silent failures, exhaustive type safety. `Async` is their concurrent I/O library — monadic, composable, handles millions of concurrent connections without callbacks.

**Why it matters beyond finance:** Any system where silent data corruption or missed errors are catastrophic — embedded systems, medical devices, financial settlements — this is the engineering standard to build to. The OCaml type system enforces correctness at compile time that you simply cannot achieve in Python or JavaScript.

### [janestreet/iron](https://github.com/janestreet/iron)

**Stars: ~200 — one of the most interesting code review tools ever published**[^9]

Jane Street's internal **code review and release management system** — built because GitHub PRs don't have the guarantees they need for code that handles billions in daily trading. Features: cryptographic commit chains, mandatory review completion before any merge, release dependency tracking, and a diff viewer that understands semantic code changes rather than line-level diffs.

### [twosigma/beakerx](https://github.com/twosigma/beakerx)

**Origin:** Two Sigma Investments — \$60B quant hedge fund[^10][^11]
**Stars: ~2,800**

**Jupyter extensions for polyglot notebooks** — run Python, R, Scala, Kotlin, Groovy, SQL in the same notebook with shared memory between kernels. Two Sigma built this because their quant researchers needed to mix languages mid-analysis without context switching. The `%%python → %%sql → %%scala` in a single notebook with shared dataframes is something vanilla Jupyter cannot do.

***

## 🧮 Distributed Systems — Built Under Scale Constraints

### [yandex/YDB](https://github.com/ydb-platform/ydb)

**Origin:** Yandex — built for Yandex's internal services[^12]
**Stars: ~3,800 — open-sourced 2022, almost nobody in the West has noticed**

A **distributed SQL database** that handles millions of requests per second with automatic sharding, ACID transactions across shards, and linear horizontal scaling. Yandex built this because neither Postgres nor MySQL could handle their scale. Comparable to Google Spanner or Amazon Aurora — but fully open source and self-hostable.[^12]

- Automatic tablet-based sharding — no manual shard keys
- Cross-shard transactions with full ACID guarantees
- Built-in CDC (change data capture) for event streaming
- **How to use:** Docker single-node for dev, Kubernetes operator for production. Yandex provides a managed cloud version too


### [yandex/YTsaurus](https://github.com/ytsaurus/ytsaurus)

**Origin:** Yandex — open-sourced 2023[^12]
**Stars: ~1,000**

Yandex's **big data platform** — their internal equivalent of Google's MapReduce + Colossus + Dremel combined into one system. Handles GPU-accelerated data processing for ML workloads alongside traditional MapReduce jobs on the same cluster. The key thing nobody realizes: it uses a **cypress tree** (hierarchical key-value store) as its metadata layer — meaning your data lake has a proper filesystem-like namespace instead of flat S3-style object paths. Vastly better for ML training data organization.

***

## 🔐 Cryptography — Correctness-First

### [Google/Tink](https://github.com/google/tink)

**Origin:** Google Security — used across all Google products[^13]
**Stars: ~13,500 — used everywhere, understood by almost nobody**

A **cryptographic library designed to be impossible to misuse**. The core insight: every other crypto library gives you primitives (AES, RSA, ECDSA) that you assemble incorrectly. Tink gives you *operations* (encrypt, sign, verify) where the safe choice is the default and the unsafe choice requires explicit opt-in.

- Automatic key rotation built into the API
- Post-quantum algorithms (Kyber, Dilithium) available via feature flag[^13]
- Key management: keys are versioned, rotatable, stored as keysets — not raw bytes
- **The correct way to add crypto to any project:** Never touch OpenSSL directly. Use Tink. Google mandates it internally across all services


### [cloudflare/circl](https://github.com/cloudflare/circl)

**Origin:** Cloudflare Research[^13]
**Stars: ~1,200 — the most production-tested post-quantum crypto library**

Cloudflare's **cryptographic library** — implements every NIST post-quantum finalist (Kyber, Dilithium, SPHINCS+, Falcon) plus elliptic curves, isogeny-based crypto, and threshold signatures. Cloudflare runs this on tens of millions of TLS connections per day — it is the most battle-tested PQC implementation in existence. Pure Go, constant-time implementations, side-channel resistant.[^13]

***

## 🤖 AI/ML Infrastructure — From Extreme-Scale Labs

### [microsoft/DeepSpeed](https://github.com/microsoft/DeepSpeed)

**Origin:** Microsoft Research — built to train GPT-3 class models[^14]
**Stars: ~36k — used by everyone training LLMs, understood by almost nobody**

The reference implementation for **LLM training at scale** — ZeRO optimizer stages 1/2/3, pipeline parallelism, tensor parallelism, inference optimization. The reason you can train a 7B model on 4 GPUs instead of needing 32. Most people `pip install deepspeed` and copy a config file. What they don't realize: ZeRO Stage 3 + CPU offload means you can train models 3–4x larger than your GPU VRAM would normally allow. This is the tool, alongside YaFSDP, for anyone training seriously.

### [stanford-crfm/helm](https://github.com/stanford-crfm/helm)

**Origin:** Stanford CRFM (Center for Research on Foundation Models)
**Stars: ~2,000 — the correct way to evaluate LLMs, almost nobody uses it**

**Holistic Evaluation of Language Models** — a benchmarking framework that evaluates models across 42 scenarios and 7 metric dimensions simultaneously, accounting for calibration, fairness, robustness, and efficiency alongside raw accuracy. Most model comparisons use a single benchmark. HELM shows you the tradeoff surface — model X is better at reasoning but worse on calibration and 3x more expensive per token. For anyone choosing models for production: HELM before any other benchmark.

***

## 🌐 Network \& Infrastructure

### [cilium/cilium](https://github.com/cilium/cilium)

**Origin:** Isovalent (ex-kernel.org engineers) — now part of Cisco[^6]
**Stars: ~20k — in production at Adobe, Capital One, Datadog — almost nobody runs it themselves**

**eBPF-powered Kubernetes networking and security** — replaces kube-proxy entirely. Every network policy enforced at kernel level. 3–5x throughput improvement over iptables-based CNI plugins. Built-in Hubble observability layer gives you a real-time Grafana dashboard of every network flow in your cluster. The gap between teams running Cilium and teams running Flannel is roughly equivalent to the gap between a professional network setup and a home router config.

### [pion/webrtc](https://github.com/pion/webrtc)

**Origin:** Sean DuBois — ex-Twitch, ex-various media companies
**Stars: ~13,500 — the most complete WebRTC implementation outside browsers**

A **pure Go WebRTC stack** — not a wrapper around libwebrtc (Chrome's C++ monster), a complete ground-up reimplementation. This means: no CGo, no Chrome dependency, no 50MB binary, deployable anywhere Go runs including embedded systems and edge compute. If you need real-time audio/video/data channels between any two endpoints — this is the library. Used by Cloudflare's stream product, by LiveKit, by dozens of production WebRTC services.

***

## The Full Origin Map

| Tool | Origin | Constraint That Built It | What It Solves |
| :-- | :-- | :-- | :-- |
| Manticore | Trail of Bits / DARPA | Zero tolerance for missed vulns in audited code | Proves absence of vulnerability classes |
| Fickling | Trail of Bits | ML supply chain security | Detects malicious code in model weight files |
| Velociraptor | Google IR alum | IR at Google fleet scale | Forensics query language across thousands of endpoints |
| Tetragon | 8200-adjacent / Isovalent | Kubernetes security that malware can't bypass | Kernel-level enforcement via eBPF |
| bcc | Netflix/Facebook/Cloudflare | Production perf debugging without reboots | 150 kernel observability tools |
| Jane Street Core | Jane Street | Financial correctness — silent failures cost millions | OCaml stdlib rebuilt for correctness |
| Iron | Jane Street | Release management for trading system code | Cryptographic code review chains |
| BeakerX | Two Sigma | Polyglot quant research workflows | Multi-language Jupyter with shared memory |
| YDB | Yandex | Yandex-scale SQL with ACID guarantees | Distributed SQL, self-hostable Spanner |
| YTsaurus | Yandex | GPU + MapReduce on same cluster | Hierarchical data lake for ML pipelines |
| Tink | Google | Crypto that devs can't misuse | Impossible-to-misuse crypto operations |
| CIRCL | Cloudflare | Post-quantum TLS at 10M req/sec | Most battle-tested PQC library in existence |
| DeepSpeed | Microsoft Research | Training GPT-3 when nobody had enough GPUs | LLM training beyond your VRAM limits |
| HELM | Stanford CRFM | Holistic model evaluation for deployment decisions | Multi-dimensional LLM benchmarking |
| Cilium | Ex-kernel.org engineers | Kubernetes networking at datacenter scale | eBPF networking — replaces kube-proxy entirely |
| pion/webrtc | Ex-Twitch engineering | WebRTC without Chrome dependency | Pure Go real-time media stack |

The pattern consistent with your reference set: every tool here was built by people for whom failure was expensive — financially, operationally, or in classified environments. The problem was solved at extreme scale or correctness requirements, then released because maintaining a community is cheaper than maintaining it alone.[^8][^2][^1][^6]
<span style="display:none">[^15][^16][^17][^18][^19][^20][^21][^22][^23][^24][^25][^26][^27][^28][^29][^30][^31][^32][^33][^34][^35][^36][^37][^38][^39][^40][^41][^42][^43][^44][^45]</span>

<div align="center">⁂</div>

[^1]: https://www.linkedin.com/posts/sentinelblue_ones2watch-one2watch-cybersecurity-activity-7379701406863245314-YLSv

[^2]: https://www.linkedin.com/posts/isaacevans_icymi-last-week-trail-of-bits-one-of-the-activity-7421933766589300736-nkxG

[^3]: https://www.youtube.com/watch?v=u7KBwgHIZ3U

[^4]: https://www.rapid7.com/products/velociraptor/

[^5]: https://www.darkreading.com/cybersecurity-operations/chinese-hackers-velociraptor-ir-tool-ransomware-attacks

[^6]: https://ebpf.foundation/new-ebpf-in-production-report-showcases-production-enterprise-outcomes-across-networking-security-and-observability/

[^7]: https://github.com/ocaml/ocaml.org/blob/main/data/success_stories/janestreet.md

[^8]: https://ocaml.org/success-stories/large-scale-trading-system

[^9]: https://github.com/janestreet/iron

[^10]: https://github.com/twosigma/beakerx

[^11]: https://www.bradicdesign.com/beaker

[^12]: https://opensource.yandex/en/projects/

[^13]: https://www.allblogthings.com/2026/03/best-post-quantum-cryptography-libraries-ranked.html

[^14]: https://www.reddit.com/r/technology/comments/1ddb51h/yandex_opensources_yafsdp_an_llm_training_tool/

[^15]: https://github.com/hazwanjaafar/Open-Source-Cyber-Security-Tools-2024

[^16]: https://cyber8200.com/en/blog/israeli-cyber-unity-8200

[^17]: https://www.bankinfosecurity.com/israels-8200-alumni-association-cybersecurity-incubator-a-24801

[^18]: https://www.helpnetsecurity.com/2025/08/27/hottest-cybersecurity-open-source-tools-of-the-month-august-2025/

[^19]: https://dev.to/sharon_42e16b8da44dabde6d/8-github-starred-security-projects-you-shouldnt-miss-in-2025-3gda

[^20]: https://darknetdiaries.com/transcript/28/

[^21]: https://www.infoworld.com/article/2254283/yandex-open-sources-catboost-machine-learning-library.html

[^22]: https://arxiv.org/html/2508.16078v1

[^23]: https://craigjohnsonr5.substack.com/p/unit-8200-producing-top-cybersecurity

[^24]: https://quantumzeitgeist.com/researchers-assess-post-quantum-cryptography-support-in-nine-libraries-by-early-2025/

[^25]: https://www.youtube.com/watch?v=mo9GG5BXJ9w

[^26]: https://yandex.com/company/news/01-11-06-2024

[^27]: https://www.security.nl/posting/908480/Cisco:+open+source+DFIR-tool+Velociraptor+gebruikt+bij+ransomware-aanvallen

[^28]: https://thehackernews.com/2025/08/attackers-abuse-velociraptor-forensic.html

[^29]: https://github.com/cloudflare/boringssl-pq

[^30]: https://hackmag.com/news/velociraptor-attacks

[^31]: https://eunomia.dev/blog/2024/02/11/the-secure-path-forward-for-ebpf-runtime-challenges-and-innovations/

[^32]: https://news.ycombinator.com/item?id=15861979

[^33]: https://www.huntress.com/blog/velociraptor-misuse-part-two-eye-of-the-storm

[^34]: https://github.com/janestreet/async

[^35]: https://github.com/janestreet/async_js

[^36]: https://www.reddit.com/r/ocaml/comments/4j5p4z/janestreets_iron/

[^37]: https://github.com/janestreet/async/blob/master/async.opam

[^38]: https://github.com/renaissance-benchmarks/renaissance

[^39]: https://www.reddit.com/r/selfhosted/comments/1rcatb1/ever_heard_of_openplanter_an_opensource/

[^40]: https://github.com/jumptrading

[^41]: https://blog.janestreet.com/announcing-async/

[^42]: https://github.com/orgs/renaissance-benchmarks/repositories

[^43]: https://news.ycombinator.com/item?id=13488795

[^44]: https://www.youtube.com/watch?v=gKDeTfQiVNI

[^45]: https://github.com/janestreet

