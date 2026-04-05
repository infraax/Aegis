# Aegis Integration Plan — Research Files 01 / 02 / 03

Full analysis of every repo from the three research files against Aegis's current
architecture. Organised by **priority tier**, then by Aegis module affected.

---

## Aegis Current Capability Map

| Module | What it does today |
|---|---|
| `classifier/` | Session event pipeline — 6 signal analyzers (timing, headers, TLS, behavioral, LLM, tool-sigs) → Tier 1/2/3 |
| `router/tier-router.ts` | Dispatches to tarpit / honeypot / escalate via Redis marker |
| `tarpit/` | HTTP tarpit for Tier 1 scanners |
| `honeypot/` | Adaptive deception — depth progression, context bombs, canary tokens |
| `supply-chain/` | SBOM collection + OSV CVE feed + correlator + isolation trigger |
| `intel-export/gun-exporter.ts` | One-way GUN.js P2P push to Pi5 dashboard |
| `mcp/` | MCP server for external tool integrations |

---

## Priority 1 — Drop-in Upgrades (High value, low integration cost)

### MITRE ATT&CK STIX Data + D3FEND
**Source:** `mitre-attack/attack-stix-data` + `d3fend/d3fend-ontology`
**Affects:** `classifier/signals/behavioral.ts` + `router/tier-router.ts`

Right now `behavioral.ts` does pattern matching against a hand-written list of
suspicious path patterns. ATT&CK STIX gives you the entire adversary technique
catalogue as structured JSON — 700+ techniques with detection logic, tool
associations, and procedure examples.

**Integration:**
- `pip install mitreattack-python` or pull the STIX JSON directly
- At startup, ingest the STIX bundle into an in-memory map:
  `technique_id → { name, detection_hints, associated_tools }`
- In `behavioral.ts`, map observed request patterns to specific ATT&CK technique
  IDs instead of generic "suspicious path" flags
- Each `Classification` object gains a `techniqueIds: string[]` field
  (e.g. `["T1595.001", "T1190"]`) — structured, exportable, searchable
- D3FEND maps each technique to its recommended countermeasure — feed this into
  the router to auto-select response strategy rather than hardcoded tier logic

**Replaces:** The current hand-rolled pattern matching in behavioral.ts
**Effort:** 1–2 days — the STIX data is clean JSON, `mitreattack-python` has a
good query API, and the TypeScript side is just an enum enrichment

---

### IQT Labs / gitgeo
**Source:** `github.com/iqtlabs/gitgeo`
**Affects:** `supply-chain/sbom-collector.ts`

Currently the SBOM collector knows *what* packages are installed and *what version*,
but nothing about who maintains them or where they are. Gitgeo maps GitHub
contributors to countries via timezone patterns, commit metadata, and email domains.

**Integration:**
- For each package in the SBOM where a GitHub repo is known (npm, pip, cargo all
  have source URLs), run gitgeo against the maintainer list
- Add `maintainerGeography: { country: string; confidence: number }[]` to the
  `Package` interface
- Flag packages where >60% of recent commits come from a single high-risk geography
  as a supply chain risk signal — feeds into `correlator.ts` as a severity modifier
- This is the exact attack vector that the SolarWinds and XZ Utils compromises
  followed — a geographic concentration attack

**Replaces:** Nothing — purely additive enrichment
**Effort:** 2–3 days — gitgeo is Python, wrap it in a child_process call or
containerise it as a sidecar the sbom-collector queries

---

### Google / Tink
**Source:** `github.com/google/tink`
**Affects:** `honeypot/adaptive-engine.ts` + `intel-export/gun-exporter.ts`

Canary tokens are currently bare UUID hex strings. If an attacker recognises the
pattern they can strip them before exfiltration. Tink gives signed, unforgeable
tokens and properly encrypted intel payloads.

**Integration:**
- Replace `issueCanaryToken()` — instead of `uuidv4().slice(0,16)`, generate a
  Tink MAC over `{ sessionId, timestamp, type }` — the token is now a verifiable
  proof of when and where it was issued
- Wrap `exportEvent()` payloads in Tink AEAD before writing to GUN — even if the
  GUN relay is compromised, threat intel stays encrypted
- Key rotation built-in — no manual key management

**Replaces:** Raw UUID canary tokens; plaintext GUN payloads
**Effort:** 1 day — `npm install @google-cloud/kms` or use Tink's local keyset
mode with no cloud dependency

---

### Trail of Bits / Fickling
**Source:** `github.com/trailofbits/fickling`
**Affects:** `supply-chain/` — new scanner module

Every PyTorch `.pt` model file is a Python pickle. Pickle is arbitrary code
execution by design. Fickling decompiles pickle bytecode and detects malicious
payloads before the file is ever loaded.

**Integration:**
- Add `supply-chain/model-scanner.ts` — when the SBOM collector discovers
  `.pt` / `.pkl` / `.pth` files on any node, queue them for fickling scan
- `fickling --check-safety model.pt` returns exit 0 (safe) or 1 (malicious)
  with a full report of what code would execute
- Flag any model file that fails as a supply chain critical — same severity
  path as `isSupplyChainAttack = true` in correlator.ts
- The XZ Utils attack vector was a poisoned build artifact; this closes the ML
  model equivalent

**Replaces:** Nothing — closes a blind spot entirely
**Effort:** 2 days — fickling is `pip install fickling`, scanner is a thin wrapper

---

## Priority 2 — Significant Capability Additions

### Velocidex / Velociraptor
**Source:** `github.com/Velocidex/velociraptor`
**Affects:** `router/tier-router.ts` — Tier 3 escalation path

Currently when a Tier 3 (targeted human attacker) session is detected, Aegis
writes a GUN alert and logs a warning. A human operator then has to manually
investigate. This is the gap.

**Integration:**
- Deploy Velociraptor server alongside Aegis (single binary, ~80MB)
- Deploy Velociraptor agents on all homelab endpoints at setup time
- In `tier-router.ts`, the `case 3:` branch does two things concurrently:
  1. Current GUN alert (unchanged)
  2. New: POST to Velociraptor REST API to trigger a Hunt — a parallel forensic
     collection across all endpoints using pre-built VQL artifacts:
     - `Windows.System.Pslist` / `Linux.Sys.Pslist` — running processes
     - `Network.NetstatEnriched` — active connections
     - `Exchange.Windows.EventLogs.RDPAuth` — auth events
     - Custom artifact: "find any file modified in the last 5 minutes"
- By the time the human operator sees the alert, full forensic context is already
  collected — not a blank screen

**What Velociraptor does that nothing else does:**
VQL (Velociraptor Query Language) runs across thousands of endpoints
simultaneously. `SELECT * FROM pslist() WHERE Username='SYSTEM' AND Name NOT IN
('svchost.exe','csrss.exe')` returns anomalous SYSTEM processes across your
entire fleet in seconds. No other free tool does this.

**Replaces:** Manual post-alert investigation
**Effort:** 3–4 days — Velociraptor setup + REST API integration + artifact
library selection

---

### Cilium / Tetragon
**Source:** `github.com/cilium/tetragon`
**Affects:** `router/tier-router.ts` — enforcement layer

Currently Aegis *detects* and *marks* sessions for routing (via a Redis key the
proxy reads), but the actual block happens at proxy/nginx level. Malware that
bypasses the proxy still reaches the actual services.

**Integration:**
- Deploy Tetragon as a DaemonSet (Kubernetes) or standalone eBPF daemon
- Define a `TracingPolicy` for Aegis's process:
  - Any outbound connection from honeypot services to unexpected IPs → block + alert
  - Any process spawned by a honeypot service → block (prevents RCE escape)
  - File writes to `/etc` or `/root` from any honeypot service → block
- When Tier 1 is confirmed, Tetragon's `action: Sigkill` policy terminates the
  connection at kernel level — the tarpit proxy layer is then a second layer, not
  the only one
- Tetragon runs where malware cannot reach it — userspace agents can be killed;
  eBPF programs in the kernel cannot

**What this gives Aegis:**
Defence in depth. Current model: proxy blocks. With Tetragon: proxy blocks AND
kernel blocks. An attacker who bypasses nginx hits eBPF enforcement before
reaching any real service.

**Replaces:** nginx-only enforcement
**Effort:** 3–5 days — requires Kubernetes or at minimum a modern Linux kernel
(5.10+). TracingPolicy YAML for the Aegis service topology is the main work

---

### GCHQ / Gaffer
**Source:** `github.com/GCHQ/Gaffer`
**Affects:** `intel-export/gun-exporter.ts` — complete replacement

GUN.js is a P2P real-time sync layer. It works for the current use case (push
events to a Pi5 dashboard) but has no query capability, no relationship modelling,
and no time-windowed aggregation.

Gaffer is GCHQ's graph database — built to query relationship networks at
national surveillance scale. Sits on Accumulo, HBase, or in-memory for small
deployments.

**What Gaffer enables that GUN cannot:**
- "Show me all sessions that connected from IPs in the same /24 subnet as this
  known attacker" — a federated graph query
- "Show me how attacker behaviour changed over a 30-day window" — time-windowed
  aggregation built in
- "Find all packages in our SBOM that share a GitHub maintainer with a known
  malicious repo" — entity relationship queries across supply chain data
- IP → session → tool → technique → package: a causal attack graph queryable
  in real time

**Integration:**
- Run Gaffer in-memory mode (no Accumulo required for homelab scale)
- Replace `gun-exporter.ts` with `gaffer-exporter.ts` — same `exportEvent()`
  interface, different backend
- Add a `gaffer-query.ts` module for the MCP server to expose graph queries
  to the dashboard

**Replaces:** gun-exporter.ts
**Effort:** 1 week — Gaffer's Docker compose works out of the box; the main
work is designing the entity-relationship schema for Aegis events

---

### DARPA Transparent Computing / CamFlow
**Source:** `github.com/darpa-i2o/Transparent-Computing` → CamFlow implementation
**Affects:** New audit layer — OS-level provenance

Aegis currently tracks *network* session behavior. It does not know what happens
on the host when a honeypot service is accessed. CamFlow instruments the Linux
kernel to log every process spawn, file read/write, and network connection as a
tamper-evident provenance graph.

**Integration:**
- Install CamFlow kernel module on the Aegis host
- CamFlow outputs provenance events as CAMQL JSON streams
- Write `attribution/camflow-bridge.ts` — consumes the CamQL stream and maps
  provenance events back to active Aegis sessions by correlating timing + IP
- When an attacker triggers an RCE in a honeypot service, CamFlow captures the
  exact causal chain: `network packet → process spawn → file read → exfil attempt`
  with cryptographic hashes at every step
- Export the provenance graph to Gaffer (replacing GUN) — now you have a complete
  attack timeline that is forensically defensible

**What this gives Aegis:**
Every classified session gets an OS-level audit trail. Not just "an agent
enumerated this endpoint" but "that enumeration caused these exact system calls
on these files at these timestamps, signed with a kernel-level hash chain."

**Replaces:** Nothing currently — fills a complete blind spot
**Effort:** 1 week — CamFlow requires a kernel build (or their pre-built Ubuntu
packages). The bridge module is ~200 lines

---

## Priority 3 — Infrastructure & Operational Tooling

### IQT Labs / Vent
**Source:** `github.com/iqtlabs/vent`
**Affects:** Orchestration / Docker setup

Vent is a container orchestration platform built specifically for security tools —
point it at a network tap or PCAP file and it automatically routes traffic through
the right analysis containers. The Aegis deployment currently requires manually
wiring together nginx → classifier → honeypot → tarpit.

**Integration:**
- Use Vent as the pipeline orchestrator instead of manual Docker compose wiring
- Define Vent plugins for: tarpit container, honeypot container, classifier,
  supply-chain scanner
- Vent handles: container health, automatic restart, routing between containers
  based on output

**Effort:** 3–4 days — Vent's documentation is sparse but the concept is simple

---

### iovisor / bcc (BPF Compiler Collection)
**Source:** `github.com/iovisor/bcc`
**Affects:** Operations / performance monitoring

For production Aegis, these tools are essential:
- `opensnoop`: watch every `open()` syscall — see exactly what files the honeypot
  services are serving in real time
- `tcpretrans`: detect TCP retransmit storms from tarpit sessions
- `runqlat`: find CPU starvation if the classifier can't keep up under load
- `memleak`: detect memory leaks in long-running classifier/honeypot processes

**Integration:** Standalone ops toolkit — no code changes needed
**Effort:** `apt install bpfcc-tools` — zero

---

### Cilium / Cilium (full CNI)
**Source:** `github.com/cilium/cilium`
**Affects:** Kubernetes deployment networking

If Aegis moves to a Kubernetes deployment (natural next step for multi-node
homelab), Cilium replaces kube-proxy entirely with eBPF-based networking.
Hubble (bundled) gives a real-time Grafana dashboard of every network flow in
the cluster — including exactly which attacker IPs are hitting which Aegis pods.

**Effort:** Replace default CNI at cluster install time — no Aegis code changes

---

### MITRE / Caldera
**Source:** `github.com/mitre/caldera`
**Affects:** Testing / red team validation

Caldera is an autonomous red team — it simulates nation-state adversary behaviour
against your own infrastructure. For Aegis, this is the test harness.

**Integration:**
- Deploy Caldera in a lab environment pointing at Aegis
- Run the `discovery` adversary profile — automated reconnaissance that Aegis
  should catch at Tier 1
- Run the `APT29` profile — sophisticated multi-stage attack that should trigger
  Tier 2 (AI agent) or Tier 3 (targeted) classification
- If Caldera's reconnaissance is not caught, that is a gap in the classifier signals
- Caldera's `stockpile` plugin has 200+ ATT&CK-mapped techniques — each failed
  detection tells you exactly which technique your classifier is blind to

**Effort:** 1 day setup. Ongoing: run after every classifier change

---

### ASD / Constellation
**Source:** `github.com/constellation-app/constellation`
**Affects:** Visualization / analysis

ASD's internal data visualization tool — handles billions of nodes with GPU
acceleration and 3D force-directed graph rendering. Desktop app (JAR download).

**Integration:** No code integration. Use as the analysis companion for Gaffer's
graph data. Export Gaffer query results as CSV → import into Constellation to
visualize the attack relationship graph in 3D.

**Effort:** Zero — download JAR, open CSV

---

## What to Replace vs What to Keep

| Current Component | Action | Replace With |
|---|---|---|
| `gun-exporter.ts` | Replace | Gaffer graph database |
| UUID canary tokens | Replace | Google Tink MACs |
| Plaintext GUN payloads | Encrypt | Tink AEAD |
| Hand-rolled behavioral patterns | Enrich | ATT&CK STIX technique mapping |
| nginx-only enforcement | Layer | Tetragon eBPF enforcement underneath |
| Manual Tier 3 investigation | Automate | Velociraptor hunt trigger |
| No host provenance | Add | CamFlow OS-level audit trail |
| SBOM without geography | Add | gitgeo maintainer attribution |
| No ML model scanning | Add | fickling supply chain scanner |

---

## Build Order

```
Week 1:  ATT&CK STIX enrichment in behavioral.ts    (immediate signal quality gain)
         Google Tink for canary tokens               (quick, high value)
Week 2:  gitgeo integration in sbom-collector        (supply chain enrichment)
         fickling model scanner                      (closes supply chain blind spot)
Week 3:  Velociraptor deploy + Tier 3 hunt trigger   (closes operational gap)
Week 4:  Tetragon eBPF enforcement layer             (defence in depth)
Week 5:  Gaffer replace GUN                          (graph query capability)
Week 6:  CamFlow OS provenance bridge                (complete audit trail)
Ongoing: Caldera red team validation after each change
Tooling: bcc ops tools, Constellation visualization
```

---

## The Two that Could Replace Core Aegis Components Entirely

### If Velociraptor + Tetragon were in from day one:
The Tier 1 tarpit and Tier 2 honeypot would still exist (they're deception layers
that Velociraptor/Tetragon don't replace), but the *response* to a Tier 3
detection would be orders of magnitude more capable. The current Tier 3 path is
essentially "send an alert and wait for a human." With Velociraptor, by the time
the human opens the alert, 400 forensic data points are already collected.

### If Gaffer replaced GUN:
The intel-export layer transforms from a one-way event log into a queryable
threat graph. You could answer "has this IP been seen before, what did it do,
what tools did it use, what packages did it probe for" — in milliseconds — by
querying the graph rather than scanning log files. This fundamentally changes
what the dashboard can do.
