# Aegis Integration Build Plan
## Session-limit-proof, staged, non-destructive

---

## How Integration Works — The Four Patterns

Before anything: we never clone a repo and copy its internals into Aegis.
That means you own the maintenance burden forever. Instead, every integration
uses one of four clean patterns depending on what the tool is:

---

### Pattern A — npm package
Tool ships a JavaScript/TypeScript package. You add it to `package.json`.
Your code calls it like any other import. Zero cloning, zero copying.

```
npm install tink-crypto            ← installed, versioned, upgradeable
import { Aead } from 'tink-crypto'  ← call it directly
```

Used for: **Google Tink**

---

### Pattern B — Data bundle at startup
Tool is a static dataset (JSON/STIX/YAML). You fetch it once at boot or embed
a snapshot. Your code reads the data structure — you never run the tool's code.

```typescript
// At startup: fetch the STIX bundle (or use the cached version in /opt/aegis/data/)
const stix = JSON.parse(fs.readFileSync('/opt/aegis/data/enterprise-attack.json'))
// Your classifier then queries this object — no MITRE code runs in your process
```

Used for: **ATT&CK STIX data** (the data, not the Python library)

---

### Pattern C — Subprocess bridge
Tool is a Python/Go/binary CLI that does one job well. You call it from
TypeScript via `child_process.spawn`, capture stdout JSON, and return a typed
result. The tool's internals stay completely separate — you only own the 20-line
bridge function.

```typescript
// supply-chain/fickling-bridge.ts
import { spawn } from 'child_process'

export async function scanPickle(filePath: string): Promise<{ safe: boolean; report: string }> {
  return new Promise((resolve, reject) => {
    const proc = spawn('python3', ['-m', 'fickling', '--check-safety', '--json', filePath])
    let stdout = ''
    proc.stdout.on('data', d => stdout += d)
    proc.on('close', code => resolve({ safe: code === 0, report: stdout }))
    proc.on('error', reject)
  })
}
```

Used for: **fickling**, **gitgeo**

---

### Pattern D — Docker sidecar + REST API
Tool runs as a separate container. You add it to `docker-compose.yml`.
Your TypeScript calls its HTTP/REST API with axios. The tool's codebase never
touches yours.

```yaml
# docker-compose.yml addition
velociraptor-api:
  image: velocidex/velociraptor:latest
  container_name: aegis-velociraptor
  ...
```
```typescript
// Your code — 15 lines of axios
await axios.post('http://velociraptor:8889/api/v1/Hunt', { artifacts: [...] })
```

Used for: **Velociraptor**, **Gaffer**

---

### Pattern E — System daemon (eBPF / kernel)
Tool runs as a privileged daemon outside Docker entirely — it operates at
kernel level. You interact with it only through its event stream (a socket or
log file) or its REST API. Your application code is completely isolated from it.

```bash
# Installed once on the host
systemctl enable tetragon
systemctl start tetragon
# Events arrive as JSON on /var/run/tetragon/tetragon.sock
```
```typescript
// aegis reads the event stream, that's the only connection
const sock = net.createConnection('/var/run/tetragon/tetragon.sock')
```

Used for: **Tetragon**, **CamFlow**

---
---

## The Staged Build Plan

Each stage is self-contained. You can stop after any stage and Aegis is better
than it was. Nothing breaks if you skip a stage. Each stage is sized to fit
within one session.

---

## Stage 1 — Signal Enrichment
**Pattern B + Pattern A**
**Touches:** `classifier/signals/behavioral.ts`, `honeypot/adaptive-engine.ts`
**Does NOT touch:** router, tarpit, docker-compose, supply-chain, gun-exporter
**Session budget:** 1 session

### 1A — ATT&CK STIX technique mapping

**What we're doing:**
Right now `behavioral.ts` returns a generic `confidence` score. We're going to
add a `techniqueIds` field — so every classification comes out with structured
ATT&CK IDs attached (e.g. `["T1595.001", "T1046"]`).

**How:**
1. Download `enterprise-attack.json` from `github.com/mitre-attack/attack-stix-data`
   — it's one file, ~20MB. Store at `/opt/aegis/data/enterprise-attack.json`
2. Write `classifier/signals/attack-db.ts` — loads the file once at startup,
   builds an in-memory map of `{ patternKeyword → technique_id[] }`
3. Modify `behavioral.ts` to call `lookupTechniques(observedPaths)` — adds
   `techniqueIds` to the `BehavioralSignal` type
4. Modify `scorer.ts` `Classification` type to include `techniqueIds: string[]`
5. Modify `gun-exporter.ts` call sites to include techniqueIds in exported events

**What you get:**
Every alert in your dashboard now says "T1190 (Exploit Public-Facing Application),
T1046 (Network Service Scanning)" instead of just "confidence: 0.82". Your intel
graph becomes ATT&CK-structured from day one.

**No rewrites.** behavioral.ts gains one import and one field. Everything else
is additive.

---

### 1B — Google Tink canary tokens

**What we're doing:**
`issueCanaryToken()` in `honeypot/adaptive-engine.ts` currently returns a raw
UUID hex string. Replacing with a Tink MAC — a short, signed, unforgeable token
that Aegis can verify on callback without a database lookup.

**How:**
```bash
npm install tink-crypto
```
1. Write `honeypot/canary-crypto.ts` — initializes a Tink MAC keyset from
   `CANARY_HMAC_KEY` env var, exports `sign(payload)` and `verify(token)`
2. Replace the UUID call in `issueCanaryToken()` — one line change
3. Add `verifyCanary(token)` to the fake-web service callback endpoint — when
   an attacker uses a canary URL, we now *prove* which session it came from
   without trusting the attacker's input

**What you get:**
Canary tokens that prove exactly which session planted them. No more "something
hit our canary" — now it's "session abc123, Tier 2, identified as AutoGPT,
used canary token from depth-2 engagement at 14:32:07."

---

## Stage 2 — Supply Chain Hardening
**Pattern C (subprocess bridge)**
**Touches:** `supply-chain/` — new modules only
**Does NOT touch:** classifier, router, honeypot, docker-compose, gun-exporter
**Session budget:** 1 session

### 2A — fickling: ML model supply chain scanner

**What we're doing:**
Adding `supply-chain/model-scanner.ts`. When the SBOM collector finds `.pt`,
`.pkl`, `.pth`, or `.safetensors` files on any node, this module scans them for
malicious pickle bytecode before they're ever loaded.

**How:**
```bash
pip3 install fickling  # on the Aegis host, one-time
```
1. Write `supply-chain/model-scanner.ts` using Pattern C above
2. Add a call from the SBOM scheduler: after `upsertPackages()`, scan any
   newly discovered model files
3. On malicious result: call `assessExposure()` with `isSupplyChainAttack: true`
   — same critical path already in correlator.ts, nothing new to wire

**No rewrites.** Two new files, one new call site in the scheduler.

---

### 2B — gitgeo: maintainer geography enrichment

**What we're doing:**
Adding `supply-chain/geo-enricher.ts`. For packages where we know the GitHub
source repo (npm and pip both publish this), we check the geographic distribution
of recent committers. A package where 85% of commits come from a single country
in the past 6 months is flagged.

**How:**
```bash
pip3 install gitgeo  # on the Aegis host, one-time
```
1. Write `supply-chain/geo-enricher.ts` — subprocess bridge to gitgeo
2. Add a `maintainerGeo` column to the `packages` SQLite table in sbom-collector
3. Run enrichment async after each SBOM collection (non-blocking)
4. If concentration score > threshold: emit a supply chain event via exportEvent()

**No rewrites.** Additive column, additive module, additive call.

---

## Stage 3 — Automated Forensic Response
**Pattern D (Docker sidecar)**
**Touches:** `router/tier-router.ts` — the Tier 3 `case 3:` branch only
**Does NOT touch:** classifier, honeypot, supply-chain, tarpit
**Session budget:** 1 session

### 3A — Velociraptor: Tier 3 auto-hunt

**What we're doing:**
When Tier 3 fires today, the code logs a warning and exports a GUN alert. That's
the entire response. We're adding: the moment Tier 3 triggers, a Velociraptor
Hunt kicks off automatically — collecting process lists, network connections,
recent file changes, and auth events from every endpoint before a human even
opens the alert.

**How:**
1. Add to `docker-compose.yml`:
```yaml
velociraptor:
  image: velocidex/velociraptor:latest
  container_name: aegis-velociraptor
  volumes:
    - velociraptor-data:/opt/velociraptor
    - ./velociraptor/config.yaml:/etc/velociraptor/config.yaml:ro
  ports:
    - "127.0.0.1:8889:8889"   # API — management interface only, not deception IP
  networks:
    - deception-net
  restart: unless-stopped
```
2. Write `router/velociraptor-client.ts` — ~40 lines of axios wrapping
   the Velociraptor REST API:
   - `triggerHunt(sourceIP: string, sessionId: string)` — fires the pre-built
     artifact collection: pslist, netstat, recent file mods, auth logs
   - Returns a `huntId` for linking back to the alert
3. In `tier-router.ts` case 3: add two awaits (current GUN alert stays unchanged):
```typescript
case 3:
  await markDestination(sessionId, 'escalate')
  await exportEvent('homelab/alerts/security/tier3-' + sessionId, { ...base, alert: '...' })
  const hunt = await triggerHunt(ip, sessionId)          // ← new line
  await exportEvent('homelab/alerts/security/tier3-' + sessionId + '/hunt', hunt)  // ← new line
  break
```

**What you get:**
Tier 3 alert fires → 30 seconds later, forensic data from every endpoint is
in Velociraptor → the alert in your dashboard links directly to the Hunt results.
The investigation is already done by the time you look at it.

**No rewrites.** Two new lines in one switch case. Everything else unchanged.

---

## Stage 4 — Enforcement Layer
**Pattern E (system daemon)**
**Touches:** Nothing in Aegis code — this is purely infrastructure
**Session budget:** 1 session

### 4A — Tetragon: kernel-level enforcement under nginx

**What we're doing:**
Installing Tetragon as an eBPF daemon on the Aegis host. Defining TracingPolicy
files that enforce what honeypot containers are allowed to do at kernel level.
No Aegis code changes at all — this is a separate protection layer underneath.

**How:**
1. Install on the host (Ubuntu 22.04+):
```bash
curl -L https://github.com/cilium/tetragon/releases/latest/download/tetragon-linux-amd64.tar.gz | tar -xz
sudo install tetragon /usr/local/bin/tetragon
```
2. Write `tetragon/policies/honeypot-lockdown.yaml`:
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: honeypot-lockdown
spec:
  kprobes:
  - call: "sys_connect"
    syscall: true
    args:
    - index: 0
      type: int
    matchArgs:
    - index: 0
      operator: "NotIn"
      values: ["allowed-cidrs"]
    action: Sigkill    # ← kills any outbound connection honeypot didn't plan
  - call: "sys_execve"
    syscall: true
    matchBinaries:
    - operator: "In"
      values: ["/opt/aegis/honeypot/"]
    action: Post       # ← alert on any exec from honeypot path
```
3. Write `tetragon/policies/exfil-alert.yaml` — alert on any write to
   `/etc`, `/root`, or `/home` from a honeypot process
4. Add event stream reader in `attribution/tetragon-events.ts` (Pattern E) —
   reads Tetragon's JSON event stream and exports alerts via exportEvent()

**What you get:**
An attacker who achieves RCE in a honeypot container and tries to connect out,
pivot, or write persistence — gets killed at kernel level. nginx not involved.
Docker not involved. The block happens before any userspace code runs.

---

## Stage 5 — Intelligence Graph
**Pattern D (Docker sidecar)**
**Touches:** `intel-export/` — replace gun-exporter.ts with gaffer-exporter.ts
**Does NOT touch:** classifier, honeypot, supply-chain, router, tarpit
**Session budget:** 1-2 sessions

### 5A — Gaffer: replace GUN with a queryable graph

**What we're doing:**
The `exportEvent()` function signature doesn't change. The backend changes
from GUN.js (one-way P2P push, no query capability) to Gaffer (graph database
with full relationship queries). Every existing call to `exportEvent()` works
as before — they just write to Gaffer instead.

**How:**
1. Add to `docker-compose.yml`:
```yaml
gaffer:
  image: gchq/gaffer:2.1.0
  container_name: aegis-gaffer
  ports:
    - "127.0.0.1:8080:8080"   # REST API — internal only
  networks:
    - deception-net
  volumes:
    - gaffer-data:/gaffer/data
    - ./gaffer/schema:/gaffer/config/schema:ro
  restart: unless-stopped
```
2. Write `gaffer/schema/` — defines the entity types:
   - `Session` entity: sessionId, ip, tier, confidence, techniqueIds
   - `IPAddress` entity: ip, firstSeen, lastSeen, country
   - `Tool` entity: name, version
   - Edges: `Session→IPAddress`, `Session→Tool`, `Session→Technique`
3. Write `intel-export/gaffer-exporter.ts` — same `exportEvent()` signature,
   translates event payloads into Gaffer REST API calls
4. Keep `gun-exporter.ts` untouched as a fallback — switch via env var:
   `INTEL_BACKEND=gaffer` or `INTEL_BACKEND=gun`

**What you get after this stage:**
- "Has this IP ever attacked us before?" → Gaffer query, <10ms
- "What tools has this IP used across sessions?" → graph traversal
- "Show me all IPs that used the same T1190 technique in the past 30 days" → edge query
- "Which supply chain packages were probed during Tier 3 sessions?" → cross-entity join

GUN stays in as fallback. You cut over by changing one env var.

---

## Stage 6 — OS Provenance Audit Trail
**Pattern E (kernel module)**
**Touches:** `attribution/` — new module
**Does NOT touch:** anything existing
**Session budget:** 1 session (bridge code) + host setup time

### 6A — CamFlow: kernel-level attack causal chain

**What we're doing:**
Installing CamFlow on the Aegis host. CamFlow instruments the kernel to output
every process spawn, file access, and network connection as a tamper-evident
provenance graph. We write a bridge that reads this stream and correlates events
back to active Aegis sessions.

**How:**
```bash
# Ubuntu pre-built package (no kernel compile needed)
sudo add-apt-repository ppa:camflow/camflow
sudo apt install camconfd camflowd
sudo systemctl enable camconfd camflowd
```
1. Write `attribution/camflow-bridge.ts` (Pattern E):
   - Connect to CamFlow's MQTT output or read from its log socket
   - Maintain a `Map<ip, sessionId>` from active Aegis sessions
   - Correlate CamFlow events by timing + source IP to session IDs
   - Export correlated provenance chains via `exportEvent()` to Gaffer
2. The Gaffer schema (Stage 5) gains `ProvenanceEvent` entities and
   `Session→ProvenanceEvent` edges

**What you get:**
When Tier 2 honeypot engagement happens, CamFlow captures the full causal
chain: `TCP connect (session:abc123) → process spawn (bash) → file open
(/etc/shadow) → connect out (10.0.0.5:4444)`. Each step cryptographically
linked. The Gaffer graph for that session now has the complete kill chain
with OS-level evidence.

---

## Complete Dependency Graph

```
Stage 1A (ATT&CK STIX)       ← no deps, standalone
Stage 1B (Tink canary)        ← no deps, standalone

Stage 2A (fickling)           ← no deps, standalone
Stage 2B (gitgeo)             ← no deps, standalone

Stage 3  (Velociraptor)       ← no deps (but Stage 1A makes its alerts richer)

Stage 4  (Tetragon)           ← no deps, purely infra

Stage 5  (Gaffer)             ← benefits from Stage 1A (richer entities)
                                 benefits from Stage 3  (hunt IDs in graph)

Stage 6  (CamFlow)            ← requires Stage 5  (needs Gaffer for provenance storage)
```

Stages 1A, 1B, 2A, 2B, 3, 4 are completely independent.
Stage 5 is independent but produces more value if 1A and 3 are already done.
Stage 6 depends on Stage 5.

---

## Integration Pattern Summary

| Tool | Pattern | Clone repo? | Copy code? | Owns maintenance? |
|---|---|---|---|---|
| ATT&CK STIX | B (data bundle) | No | No — read JSON | MITRE updates it |
| Google Tink | A (npm) | No | No — import | npm upgrade |
| fickling | C (subprocess) | No | No — pip install | pip upgrade |
| gitgeo | C (subprocess) | No | No — pip install | pip upgrade |
| Velociraptor | D (Docker sidecar) | No | No — Docker pull | image tag pin |
| Tetragon | E (system daemon) | No | No — apt/binary | apt upgrade |
| Gaffer | D (Docker sidecar) | No | No — Docker pull | image tag pin |
| CamFlow | E (kernel module) | No | No — apt install | apt upgrade |

**None of these clone a repo and copy code into Aegis.**
Every tool stays in its own process, its own container, its own namespace.
Aegis owns only the bridge layer — 20–50 lines per integration — which you
fully control and can swap out if a better tool appears.

---

## What Each Session Looks Like

Every stage is designed to be completable in one session without getting cut off.

| Session | Deliverable | Risk to existing code |
|---|---|---|
| S1 | ATT&CK STIX + Tink canary tokens | Zero — additive only |
| S2 | fickling + gitgeo supply chain | Zero — new modules only |
| S3 | Velociraptor + Tier 3 hunt trigger | Minimal — 2 lines in tier-router |
| S4 | Tetragon TracingPolicy + event bridge | Zero — infra only |
| S5 | Gaffer schema + exporter (GUN stays as fallback) | Zero — env var switchover |
| S6 | CamFlow bridge + Gaffer provenance schema | Additive to Stage 5 |

The rule: **each stage merges as a clean PR, all tests pass, the system runs
without the new stage's external dependency if that dependency is offline.**
Graceful degradation is built into every bridge with try/catch and the
existing `logger.warn('export failed')` pattern already in gun-exporter.ts.
