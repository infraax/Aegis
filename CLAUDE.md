# CLAUDE.md — Aegis Project Context

This file is read automatically at the start of every Claude Code session.
It tells you everything you need to know to work on this project without
requiring context from previous sessions.

---

## What Aegis Is

**Aegis** is an Adaptive Cyber Intelligence & Deception System — a self-hosted
threat detection, classification, and response platform deployed on a ThinkPad
laptop on a private Tailscale network.

It presents a realistic fake infrastructure to attackers (SSH, web, Postgres,
Redis, admin panel), classifies sessions into three tiers, and responds
automatically:

- **Tier 1 (scanner):** Route to tarpit (endlessh)
- **Tier 2 (AI agent / tool):** Route to adaptive honeypot, issue canary tokens
- **Tier 3 (targeted human):** Escalate, trigger Velociraptor forensic hunt

---

## Deployment Target

```
Machine:    ThinkPad (Linux)
Tailnet:    tailcf4fee.ts.net
Tailscale:  100.126.159.28   ← this is the ThinkPad

Other nodes on the tailnet:
  pi5-orchestrator  100.69.201.84  Linux  ← GUN relay (ws://100.69.201.84:8765/gun)
  tuf-gaming        100.84.23.76   Linux  ← secondary node, can run Wazuh agent
  macbook-pro       100.77.147.119 macOS  ← owner's primary dev machine
```

**Deception interface:** `eth1` (external, attacker-facing)
**Management interface:** Tailscale (`tailscale0` / `100.126.159.28`)

All honeypot services bind to `$DECEPTION_IP` (eth1).
All management services bind to `127.0.0.1` (accessible via Tailscale through nginx proxy).

---

## Repository Structure

```
/classifier/          — Session classifier (Express :9000)
  /signals/           — Individual signal modules (timing, headers, TLS, behavioral, LLM, JA3, AI agent)
  scorer.ts           — Weighted signal aggregation → tier + confidence
  index.ts            — HTTP server, session state, all bridge startups

/router/              — Tier routing logic + Velociraptor client
/honeypot/            — Adaptive engine, canary crypto, prompt injection traps
/supply-chain/        — fickling model scanner, gitgeo geo enricher, SBOM collector
/attribution/         — All bridge modules (suricata-tail, arp-monitor, tetragon-events,
                        camflow-bridge, wazuh-bridge, dns-monitor, process-net-monitor)
/intel-export/        — GUN exporter, Gaffer exporter, index router (INTEL_BACKEND env var)
/tarpit/              — Tier 1 slow-response tarpit
/shared/              — Logger, test-utils
/scripts/             — Python daemons (arp_monitor.py, dns_monitor.py,
                        process_net_monitor.py, gitgeo_scan.py)
/docker/              — docker-compose.yml + service configs (suricata, zeek, velociraptor)
/wazuh/               — Wazuh config (ossec.conf, custom rules)
/tetragon/            — Tetragon TracingPolicy YAMLs
/gaffer/              — Gaffer graph schema (elements.json, types.json)
/systemd/             — systemd units for host-level daemons
/docs/                — ports.md (port registry), architecture docs
/research/            — Build plan (10-build-plan.md), architecture research (11-architecture-research.md)
/__tests__/           — vitest test files (15 test files, 199 tests)
```

---

## Tech Stack

- **Runtime:** Node.js + TypeScript (`"module": "commonjs"` in tsconfig — use `__dirname`, not `import.meta.url`)
- **Tests:** vitest (`npm test`), coverage with `@vitest/coverage-v8`
- **Typecheck:** `npm run typecheck` (tsc --noEmit)
- **Python daemons:** scapy, psutil, gitgeo, fickling (subprocess bridges)
- **Docker services:** Suricata, Zeek, Velociraptor, Wazuh, Gaffer, Portainer

---

## Development Rules

### Before touching any code
1. Run `npm run typecheck` — must be clean before and after your changes
2. Run `npm test` — must be 199/199 (or more) passing
3. Read the file before editing it — never modify code you haven't read

### Key patterns — follow these exactly

**Graceful degradation:** Every bridge catches all errors, logs a warning, and
returns/skips gracefully. The main pipeline never throws because an optional
service is offline.

```typescript
// CORRECT — every bridge looks like this
export function startXxxBridge(): void {
  if (process.env.XXX_DISABLE === '1') { logger.debug('...disabled'); return; }
  if (_proc || _stopped) return;  // idempotent
  startProcess();
}
```

**Test isolation:** Every stateful module exports `_resetForTest()`. Tests call
`silenceLogger()` / `restoreLogger()` in `beforeEach` / `afterEach`.

**CommonJS project:** Use `__dirname`, not `import.meta.url`. Use `require()` style
paths where needed. `import` statements are fine — it's TS compiled to CJS.

**No top-level await:** The tsconfig targets CommonJS. Use IIFE or lazy init.

**Comments in code:** Only where logic isn't self-evident. Don't add docstrings
or type annotations to code you didn't change.

### Commit discipline
- One commit per logical stage
- Always `npm run typecheck && npm test` before committing
- Never commit `.env`, `tskey-*`, `*.key`, `*.pem` files
- Push to branch `claude/setup-local-environment-RtJlN`

---

## Environment Variables

Copy `.env.example` to `.env` before deploying. **Never commit `.env`.**

```bash
# Required
WAZUH_API_PASSWORD=<choose-strong-password>

# Tailscale-aware defaults (these are correct for ThinkPad deployment)
GUN_RELAY_URL=ws://100.69.201.84:8765/gun
DECEPTION_IP=<eth1-ip-of-thinkpad>
DECEPTION_IFACE=eth1
TAILSCALE_IP=100.126.159.28

# Optional — switch Gaffer on
INTEL_BACKEND=gaffer           # default: gun
GAFFER_URL=http://127.0.0.1:8082
VELOCIRAPTOR_URL=http://127.0.0.1:8889
VELOCIRAPTOR_API_KEY=<from-velociraptor-config>
WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_API_USER=wazuh-wui

# Classifier
CLASSIFIER_PORT=9000           # default: 9000

# Disable bridges in dev (set to "1" to silence the noisy startup warnings)
TETRAGON_EVENTS_DISABLE=1
CAMFLOW_DISABLE=1
DNS_MONITOR_DISABLE=1
PROCESS_NET_DISABLE=1
WAZUH_DISABLE=1
```

---

## Port Map (quick reference)

Full registry: `docs/ports.md`

| Port | Binding | Service |
|------|---------|---------|
| 22 | eth1 | Cowrie SSH honeypot |
| 80/443 | eth1 | Fake web app |
| 5432 | eth1 | Fake PostgreSQL |
| 6379 | eth1 | Fake Redis |
| 8080 | eth1 | Fake internal API |
| 8443 | eth1 | Fake admin panel |
| 9000 | 127.0.0.1 | Aegis classifier |
| 8889 | 127.0.0.1 | Velociraptor REST |
| 8000 | 127.0.0.1 | Velociraptor UI |
| 9200 | 127.0.0.1 | Wazuh indexer |
| 55000 | 127.0.0.1 | Wazuh manager API |
| 5601 | 127.0.0.1 | Wazuh dashboard |
| 8082 | 127.0.0.1 | Gaffer graph API |
| 9001 | 127.0.0.1 | Portainer UI |
| 1514 | 0.0.0.0 | Wazuh agent reg (Tailscale only) |

---

## What Has Already Been Built (Stages 1–10)

Do NOT re-implement these. They exist and are tested.

| Stage | What | Key files |
|-------|------|-----------|
| 1A | MITRE ATT&CK STIX signal | `classifier/signals/attack-db.ts` |
| 1B | HMAC-SHA256 canary tokens | `honeypot/canary-crypto.ts` |
| 2A | fickling ML model scanner | `supply-chain/model-scanner.ts` |
| 2B | gitgeo geo enricher | `supply-chain/geo-enricher.ts` |
| 3 | Velociraptor Tier 3 auto-hunt | `router/velociraptor-client.ts` |
| 3.5 | JA3/JA4 TLS fingerprinting | `classifier/signals/ja3-signal.ts`, `attribution/suricata-tail.ts` |
| 3.6 | ARP integrity monitor | `scripts/arp_monitor.py`, `attribution/arp-monitor.ts` |
| 4 | Tetragon eBPF enforcement | `tetragon/policies/`, `attribution/tetragon-events.ts` |
| 5 | Gaffer intelligence graph | `intel-export/gaffer-exporter.ts`, `gaffer/schema/` |
| 6 | CamFlow OS provenance | `attribution/camflow-bridge.ts` |
| 7 | Wazuh HIDS full stack | `wazuh/`, `attribution/wazuh-bridge.ts` |
| 8 | DNS anomaly detector | `scripts/dns_monitor.py`, `attribution/dns-monitor.ts` |
| 9 | Process-to-network monitor | `scripts/process_net_monitor.py`, `attribution/process-net-monitor.ts` |
| 10 | AI agent behavioral detector | `classifier/signals/ai-agent-detector.ts`, `honeypot/prompt-injection-traps.ts` |

---

## What Is NOT Yet Built

If you need to add something new, these are the known gaps from the research:

- **Module 4: USB/ADS scanner** — USBGuard + NTFS ADS detection (T1091, T1564.004)
- **Module 8: YARA scanner** — yara-python memory + file scan (T1055, T1027)
- **Module 10: Volatility 3** — memory forensics on demand (T1014)
- **Module 11: CHIPSEC** — UEFI/firmware integrity (T1542)
- **RITA beacon scoring** — Zeek logs → beacon interval analysis (complement to Stage 3.5)

Full research doc: `research/11-architecture-research.md`
Full build plan: `research/10-build-plan.md`

---

## Running the Stack

```bash
# First time setup
cp .env.example .env   # fill in WAZUH_API_PASSWORD and DECEPTION_IP

# Start all Docker services
docker compose -f docker/docker-compose.yml up -d

# Start host-level daemons (after Tetragon + CamFlow installed)
sudo systemctl start aegis-arp-monitor aegis-wazuh-agent

# Start classifier (development)
npm run dev

# Or production (compiled)
npm run build
node dist/classifier/index.js

# View port usage at any time
ss -tlnp
docker ps --format "table {{.Names}}\t{{.Ports}}"

# Portainer UI (after docker compose up)
# http://127.0.0.1:9001  or  http://100.126.159.28:9001
```

---

## Testing

```bash
npm test               # run all 199 tests
npm run typecheck      # tsc --noEmit (must be clean)
npm run test:coverage  # coverage report
```

Test fixtures are in `__tests__/fixtures/`. Every new bridge module needs:
1. A lifecycle test (DISABLE env var, idempotent start, safe stop)
2. A parser/mapper unit test (parse the raw JSON → typed struct)
3. An integration test if it touches the scorer or exporter

---

## Security Notes

- **No credentials in code.** All secrets via `.env` (gitignored).
- The `tskey-*` Tailscale keys provided in a previous session are in the
  conversation history. **Rotate them** if the conversation is shared.
- Port 1514 (Wazuh agent) is open on `0.0.0.0` — firewall it to
  `100.64.0.0/10` (Tailscale CGNAT) immediately on deployment.
- Portainer binds to `127.0.0.1:9001` — never expose directly on eth1.
