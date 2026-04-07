# Aegis Port Registry
## ThinkPad deployment — tailnet `tailcf4fee.ts.net` (100.126.159.28)

All ports are either:
- **DECEPTION** — bound to `$DECEPTION_IP` (eth1, the external/attacker-facing interface)
- **MGMT** — bound to `127.0.0.1` or Tailscale IP only; never exposed to attackers
- **TAILSCALE** — reachable from any tailnet device via `100.126.159.28:<port>`

---

## Deception Interface Ports (`$DECEPTION_IP` = eth1)
These are the honeypot services attackers see. All bind to `DECEPTION_IP` only.

| Port | Proto | Service | Container | Notes |
|------|-------|---------|-----------|-------|
| **22** | TCP | Fake SSH (Cowrie) | `aegis-fake-ssh` | Logs creds, shells, exfil attempts |
| **80** | TCP | Fake Web App | `aegis-fake-web` | HTTP → container :3000 |
| **443** | TCP | Fake Web App (TLS) | `aegis-fake-web` | HTTPS → container :3443 |
| **5432** | TCP | Fake PostgreSQL | `aegis-fake-db` | DB: `meridian_prod` / user: `admin` |
| **6379** | TCP | Fake Redis | `aegis-fake-redis` | No auth — intentional trap |
| **8080** | TCP | Fake Internal API | `aegis-fake-api` | REST API with canary endpoints |
| **8443** | TCP | Fake Admin Panel | `aegis-fake-admin` | Admin UI with canary credentials |

---

## Management Ports (`127.0.0.1` — localhost only)
These bind only to loopback. Access from other tailnet nodes: use `ssh -L` or nginx proxy.

| Port | Proto | Service | Container | Env Var Override |
|------|-------|---------|-----------|-----------------|
| **9000** | TCP | **Aegis Classifier** | host process | `CLASSIFIER_PORT` |
| **8889** | TCP | Velociraptor REST API | `aegis-velociraptor` | `VELOCIRAPTOR_URL` |
| **8000** | TCP | Velociraptor Web UI | `aegis-velociraptor` | — |
| **9200** | TCP | Wazuh Indexer (OpenSearch) | `aegis-wazuh-indexer` | — |
| **55000** | TCP | Wazuh Manager REST API | `aegis-wazuh-manager` | `WAZUH_API_URL` |
| **5601** | TCP | Wazuh Dashboard | `aegis-wazuh-dashboard` | — |
| **8082** | TCP | Gaffer Graph REST API | `aegis-gaffer` | `GAFFER_URL` |
| **514** | UDP | Wazuh Syslog Input | `aegis-wazuh-manager` | — |

---

## All-Interface Ports (`0.0.0.0`)
These are reachable from the Tailscale network for remote agent registration.

| Port | Proto | Service | Container | Who connects |
|------|-------|---------|-----------|-------------|
| **1514** | TCP | Wazuh Agent Registration | `aegis-wazuh-manager` | pi5-orchestrator, tuf-gaming |

---

## Tailscale-Accessible (via nginx reverse proxy on ThinkPad)
Set up nginx on ThinkPad to proxy these internal ports to the Tailscale IP.
Accessible from any tailnet device at `https://100.126.159.28`.

| Tailscale URL | Proxied To | Service |
|---|---|---|
| `https://100.126.159.28/` or `:443` | `127.0.0.1:5601` | Wazuh Dashboard |
| `https://100.126.159.28:8000` | `127.0.0.1:8000` | Velociraptor UI |
| `https://100.126.159.28:8082` | `127.0.0.1:8082` | Gaffer REST API |
| `http://100.126.159.28:9000` | `127.0.0.1:9000` | Aegis Classifier (health check) |

---

## Host-Level Ports (no Docker — kernel/daemon)
These run directly on the ThinkPad host OS.

| Port | Proto | Service | Process | Notes |
|------|-------|---------|---------|-------|
| **41641** | UDP | Tailscale WireGuard | `tailscaled` | Tailscale default; may vary |
| `/var/run/tetragon/tetragon.sock` | Unix | Tetragon eBPF events | `tetragon` | Stage 4 bridge reads this |
| `/run/camflowd.sock` | Unix | CamFlow provenance | `camflowd` | Stage 6 bridge reads this |
| `/var/ossec/queue/sockets/` | Unix | Wazuh agent IPC | `wazuh-agentd` | Internal agent comms |

---

## Network Capture (no port binding — passive tap)
These services capture traffic without binding a port.

| Service | Container | Interface | What it captures |
|---------|-----------|-----------|-----------------|
| Suricata | `aegis-suricata` | `$DECEPTION_IFACE` (eth1) | All traffic; JA3/JA4 → EVE JSON |
| Zeek | `aegis-zeek` | `$DECEPTION_IFACE` (eth1) | All traffic; SSL logs, conn logs |
| `scripts/arp_monitor.py` | host process | `$DECEPTION_IFACE` | ARP packets only |
| `scripts/dns_monitor.py` | host process | `$DECEPTION_IFACE` | DNS (port 53 UDP/TCP) |

---

## GUN Relay (Pi5 — remote)

| Host | Port | Proto | Service | Env Var |
|------|------|-------|---------|---------|
| `pi5-orchestrator` (`100.69.201.84`) | **8765** | WS | GUN relay | `GUN_RELAY_URL=ws://100.69.201.84:8765/gun` |

---

## Conflict Check

```
Port  22    → deception only (eth1)      ✓ no conflict with host SSH
Port  80    → deception only (eth1)      ✓
Port  443   → deception only (eth1)      ✓
Port  514   → 127.0.0.1 only             ✓
Port  1514  → 0.0.0.0 (Tailscale nodes) — ensure firewall allows 100.64.0.0/10 only
Port  5432  → deception only (eth1)      ✓
Port  5601  → 127.0.0.1 only             ✓
Port  6379  → deception only (eth1)      ✓
Port  8000  → 127.0.0.1 only             ✓
Port  8080  → deception only (eth1)      ✓
Port  8082  → 127.0.0.1 only             ✓
Port  8443  → deception only (eth1)      ✓
Port  8889  → 127.0.0.1 only             ✓
Port  9000  → 127.0.0.1 only             ✓
Port  9200  → 127.0.0.1 only             ✓
Port  55000 → 127.0.0.1 only             ✓
```

**No port conflicts.** `8080` on deception IF and `8082` for Gaffer on localhost are
different bindings — no clash.

---

## Recommended firewall rules (ufw)

```bash
# Block all by default
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow Tailscale
sudo ufw allow in on tailscale0

# Allow WireGuard for Tailscale
sudo ufw allow 41641/udp

# Deception interface — allow everything inbound (that's the point)
sudo ufw allow in on eth1

# Wazuh agent registration — Tailscale CGNAT range only
sudo ufw allow from 100.64.0.0/10 to any port 1514 proto tcp

# Block Wazuh agent port from the deception interface explicitly
sudo ufw deny in on eth1 to any port 1514
```
