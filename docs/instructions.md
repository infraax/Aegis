# Aegis — Setup & Integration Instructions

This document is the step-by-step guide for deploying Aegis on the ThinkPad and
integrating it with the Tailscale tailnet (`tailcf4fee.ts.net`).

---

## 1. Prerequisites

| Requirement | Check |
|---|---|
| Ubuntu 22.04 / Debian 12 on ThinkPad | `uname -r` |
| Two network interfaces: `eth0` (management) + `eth1` (deception) | `ip link` |
| Docker + Docker Compose v2 | `docker compose version` |
| Node 20 + | `node -v` |
| Python 3.10 + | `python3 -V` |
| Tailscale installed | `tailscale --version` |

---

## 2. Tailscale Setup

### 2a. Install & Authenticate

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --accept-routes --advertise-exit-node=false
```

After `tailscale up`, copy the displayed IP — this is your `TAILSCALE_IP` (e.g. `100.126.159.28`).

### 2b. Confirm the Node Appears in the Admin Console

Visit https://login.tailscale.com/admin/machines and confirm:

- `thinkpad` is listed and **Connected**
- `pi5-orchestrator` (`100.69.201.84`) is listed

### 2c. Lock the Tailscale Interface (optional but recommended)

```bash
# Disable key expiry for this node (avoids re-auth every 90 days)
# Do this from the admin console: Machines → thinkpad → Disable key expiry
```

---

## 3. Environment Configuration

```bash
cd /home/user/Aegis
cp .env.example .env
nano .env
```

Fill in at minimum:

| Variable | How to get it |
|---|---|
| `DECEPTION_IP` | `ip addr show eth1 \| grep 'inet '` |
| `DECEPTION_IFACE` | Usually `eth1`; confirm with `ip link` |
| `TAILSCALE_IP` | `tailscale ip -4` |
| `CANARY_BASE_DOMAIN` | Register a cheap domain; point NS to your canary server |
| `WAZUH_API_PASSWORD` | Pick a strong password (min 8 chars, 1 uppercase, 1 digit) |
| `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api |

Leave all other vars at their defaults for a first deployment.

---

## 4. Firewall (ufw)

Run once on the ThinkPad host:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Tailscale full trust
sudo ufw allow in on tailscale0

# WireGuard (Tailscale uses port 41641 by default)
sudo ufw allow 41641/udp

# Deception interface — intentionally wide open (honeypot)
sudo ufw allow in on eth1

# Wazuh agent registration — Tailscale CGNAT range only
sudo ufw allow from 100.64.0.0/10 to any port 1514 proto tcp

# Explicitly block Wazuh reg from the deception interface
sudo ufw deny in on eth1 to any port 1514

sudo ufw enable
sudo ufw status verbose
```

---

## 5. Start Docker Services

```bash
cd /home/user/Aegis/docker
export DECEPTION_IP=$(ip -4 addr show eth1 | awk '/inet /{print $2}' | cut -d/ -f1)
docker compose up -d
docker compose ps   # all should show "Up"
```

### First-Run Portainer Password

Open http://127.0.0.1:9001 in a browser (or SSH tunnel from another tailnet device):

```bash
# From any tailnet device:
ssh thinkpad -L 9001:127.0.0.1:9001
# Then open http://127.0.0.1:9001
```

Set an admin password immediately on first visit.  
Portainer gives you a live view of every container, port binding, log stream, and resource usage.

---

## 6. nginx Reverse Proxy (Tailscale Access)

Create `/etc/nginx/sites-available/aegis`:

```nginx
# Wazuh Dashboard — https://100.126.159.28/
server {
    listen 100.126.159.28:443 ssl;
    server_name 100.126.159.28;

    ssl_certificate     /etc/ssl/aegis/aegis.crt;
    ssl_certificate_key /etc/ssl/aegis/aegis.key;

    location / {
        proxy_pass https://127.0.0.1:5601;
        proxy_ssl_verify off;
    }
}

# Velociraptor UI — https://100.126.159.28:8000
server {
    listen 100.126.159.28:8000 ssl;
    server_name 100.126.159.28;

    ssl_certificate     /etc/ssl/aegis/aegis.crt;
    ssl_certificate_key /etc/ssl/aegis/aegis.key;

    location / {
        proxy_pass https://127.0.0.1:8000;
        proxy_ssl_verify off;
    }
}

# Gaffer REST API — http://100.126.159.28:8082
server {
    listen 100.126.159.28:8082;
    server_name 100.126.159.28;
    location / { proxy_pass http://127.0.0.1:8082; }
}

# Portainer — http://100.126.159.28:9001
server {
    listen 100.126.159.28:9001;
    server_name 100.126.159.28;
    location / { proxy_pass http://127.0.0.1:9001; }
}
```

Generate a self-signed cert if you don't have one:

```bash
sudo mkdir -p /etc/ssl/aegis
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
  -keyout /etc/ssl/aegis/aegis.key \
  -out /etc/ssl/aegis/aegis.crt \
  -subj "/CN=100.126.159.28"
```

Enable and reload:

```bash
sudo ln -sf /etc/nginx/sites-available/aegis /etc/nginx/sites-enabled/aegis
sudo nginx -t && sudo systemctl reload nginx
```

---

## 7. Start the Classifier (Host Process)

```bash
cd /home/user/Aegis
npm run build
node dist/classifier/index.js &
# or with pm2:
pm2 start dist/classifier/index.js --name aegis-classifier
```

The classifier listens on `127.0.0.1:9000` (configurable via `CLASSIFIER_PORT`).

---

## 8. Wazuh Agent Registration (Pi5 / Other Tailnet Nodes)

On each node you want to monitor:

```bash
# Install the Wazuh agent (matching version 4.7.x)
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
sudo WAZUH_MANAGER='100.126.159.28' WAZUH_AGENT_NAME='pi5-orchestrator' dpkg -i wazuh-agent.deb
sudo systemctl enable --now wazuh-agent
```

The manager (`aegis-wazuh-manager`) listens on `0.0.0.0:1514` so Tailscale nodes can reach it.

---

## 9. Velociraptor API Key (First Run)

```bash
docker compose exec velociraptor \
  velociraptor --config /etc/velociraptor/config.yaml \
  config api_client --name aegis --role analyst,api \
  > /home/user/Aegis/velociraptor/api.config.yaml
```

> **Keep `api.config.yaml` out of git.** It is already in `.gitignore`.

---

## 10. Suricata Rule Updates

```bash
docker compose exec suricata suricata-update
docker compose restart suricata
```

Schedule weekly:

```bash
echo "0 3 * * 1 root docker compose -f /home/user/Aegis/docker/docker-compose.yml exec -T suricata suricata-update && docker compose -f /home/user/Aegis/docker/docker-compose.yml restart suricata" \
  | sudo tee /etc/cron.d/aegis-suricata-update
```

---

## 11. Verifying Everything Works

```bash
# All containers healthy
docker compose ps

# Classifier responding
curl -s http://127.0.0.1:9000/health

# Wazuh indexer healthy
curl -s http://127.0.0.1:9200/_cluster/health | jq .status

# Wazuh manager API
curl -sk https://127.0.0.1:55000/ | jq .title

# Gaffer graph
curl -s http://127.0.0.1:8082/rest/v2/graph/status | jq .

# Portainer UI reachable
curl -s http://127.0.0.1:9001/api/status | jq .Version
```

---

## 12. Adding a New Tailscale Device

1. Install Tailscale on the new device and run `tailscale up`.
2. Approve the device in the admin console (https://login.tailscale.com/admin/machines).
3. If the device needs to register a Wazuh agent, follow Step 8 above.
4. If the device needs access to management UIs, ensure nginx is proxying the relevant ports to `TAILSCALE_IP` (Step 6).
5. Update `docs/ports.md` → "All-Interface Ports" table if you add a new agent.

---

## 13. Port Reference

See `docs/ports.md` for the complete port registry.  
See `docker/docker-compose.yml` for actual container port bindings.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Container won't start — `bind: address already in use` | `ss -tlnp \| grep <port>` to find the owner; update `.env` or kill the conflict |
| Wazuh Dashboard shows no data | Check `aegis-wazuh-indexer` health: `docker compose logs wazuh-indexer` |
| Suricata not capturing traffic | Confirm `DECEPTION_IFACE` matches `ip link` output |
| Tailscale device unreachable | `tailscale ping <device>` to test; check admin console for expiry |
| Portainer shows no containers | Confirm `/var/run/docker.sock` exists and Docker is running |
