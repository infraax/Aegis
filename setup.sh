#!/usr/bin/env bash
# =============================================================================
# Aegis — Local Machine Setup Script
# Kali Linux / Debian-based systems
#
# Usage:
#   sudo ./setup.sh
#
# What this does:
#   1. Installs system dependencies (Node 20, Docker, tools)
#   2. Creates the aegis system user and directories
#   3. Installs npm dependencies and builds TypeScript
#   4. Installs and enables systemd service units
#   5. Applies UFW network isolation rules
#   6. Creates the Docker deception network namespace
# =============================================================================

set -euo pipefail

AEGIS_DIR="/opt/aegis"
AEGIS_USER="aegis"
LOG_DIR="/var/log/aegis"
DATA_DIR="/opt/aegis/data"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[aegis]${NC} $*"; }
warn()    { echo -e "${YELLOW}[aegis]${NC} $*"; }
error()   { echo -e "${RED}[aegis]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo ./setup.sh"

# ── 1. System packages ─────────────────────────────────────────────────────
info "Updating package lists..."
apt-get update -qq

info "Installing system dependencies..."
apt-get install -y --no-install-recommends \
  wireguard wireguard-tools \
  docker.io docker-compose-plugin \
  curl git jq \
  python3 python3-pip python3-venv \
  nmap masscan \
  tcpdump tshark \
  fail2ban \
  ufw \
  postgresql-client \
  redis-tools \
  sqlite3

# Node.js 20
if ! command -v node &>/dev/null || [[ "$(node --version | cut -d. -f1 | tr -d v)" -lt 20 ]]; then
  info "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi
info "Node $(node --version) / npm $(npm --version)"

# ── 2. System user & directories ───────────────────────────────────────────
info "Creating aegis system user..."
id -u "$AEGIS_USER" &>/dev/null || useradd -r -s /usr/sbin/nologin -d "$AEGIS_DIR" "$AEGIS_USER"
usermod -aG docker "$AEGIS_USER"

info "Creating directories..."
mkdir -p "$AEGIS_DIR" "$LOG_DIR" "$DATA_DIR" \
  "$AEGIS_DIR/geoip" \
  "$AEGIS_DIR/honeypot/cowrie-config" \
  "$AEGIS_DIR/honeypot/filesystem" \
  "$AEGIS_DIR/honeypot/credentials" \
  "$AEGIS_DIR/honeypot/context-bombs"

chown -R "$AEGIS_USER:$AEGIS_USER" "$AEGIS_DIR" "$LOG_DIR"

# ── 3. Copy project files ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Copying project files to $AEGIS_DIR..."
rsync -a --exclude=node_modules --exclude=dist --exclude=.git \
  "$SCRIPT_DIR/" "$AEGIS_DIR/"

# ── 4. Environment file ────────────────────────────────────────────────────
if [[ ! -f "$AEGIS_DIR/.env" ]]; then
  warn ".env not found — copying from .env.example"
  cp "$AEGIS_DIR/.env.example" "$AEGIS_DIR/.env"
  warn "IMPORTANT: Edit $AEGIS_DIR/.env before starting services!"
fi

# ── 5. npm install + TypeScript build ─────────────────────────────────────
info "Installing npm dependencies..."
cd "$AEGIS_DIR"
npm ci --omit=dev 2>/dev/null || npm install

info "Building TypeScript..."
npx tsc --build

# ── 6. GeoIP database ─────────────────────────────────────────────────────
if [[ ! -f "$AEGIS_DIR/geoip/GeoLite2-City.mmdb" ]]; then
  warn "MaxMind GeoLite2-City.mmdb not found."
  warn "Register free at https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
  warn "Then place the .mmdb file at: $AEGIS_DIR/geoip/GeoLite2-City.mmdb"
fi

# ── 7. systemd services ────────────────────────────────────────────────────
info "Installing systemd service units..."
cp "$AEGIS_DIR/systemd/"*.service "$AEGIS_DIR/systemd/"*.target /etc/systemd/system/
systemctl daemon-reload

info "Enabling Aegis target..."
systemctl enable aegis.target
systemctl enable aegis-classifier.service
systemctl enable aegis-tarpit-http.service
systemctl enable aegis-honeypot.service
systemctl enable aegis-canary-server.service
systemctl enable aegis-supply-chain.service

# ── 8. UFW network isolation ───────────────────────────────────────────────
info "Applying UFW firewall rules..."
ufw --force reset

ufw default deny incoming
ufw default deny outgoing

# WireGuard mesh (management interface) — bidirectional
ufw allow in  on wg0
ufw allow out on wg0

# DNS outbound (threat intel lookups)
ufw allow out 53/udp
ufw allow out 53/tcp

# HTTPS outbound (CVE feeds, threat intel APIs, canary DNS registration)
ufw allow out 443/tcp

# NTP
ufw allow out 123/udp

ufw --force enable
info "UFW rules applied."
warn "Docker deception containers use a separate bridge (deception-net)."
warn "Ensure DECEPTION_IP (eth1/vlan) has NO route to wg0."

# ── 9. Docker deception network namespace (single-interface fallback) ──────
if ! ip netns list | grep -q deception 2>/dev/null; then
  info "Creating 'deception' network namespace for single-interface setups..."
  ip netns add deception || true
  ip link add veth-host type veth peer name veth-deception 2>/dev/null || true
  ip link set veth-deception netns deception 2>/dev/null || true
  ip link set veth-host up 2>/dev/null || true
  ip -n deception link set veth-deception up 2>/dev/null || true
  warn "Network namespace created. Configure addresses per Aegis.md §Phase 0."
fi

# ── Done ───────────────────────────────────────────────────────────────────
echo ""
info "=========================================="
info " Aegis setup complete!"
info "=========================================="
echo ""
echo "  Next steps:"
echo "  1. Edit /opt/aegis/.env (fill in DECEPTION_IP, API keys, etc.)"
echo "  2. Configure WireGuard: wg0 mesh peer to Pi5 (10.99.0.1)"
echo "  3. Place GeoLite2-City.mmdb in /opt/aegis/geoip/"
echo "  4. Build Docker deception images:"
echo "     cd /opt/aegis/docker && docker compose build"
echo "  5. Start all services:"
echo "     systemctl start aegis.target"
echo "  6. Check logs:"
echo "     journalctl -u aegis-classifier -f"
echo ""
warn "REMINDER: Verify deception interface (eth1) has NO route to wg0 before starting."
