#!/usr/bin/env python3
"""
Process-to-Network Attribution Monitor (Module 7 — Stage 9)

Continuously maps all outbound TCP/UDP connections to their originating
PID and binary path using psutil. Alerts on unexpected outbound connections
from unknown or untrusted processes.

ATT&CK coverage:
  T1071  — Application Layer Protocol (unexpected outbound C2)
  T1041  — Exfiltration Over C2 Channel
  T1095  — Non-Application Layer Protocol

Usage:
  python3 process_net_monitor.py [--interval 5] [--whitelist /path/whitelist.json]

Requirements:
  pip install psutil

Environment:
  PROCESS_NET_IFACE       — informational only; used in JSON output
  PROCESS_NET_INTERVAL    — polling interval seconds (default: 5)
  PROCESS_NET_WHITELIST   — JSON file with allowed binary→dst patterns

Whitelist format (process_net_whitelist.json):
  {
    "binaries": [
      "/usr/bin/node",
      "/usr/bin/python3",
      "/usr/bin/curl",
      "/usr/sbin/sshd"
    ],
    "destinations": [
      "127.0.0.1",
      "100.64.0.0/10"   (Tailscale CGNAT range)
    ]
  }
"""

import argparse
import ipaddress
import json
import os
import signal
import sys
import time
from typing import Optional

try:
    import psutil
except ImportError:
    print(json.dumps({
        "event_type": "error",
        "error": "psutil not installed — run: pip install psutil",
        "ts": time.time()
    }), flush=True)
    sys.exit(1)

# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_INTERVAL  = int(os.environ.get("PROCESS_NET_INTERVAL", "5"))
DEFAULT_WHITELIST = os.environ.get("PROCESS_NET_WHITELIST",
                                   os.path.join(os.path.dirname(__file__),
                                                "process_net_whitelist.json"))

# ── Default whitelist (augmented from whitelist file if present) ─────────────

DEFAULT_TRUSTED_BINARIES = {
    "/usr/bin/node",
    "/usr/local/bin/node",
    "/usr/bin/python3",
    "/usr/bin/python",
    "/usr/sbin/sshd",
    "/usr/sbin/ntpd",
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/usr/lib/apt/methods/http",
    "/usr/lib/apt/methods/https",
    "/usr/bin/tailscale",
    "/usr/sbin/tailscaled",
    "/usr/sbin/wazuh-agentd",
    "/var/ossec/bin/wazuh-agentd",
    "/usr/bin/dockerd",
    "/usr/sbin/dockerd",
    "docker-proxy",       # Docker's port proxy (binary name only)
}

# Tailscale CGNAT + loopback + RFC1918 — always trusted destinations
TRUSTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),    # Tailscale CGNAT range
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),  # Tailscale IPv6
]

def load_whitelist(path: str) -> tuple[set, list]:
    trusted_bins: set = set(DEFAULT_TRUSTED_BINARIES)
    trusted_nets: list = list(TRUSTED_NETWORKS)
    if not os.path.exists(path):
        return trusted_bins, trusted_nets
    try:
        with open(path) as f:
            wl = json.load(f)
        trusted_bins.update(wl.get("binaries", []))
        for cidr in wl.get("destinations", []):
            try:
                trusted_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    except Exception as e:
        print(json.dumps({
            "event_type": "warning",
            "message": f"Could not load whitelist: {e}",
            "ts": time.time()
        }), flush=True)
    return trusted_bins, trusted_nets

def is_trusted_dest(ip_str: str, trusted_nets: list) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in trusted_nets)
    except ValueError:
        return False

def get_binary(proc: psutil.Process) -> Optional[str]:
    try:
        return proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def get_binary_name(binary: Optional[str]) -> str:
    if not binary:
        return "<unknown>"
    return os.path.basename(binary)

# ── Connection tracker ───────────────────────────────────────────────────────
# Track seen connections to avoid repeated alerts for persistent connections
_seen: dict = {}   # (pid, laddr, raddr) → first_seen_ts

def connection_key(conn: psutil.pconn) -> tuple:
    raddr = (conn.raddr.ip, conn.raddr.port) if conn.raddr else ("", 0)
    laddr = (conn.laddr.ip, conn.laddr.port) if conn.laddr else ("", 0)
    return (conn.pid, laddr, raddr)

# ── Main monitor loop ────────────────────────────────────────────────────────

def scan_connections(trusted_bins: set, trusted_nets: list) -> None:
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print(json.dumps({
            "event_type": "error",
            "error": "Permission denied — requires root or CAP_NET_ADMIN",
            "ts": time.time()
        }), flush=True)
        sys.exit(1)

    now = time.time()

    for conn in connections:
        # Only care about established outbound connections
        if conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.raddr:
            continue

        key = connection_key(conn)
        if key in _seen:
            continue   # already reported

        _seen[key] = now
        rip = conn.raddr.ip
        rport = conn.raddr.port

        # Trusted destination — skip
        if is_trusted_dest(rip, trusted_nets):
            continue

        # Get binary for this PID
        binary: Optional[str] = None
        cmdline: list = []
        username: str = "unknown"
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                binary   = get_binary(proc)
                cmdline  = proc.cmdline()[:5]   # first 5 args
                username = proc.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        binary_name = get_binary_name(binary)
        is_trusted_bin = (
            binary in trusted_bins or
            binary_name in trusted_bins or
            any(t.endswith(binary_name) for t in trusted_bins if binary_name)
        )

        if is_trusted_bin:
            continue

        # Unknown process making outbound connection — alert
        print(json.dumps({
            "event_type":  "unexpected_outbound",
            "pid":         conn.pid,
            "binary":      binary or "<unknown>",
            "binary_name": binary_name,
            "cmdline":     " ".join(cmdline),
            "username":    username,
            "src_ip":      conn.laddr.ip if conn.laddr else "",
            "src_port":    conn.laddr.port if conn.laddr else 0,
            "dst_ip":      rip,
            "dst_port":    rport,
            "technique":   "T1071",
            "ts":          now,
        }), flush=True)

def cleanup_seen(max_age_s: int = 300) -> None:
    """Evict stale connection records (closed connections)."""
    now = time.time()
    cutoff = now - max_age_s
    stale = [k for k, t in _seen.items() if t < cutoff]
    for k in stale:
        del _seen[k]

def main():
    parser = argparse.ArgumentParser(description="Process-to-network monitor for Aegis")
    parser.add_argument("--interval",  type=int,  default=DEFAULT_INTERVAL,
                        help="Poll interval in seconds (default: 5)")
    parser.add_argument("--whitelist", default=DEFAULT_WHITELIST,
                        help="Path to whitelist JSON file")
    args = parser.parse_args()

    def _handle_sigterm(sig, frame):
        print(json.dumps({
            "event_type": "stopped",
            "ts": time.time()
        }), flush=True)
        sys.exit(0)
    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT,  _handle_sigterm)

    trusted_bins, trusted_nets = load_whitelist(args.whitelist)

    print(json.dumps({
        "event_type":      "started",
        "interval_s":      args.interval,
        "trusted_bins":    len(trusted_bins),
        "trusted_nets":    len(trusted_nets),
        "ts":              time.time()
    }), flush=True)

    tick = 0
    while True:
        scan_connections(trusted_bins, trusted_nets)
        tick += 1
        if tick % (60 // args.interval) == 0:   # cleanup every ~60s
            cleanup_seen()
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
