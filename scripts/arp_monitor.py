#!/usr/bin/env python3
"""
arp_monitor.py — ARP integrity monitor for Aegis (Stage 3.6)

Sniffs ARP traffic on the deception interface and alerts when any device
claims to own an IP address that belongs to a different MAC in the trusted
baseline — the signature of Archimedes-style ARP poisoning (ATT&CK T1557.002).

Usage:
    python3 scripts/arp_monitor.py [--iface IFACE] [--baseline-file PATH]

Output: one JSON object per line to stdout on alert, debug lines to stderr.
Exit: 0 on SIGTERM/SIGINT (clean shutdown), 1 on fatal error.

Requires: scapy, root/CAP_NET_RAW privileges
    pip3 install scapy
"""

import argparse
import ipaddress
import json
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    from scapy.all import ARP, Ether, sniff, get_if_hwaddr
    from scapy.error import Scapy_Exception
except ImportError:
    print(json.dumps({
        "error": "scapy not installed",
        "hint": "pip3 install scapy",
        "ts": int(time.time() * 1000),
    }))
    sys.exit(1)

# ── Baseline builder ──────────────────────────────────────────────────────────

def build_baseline(iface: str) -> dict[str, str]:
    """Seed the trusted IP→MAC map from the current ARP table."""
    baseline: dict[str, str] = {}
    try:
        out = subprocess.check_output(["arp", "-n", "-i", iface], text=True)
        for line in out.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 3 and parts[2] not in ("(incomplete)", "<incomplete>"):
                ip_str, mac = parts[0], parts[2]
                try:
                    ipaddress.ip_address(ip_str)  # validate
                    baseline[ip_str] = mac.lower()
                except ValueError:
                    pass
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Always trust the interface's own MAC → its IP
    try:
        own_mac = get_if_hwaddr(iface)
        if own_mac:
            baseline["own"] = own_mac.lower()
    except Exception:  # noqa: BLE001
        pass

    print(f"[arp_monitor] baseline: {len(baseline)} entries on {iface}", file=sys.stderr)
    return baseline


# ── Alert emitter ─────────────────────────────────────────────────────────────

def emit_alert(event_type: str, sender_ip: str, sender_mac: str,
               trusted_mac: str | None, target_ip: str) -> None:
    alert = {
        "event_type": event_type,        # "arp_conflict" | "gateway_spoof"
        "sender_ip": sender_ip,
        "sender_mac": sender_mac,
        "trusted_mac": trusted_mac,      # what we expected, or None if new entry
        "target_ip": target_ip,
        "ts": int(time.time() * 1000),
        "iso": datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(alert), flush=True)  # stdout — read by arp-monitor.ts


# ── Packet handler ────────────────────────────────────────────────────────────

class ARPMonitor:
    def __init__(self, iface: str, baseline: dict[str, str], gateway_ip: str | None):
        self.iface = iface
        self.baseline = dict(baseline)   # mutable — we learn new entries
        self.gateway_ip = gateway_ip
        self.alert_count = 0

    def handle(self, pkt: Ether) -> None:
        if not pkt.haslayer(ARP):
            return

        arp: ARP = pkt[ARP]
        # ARP reply (op=2) or gratuitous ARP (op=1 with same src/dst IP)
        is_reply = arp.op == 2
        is_gratuitous = arp.op == 1 and arp.psrc == arp.pdst

        if not (is_reply or is_gratuitous):
            return

        sender_ip  = arp.psrc
        sender_mac = arp.hwsrc.lower()

        trusted_mac = self.baseline.get(sender_ip)

        if trusted_mac is None:
            # New IP — add to baseline silently
            self.baseline[sender_ip] = sender_mac
            print(f"[arp_monitor] learned {sender_ip} → {sender_mac}", file=sys.stderr)
            return

        if trusted_mac != sender_mac:
            event_type = "gateway_spoof" if sender_ip == self.gateway_ip else "arp_conflict"
            emit_alert(event_type, sender_ip, sender_mac, trusted_mac, arp.pdst)
            self.alert_count += 1
            print(
                f"[arp_monitor] ALERT #{self.alert_count} {event_type}: "
                f"{sender_ip} claimed by {sender_mac} (expected {trusted_mac})",
                file=sys.stderr,
            )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ARP integrity monitor")
    parser.add_argument("--iface",    default="eth1",  help="Network interface to monitor")
    parser.add_argument("--gateway",  default=None,    help="Gateway IP for priority alerting")
    parser.add_argument("--baseline", default=None,    help="Path to JSON baseline file (optional)")
    args = parser.parse_args()

    # Handle SIGTERM cleanly (Docker stop)
    def shutdown(signum, frame):  # noqa: ANN001
        print("[arp_monitor] shutting down", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    baseline: dict[str, str] = {}

    if args.baseline:
        try:
            with open(args.baseline) as f:
                baseline = json.load(f)
            print(f"[arp_monitor] loaded baseline from {args.baseline}", file=sys.stderr)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[arp_monitor] baseline load failed: {e} — using live ARP table", file=sys.stderr)

    if not baseline:
        baseline = build_baseline(args.iface)

    monitor = ARPMonitor(iface=args.iface, baseline=baseline, gateway_ip=args.gateway)

    print(
        json.dumps({"event_type": "started", "iface": args.iface,
                    "baseline_size": len(baseline), "ts": int(time.time() * 1000)}),
        flush=True,
    )

    try:
        sniff(
            iface=args.iface,
            filter="arp",
            prn=monitor.handle,
            store=False,   # don't accumulate packets in memory
        )
    except Scapy_Exception as e:
        print(json.dumps({"error": str(e), "ts": int(time.time() * 1000)}))
        sys.exit(1)
    except PermissionError:
        print(json.dumps({
            "error": "Permission denied — raw socket requires root or CAP_NET_RAW",
            "hint": "Run as root or: sudo setcap cap_net_raw+ep $(which python3)",
            "ts": int(time.time() * 1000),
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()
