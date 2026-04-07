#!/usr/bin/env python3
"""
DNS Anomaly Monitor (Module 6 — Stage 8)

Sniffs DNS traffic on the deception interface and emits JSON alerts for:
  - High-entropy subdomains (DNS tunneling / DGA)
  - TXT record abuse (data exfiltration, >512 bytes)
  - Abnormal query volume per host (>100 queries/min)
  - Deep subdomain nesting (>4 labels — tunneling indicator)
  - Domain length anomalies (>52 chars)
  - Repeated NXDOMAIN (DGA/beaconing)

ATT&CK coverage:
  T1071.004 — Application Layer Protocol: DNS
  T1568     — Dynamic Resolution (DGA)
  T1048     — Exfiltration Over Alternative Protocol

Usage:
  python3 dns_monitor.py --iface eth1 [--threshold 0.7] [--window 60]

Requirements:
  pip install scapy

Environment:
  DNS_MONITOR_IFACE      — network interface (default: eth1)
  DNS_MONITOR_THRESHOLD  — entropy threshold for alert (default: 3.5 bits)
  DNS_MONITOR_WINDOW     — volume count window in seconds (default: 60)
"""

import argparse
import json
import math
import os
import re
import signal
import sys
import time
from collections import defaultdict
from typing import Optional

# ── Graceful import ──────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, conf as scapy_conf
    scapy_conf.verb = 0
except ImportError:
    print(json.dumps({
        "event_type": "error",
        "error": "scapy not installed — run: pip install scapy",
        "ts": time.time()
    }), flush=True)
    sys.exit(1)
except PermissionError:
    print(json.dumps({
        "event_type": "error",
        "error": "Permission denied — requires CAP_NET_RAW or root",
        "ts": time.time()
    }), flush=True)
    sys.exit(1)

# ── Configuration ────────────────────────────────────────────────────────────
DEFAULT_IFACE     = os.environ.get("DNS_MONITOR_IFACE",     "eth1")
DEFAULT_THRESHOLD = float(os.environ.get("DNS_MONITOR_THRESHOLD", "3.5"))
DEFAULT_WINDOW    = int(os.environ.get("DNS_MONITOR_WINDOW",    "60"))

# ── Entropy calculator ───────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

def is_base32(s: str) -> bool:
    """Rough check: base32-encoded data has only [A-Z2-7=]."""
    return bool(re.match(r'^[A-Z2-7=]+$', s.upper())) and len(s) > 8

def is_base64_like(s: str) -> bool:
    """Rough check: base64url chars."""
    return bool(re.match(r'^[A-Za-z0-9+/=_-]+$', s)) and len(s) > 12

# ── Query volume tracker ─────────────────────────────────────────────────────

# src_ip → list of timestamps in the current window
_query_times: dict = defaultdict(list)
_nxdomain_counts: dict = defaultdict(int)

def volume_count(src_ip: str, window_s: int) -> int:
    now = time.time()
    times = _query_times[src_ip]
    times.append(now)
    # Trim old timestamps
    cutoff = now - window_s
    _query_times[src_ip] = [t for t in times if t > cutoff]
    return len(_query_times[src_ip])

# ── DNS packet handler ───────────────────────────────────────────────────────

def emit(event_type: str, src_ip: str, qname: str, **kwargs):
    print(json.dumps({
        "event_type":    event_type,
        "src_ip":        src_ip,
        "qname":         qname,
        "ts":            time.time(),
        **kwargs
    }), flush=True)

def analyze_dns(pkt, entropy_threshold: float, window_s: int, volume_threshold: int):
    if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dns    = pkt[DNS]

    # ── Query (QR=0) ───────────────────────────────────────────────────────
    if dns.qr == 0 and dns.qd:
        qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
        labels = qname.split(".")

        # 1. Query volume
        count = volume_count(src_ip, window_s)
        if count == volume_threshold:   # emit once when threshold crossed
            emit("high_volume", src_ip, qname,
                 queries_per_window=count,
                 window_s=window_s,
                 dns_event_type="high_volume",
                 technique="T1071.004")

        # 2. Domain length
        if len(qname) > 52:
            emit("long_domain", src_ip, qname,
                 length=len(qname),
                 dns_event_type="tunnel_indicator",
                 technique="T1071.004")

        # 3. Deep subdomain nesting
        if len(labels) > 4:
            emit("deep_subdomain", src_ip, qname,
                 depth=len(labels),
                 dns_event_type="tunnel_indicator",
                 technique="T1048")

        # 4. High-entropy subdomain (check first label)
        if labels:
            first = labels[0]
            entropy = shannon_entropy(first)
            if entropy > entropy_threshold:
                tunnel_type = "base32" if is_base32(first) else \
                              "base64" if is_base64_like(first) else "high_entropy"
                emit("high_entropy_subdomain", src_ip, qname,
                     subdomain=first,
                     entropy=round(entropy, 3),
                     tunnel_type=tunnel_type,
                     dns_event_type="high_entropy",
                     technique="T1071.004")

    # ── Response (QR=1) ────────────────────────────────────────────────────
    elif dns.qr == 1 and dns.qd:
        qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")

        # 5. NXDOMAIN (DGA indicator when repeated)
        if dns.rcode == 3:
            _nxdomain_counts[src_ip] += 1
            if _nxdomain_counts[src_ip] % 10 == 0:
                emit("repeated_nxdomain", src_ip, qname,
                     nxdomain_count=_nxdomain_counts[src_ip],
                     dns_event_type="tunnel_indicator",
                     technique="T1568")

        # 6. Large TXT records (exfiltration)
        if dns.an:
            rr = dns.an
            while rr:
                if hasattr(rr, "type") and rr.type == 16:   # TXT
                    try:
                        data = b"".join(rr.rdata) if isinstance(rr.rdata, (list, tuple)) else rr.rdata
                        if len(data) > 512:
                            emit("large_txt_response", src_ip, qname,
                                 txt_bytes=len(data),
                                 dns_event_type="txt_abuse",
                                 technique="T1048")
                    except Exception:
                        pass
                rr = rr.payload if hasattr(rr, "payload") else None
                if rr and not rr.haslayer(DNSRR):
                    break

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DNS anomaly monitor for Aegis")
    parser.add_argument("--iface",     default=DEFAULT_IFACE,
                        help="Network interface to sniff")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help="Shannon entropy threshold (default: 3.5)")
    parser.add_argument("--window",    type=int,   default=DEFAULT_WINDOW,
                        help="Volume tracking window in seconds (default: 60)")
    parser.add_argument("--volume",    type=int,   default=100,
                        help="Query volume alert threshold per window (default: 100)")
    args = parser.parse_args()

    # Signal handler for graceful shutdown
    def _handle_sigterm(sig, frame):
        print(json.dumps({
            "event_type": "stopped",
            "iface": args.iface,
            "ts": time.time()
        }), flush=True)
        sys.exit(0)
    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT,  _handle_sigterm)

    print(json.dumps({
        "event_type":  "started",
        "iface":       args.iface,
        "threshold":   args.threshold,
        "window_s":    args.window,
        "volume_thr":  args.volume,
        "ts":          time.time()
    }), flush=True)

    try:
        sniff(
            iface=args.iface,
            filter="udp port 53 or tcp port 53",
            prn=lambda pkt: analyze_dns(pkt, args.threshold, args.window, args.volume),
            store=False,
        )
    except PermissionError:
        print(json.dumps({
            "event_type": "error",
            "error": "Permission denied — requires CAP_NET_RAW or root",
            "ts": time.time()
        }), flush=True)
        sys.exit(1)
    except OSError as e:
        print(json.dumps({
            "event_type": "error",
            "error": f"Interface error: {e}",
            "iface": args.iface,
            "ts": time.time()
        }), flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
