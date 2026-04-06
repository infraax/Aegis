/**
 * ARP Integrity Monitor Bridge
 *
 * Spawns scripts/arp_monitor.py as a long-running child process, reads JSON
 * alert lines from its stdout, and exports each alert via exportEvent().
 *
 * Integration pattern: Pattern C (subprocess bridge, long-running)
 *   - The scapy ARP sniffer runs in its own Python process with CAP_NET_RAW
 *   - This bridge owns only process lifecycle + JSON parsing + export wiring
 *   - Auto-restarts the child process on unexpected exit
 *
 * Covers: ATT&CK T1557.002 (ARP Cache Poisoning / Archimedes-style MITM)
 *
 * Graceful degradation:
 *   - scapy not installed → arp_monitor.py prints error JSON and exits;
 *     bridge logs a warning and does NOT restart (permanent failure)
 *   - Permission denied → same: log, no restart
 *   - Network error / interface not found → log warning, retry with backoff
 *
 * Environment:
 *   ARP_MONITOR_IFACE    — network interface (default: eth1)
 *   ARP_MONITOR_GATEWAY  — gateway IP for priority alerting (optional)
 *   ARP_MONITOR_BASELINE — path to JSON baseline file (optional)
 *   ARP_SCRIPT_PATH      — override script path (for tests)
 */

import { spawn, type ChildProcess } from 'child_process';
import path from 'path';
import readline from 'readline';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';

const SCRIPT_PATH = process.env.ARP_SCRIPT_PATH ??
  path.resolve(__dirname, '../scripts/arp_monitor.py');

const IFACE    = process.env.ARP_MONITOR_IFACE    ?? 'eth1';
const GATEWAY  = process.env.ARP_MONITOR_GATEWAY  ?? undefined;
const BASELINE = process.env.ARP_MONITOR_BASELINE ?? undefined;

const MAX_RESTARTS   = 5;
const RESTART_DELAY_MS = 5_000;

// ─── Alert types from arp_monitor.py ─────────────────────────────────────────

interface ARPAlert {
  event_type: 'arp_conflict' | 'gateway_spoof' | 'started';
  sender_ip?: string;
  sender_mac?: string;
  trusted_mac?: string | null;
  target_ip?: string;
  ts: number;
  error?: string;
}

// ─── Process manager ──────────────────────────────────────────────────────────

let _proc: ChildProcess | null = null;
let _restarts = 0;
let _stopped  = false;

function buildArgs(): string[] {
  const args = [SCRIPT_PATH, '--iface', IFACE];
  if (GATEWAY)  args.push('--gateway',  GATEWAY);
  if (BASELINE) args.push('--baseline', BASELINE);
  return args;
}

function handleAlert(alert: ARPAlert): void {
  if (alert.event_type === 'started') {
    logger.info('arp-monitor: started', { iface: IFACE, gateway: GATEWAY });
    return;
  }

  if (alert.error) {
    const isPermanent =
      alert.error.includes('not installed') ||
      alert.error.includes('Permission denied');

    if (isPermanent) {
      logger.warn('arp-monitor: permanent failure — disabling restarts', {
        error: alert.error,
      });
      _stopped = true;
    } else {
      logger.warn('arp-monitor: script error', { error: alert.error });
    }
    return;
  }

  const severity = alert.event_type === 'gateway_spoof' ? 'CRITICAL' : 'HIGH';

  logger.warn(`arp-monitor: ${severity} — ${alert.event_type.toUpperCase()}`, {
    senderIp:   alert.sender_ip,
    senderMac:  alert.sender_mac,
    trustedMac: alert.trusted_mac,
    targetIp:   alert.target_ip,
    technique:  'T1557.002',
  });

  exportEvent(`homelab/threats/arp/${alert.sender_ip}`, {
    eventType:   alert.event_type,
    senderIp:    alert.sender_ip,
    senderMac:   alert.sender_mac,
    trustedMac:  alert.trusted_mac,
    targetIp:    alert.target_ip,
    severity,
    technique:   'T1557.002',
    ts:          alert.ts,
  }).catch((err) => logger.error('arp-monitor: export failed', { err }));
}

function startProcess(): void {
  if (_stopped) return;

  logger.info('arp-monitor: spawning', { script: SCRIPT_PATH, iface: IFACE });

  const proc = spawn('python3', buildArgs(), {
    env: { ...process.env },
  });

  _proc = proc;

  // Read JSON alerts from stdout line-by-line
  const rl = readline.createInterface({ input: proc.stdout, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      const alert: ARPAlert = JSON.parse(line);
      handleAlert(alert);
    } catch {
      logger.debug('arp-monitor: non-JSON stdout line', { line });
    }
  });

  proc.stderr.on('data', (chunk: Buffer) => {
    logger.debug('arp-monitor: stderr', { msg: chunk.toString().trim() });
  });

  proc.on('error', (err) => {
    if (err.message.includes('ENOENT')) {
      logger.warn('arp-monitor: python3 not found or script missing', {
        script: SCRIPT_PATH,
        hint: 'Ensure python3 is in PATH and scapy is installed',
      });
      _stopped = true;
    } else {
      logger.error('arp-monitor: process error', { err: err.message });
    }
  });

  proc.on('close', (code) => {
    _proc = null;
    if (_stopped) return;

    if (_restarts >= MAX_RESTARTS) {
      logger.error('arp-monitor: max restarts reached — giving up', { restarts: _restarts });
      _stopped = true;
      return;
    }

    _restarts++;
    logger.warn('arp-monitor: process exited — restarting', {
      code,
      restarts: _restarts,
      delayMs: RESTART_DELAY_MS,
    });
    setTimeout(startProcess, RESTART_DELAY_MS);
  });
}

/**
 * Start the ARP monitor. Non-blocking — spawns the Python process.
 * Safe to call multiple times — subsequent calls are no-ops if already running.
 */
export function startARPMonitor(): void {
  if (_proc || _stopped) return;
  startProcess();
}

/** Stop the monitor and prevent restarts. */
export function stopARPMonitor(): void {
  _stopped = true;
  if (_proc) {
    _proc.kill('SIGTERM');
    _proc = null;
  }
}

/** Exposed for tests */
export function _resetForTest(): void {
  _stopped  = false;
  _restarts = 0;
  _proc     = null;
}
