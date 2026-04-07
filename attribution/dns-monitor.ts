/**
 * DNS Anomaly Monitor Bridge (Module 6 — Stage 8)
 *
 * Spawns scripts/dns_monitor.py as a long-running child process, reads
 * JSON alerts from its stdout, and exports each alert via exportEvent().
 *
 * Integration pattern: Pattern C (subprocess bridge, long-running)
 *
 * ATT&CK coverage:
 *   T1071.004 — Application Layer Protocol: DNS (tunneling, C2 beacons)
 *   T1568     — Dynamic Resolution (DGA — repeated NXDOMAIN)
 *   T1048     — Exfiltration Over Alternative Protocol (TXT abuse)
 *
 * Graceful degradation:
 *   - scapy not installed → script prints error JSON and exits; bridge logs warning
 *   - Permission denied → same; no restart
 *   - Interface not found → same; no restart
 *   - Normal exits (closed iface) → restart with backoff up to MAX_RESTARTS
 *
 * Environment:
 *   DNS_MONITOR_IFACE     — network interface (default: eth1)
 *   DNS_MONITOR_THRESHOLD — entropy threshold (default: 3.5)
 *   DNS_SCRIPT_PATH       — override script path (for tests)
 *   DNS_MONITOR_DISABLE   — set to "1" to suppress
 */

import { spawn, type ChildProcess } from 'child_process';
import path from 'path';
import readline from 'readline';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';

const SCRIPT_PATH = process.env.DNS_SCRIPT_PATH ??
  path.resolve(__dirname, '../scripts/dns_monitor.py');

const IFACE     = process.env.DNS_MONITOR_IFACE      ?? 'eth1';
const THRESHOLD = process.env.DNS_MONITOR_THRESHOLD  ?? '3.5';

const MAX_RESTARTS    = 5;
const RESTART_DELAY_MS = 5_000;

export interface DNSAlert {
  event_type:   string;
  src_ip:       string;
  qname:        string;
  dns_event_type?: string;
  entropy?:     number;
  tunnel_type?: string;
  txt_bytes?:   number;
  depth?:       number;
  length?:      number;
  nxdomain_count?: number;
  queries_per_window?: number;
  technique?:   string;
  ts:           number;
  error?:       string;
}

let _proc: ChildProcess | null = null;
let _restarts = 0;
let _stopped  = false;

const PERMANENT_ERRORS = ['not installed', 'Permission denied', 'Interface error'];

function isPermanentError(error: string): boolean {
  return PERMANENT_ERRORS.some((e) => error.includes(e));
}

function handleAlert(alert: DNSAlert): void {
  if (alert.event_type === 'started') {
    logger.info('dns-monitor: started', { iface: IFACE });
    return;
  }
  if (alert.event_type === 'stopped') {
    logger.info('dns-monitor: stopped');
    return;
  }

  if (alert.error) {
    if (isPermanentError(alert.error)) {
      logger.warn('dns-monitor: permanent failure — disabling', { error: alert.error });
      _stopped = true;
    } else {
      logger.warn('dns-monitor: error', { error: alert.error });
    }
    return;
  }

  const severity =
    alert.event_type === 'high_entropy_subdomain' ? 'HIGH' :
    alert.event_type === 'large_txt_response'     ? 'HIGH' :
    alert.event_type === 'repeated_nxdomain'      ? 'MEDIUM' :
    'MEDIUM';

  logger.warn(`dns-monitor: ${severity} ${alert.event_type}`, {
    srcIp:     alert.src_ip,
    qname:     alert.qname,
    entropy:   alert.entropy,
    technique: alert.technique,
  });

  exportEvent(`homelab/threats/dns/${alert.src_ip}`, {
    ...alert,
    severity,
  }).catch((err) => logger.error('dns-monitor: export failed', { err }));
}

function startProcess(): void {
  if (_stopped) return;

  logger.info('dns-monitor: spawning', { script: SCRIPT_PATH, iface: IFACE });

  const proc = spawn('python3', [
    SCRIPT_PATH,
    '--iface',     IFACE,
    '--threshold', THRESHOLD,
  ], { env: { ...process.env } });

  _proc = proc;

  const rl = readline.createInterface({ input: proc.stdout, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      handleAlert(JSON.parse(line) as DNSAlert);
    } catch {
      logger.debug('dns-monitor: non-JSON stdout line', { line });
    }
  });

  proc.stderr.on('data', (chunk: Buffer) => {
    logger.debug('dns-monitor: stderr', { msg: chunk.toString().trim() });
  });

  proc.on('error', (err) => {
    if (err.message.includes('ENOENT')) {
      logger.warn('dns-monitor: python3 not found', { script: SCRIPT_PATH });
      _stopped = true;
    } else {
      logger.error('dns-monitor: process error', { err: err.message });
    }
  });

  proc.on('close', (code) => {
    _proc = null;
    if (_stopped) return;
    if (_restarts >= MAX_RESTARTS) {
      logger.error('dns-monitor: max restarts reached', { restarts: _restarts });
      _stopped = true;
      return;
    }
    _restarts++;
    logger.warn('dns-monitor: restarting', { code, restarts: _restarts });
    setTimeout(startProcess, RESTART_DELAY_MS);
  });
}

export function startDNSMonitor(): void {
  if (process.env.DNS_MONITOR_DISABLE === '1') {
    logger.debug('dns-monitor: disabled via env');
    return;
  }
  if (_proc || _stopped) return;
  startProcess();
}

export function stopDNSMonitor(): void {
  _stopped = true;
  if (_proc) {
    _proc.kill('SIGTERM');
    _proc = null;
  }
}

export function _resetForTest(): void {
  _stopped  = false;
  _restarts = 0;
  _proc     = null;
}
