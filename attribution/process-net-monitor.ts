/**
 * Process-to-Network Attribution Monitor Bridge (Module 7 — Stage 9)
 *
 * Spawns scripts/process_net_monitor.py, reads JSON alerts, exports via exportEvent().
 *
 * Integration pattern: Pattern C (subprocess bridge, long-running)
 *
 * ATT&CK coverage:
 *   T1071  — Application Layer Protocol (unexpected outbound C2)
 *   T1041  — Exfiltration Over C2 Channel
 *
 * Graceful degradation:
 *   - psutil not installed → permanent failure, no restart
 *   - Permission denied → permanent failure, no restart
 *   - Normal exits → restart with backoff up to MAX_RESTARTS
 *
 * Environment:
 *   PROCESS_NET_INTERVAL      — poll interval in seconds (default: 5)
 *   PROCESS_NET_WHITELIST     — path to whitelist JSON
 *   PROCESS_NET_SCRIPT_PATH   — override script path (for tests)
 *   PROCESS_NET_DISABLE       — set to "1" to suppress
 */

import { spawn, type ChildProcess } from 'child_process';
import path from 'path';
import readline from 'readline';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';

const SCRIPT_PATH = process.env.PROCESS_NET_SCRIPT_PATH ??
  path.resolve(__dirname, '../scripts/process_net_monitor.py');

const INTERVAL  = process.env.PROCESS_NET_INTERVAL  ?? '5';
const WHITELIST = process.env.PROCESS_NET_WHITELIST ??
  path.resolve(__dirname, '../scripts/process_net_whitelist.json');

const MAX_RESTARTS    = 5;
const RESTART_DELAY_MS = 5_000;

export interface ProcessNetAlert {
  event_type:   string;
  pid?:         number;
  binary?:      string;
  binary_name?: string;
  cmdline?:     string;
  username?:    string;
  src_ip?:      string;
  src_port?:    number;
  dst_ip?:      string;
  dst_port?:    number;
  technique?:   string;
  ts:           number;
  error?:       string;
}

let _proc: ChildProcess | null = null;
let _restarts = 0;
let _stopped  = false;

function handleAlert(alert: ProcessNetAlert): void {
  if (alert.event_type === 'started') {
    logger.info('process-net: started', { interval: INTERVAL });
    return;
  }
  if (alert.event_type === 'stopped') {
    logger.info('process-net: stopped');
    return;
  }
  if (alert.event_type === 'warning') {
    logger.warn('process-net: warning', alert);
    return;
  }

  if (alert.error) {
    const permanent = alert.error.includes('not installed') ||
                      alert.error.includes('Permission denied');
    if (permanent) {
      logger.warn('process-net: permanent failure — disabling', { error: alert.error });
      _stopped = true;
    } else {
      logger.warn('process-net: error', { error: alert.error });
    }
    return;
  }

  if (alert.event_type !== 'unexpected_outbound') return;

  logger.warn('process-net: HIGH unexpected_outbound', {
    binary:  alert.binary,
    pid:     alert.pid,
    dstIp:   alert.dst_ip,
    dstPort: alert.dst_port,
    technique: alert.technique,
  });

  exportEvent(`homelab/threats/process-net/${alert.dst_ip}`, {
    ...alert,
    severity: 'HIGH',
  }).catch((err) => logger.error('process-net: export failed', { err }));
}

function startProcess(): void {
  if (_stopped) return;

  logger.info('process-net: spawning', { script: SCRIPT_PATH });

  const proc = spawn('python3', [
    SCRIPT_PATH,
    '--interval',  INTERVAL,
    '--whitelist', WHITELIST,
  ], { env: { ...process.env } });

  _proc = proc;

  const rl = readline.createInterface({ input: proc.stdout, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      handleAlert(JSON.parse(line) as ProcessNetAlert);
    } catch {
      logger.debug('process-net: non-JSON line', { line });
    }
  });

  proc.stderr.on('data', (chunk: Buffer) => {
    logger.debug('process-net: stderr', { msg: chunk.toString().trim() });
  });

  proc.on('error', (err) => {
    if (err.message.includes('ENOENT')) {
      logger.warn('process-net: python3 not found', { script: SCRIPT_PATH });
      _stopped = true;
    } else {
      logger.error('process-net: process error', { err: err.message });
    }
  });

  proc.on('close', (code) => {
    _proc = null;
    if (_stopped) return;
    if (_restarts >= MAX_RESTARTS) {
      logger.error('process-net: max restarts reached', { restarts: _restarts });
      _stopped = true;
      return;
    }
    _restarts++;
    logger.warn('process-net: restarting', { code, restarts: _restarts });
    setTimeout(startProcess, RESTART_DELAY_MS);
  });
}

export function startProcessNetMonitor(): void {
  if (process.env.PROCESS_NET_DISABLE === '1') {
    logger.debug('process-net: disabled via env');
    return;
  }
  if (_proc || _stopped) return;
  startProcess();
}

export function stopProcessNetMonitor(): void {
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
