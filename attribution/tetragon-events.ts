/**
 * Tetragon eBPF Event Bridge
 *
 * Reads Tetragon's gRPC/JSON event stream from its Unix domain socket and
 * exports security-relevant events via exportEvent().
 *
 * Integration pattern: Pattern E (system daemon bridge)
 *   - Tetragon is a host-level eBPF daemon managed by systemd
 *   - This bridge owns only socket connection + JSON parsing + export wiring
 *   - Reconnects automatically on socket error / daemon restart
 *
 * ATT&CK coverage (via kernel enforcement):
 *   T1071  — Application Layer Protocol (outbound connect kill events)
 *   T1059  — Command and Scripting Interpreter (execve alerts)
 *   T1565.001 — Stored Data Manipulation (/etc write alerts)
 *   T1547  — Boot/Logon Autostart Execution (cron write + kill events)
 *   T1552.001 — Credentials In Files (/root, /home read alerts)
 *   T1557.002 — (ARP — covered by arp-monitor.ts; Tetragon covers the exec layer)
 *
 * Graceful degradation:
 *   - Socket not found (Tetragon not installed) → logs warning, no retry
 *   - Socket closed / ECONNRESET → exponential backoff, reconnect up to 10×
 *   - Malformed JSON line → skipped with debug log
 *
 * Environment:
 *   TETRAGON_SOCK  — path to Tetragon Unix socket
 *                    (default: /var/run/tetragon/tetragon.sock)
 *   TETRAGON_EVENTS_DISABLE — set to "1" to suppress bridge startup
 *                              (useful in unit-test environments)
 */

import net from 'net';
import readline from 'readline';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';

// ─── Configuration ────────────────────────────────────────────────────────────

const SOCK_PATH = process.env.TETRAGON_SOCK ??
  '/var/run/tetragon/tetragon.sock';

const MAX_RECONNECTS   = 10;
const BASE_BACKOFF_MS  = 1_000;
const MAX_BACKOFF_MS   = 30_000;

// ─── Tetragon event types (subset we care about) ─────────────────────────────

/**
 * Tetragon emits newline-delimited JSON. Each line is a wrapper object with
 * one of these top-level fields set:
 */
export interface TetragonProcessExec {
  process_exec: {
    process: TetragonProcess;
    parent?: TetragonProcess;
  };
}

export interface TetragonProcessKprobe {
  process_kprobe: {
    process: TetragonProcess;
    parent?: TetragonProcess;
    function_name: string;
    args: TetragonKprobeArg[];
    action: 'KPROBE_ACTION_POST' | 'KPROBE_ACTION_SIGKILL' | string;
  };
}

export interface TetragonProcess {
  exec_id:    string;
  pid:        number;
  uid:        number;
  cwd:        string;
  binary:     string;
  arguments:  string;
  pod?:       { namespace: string; name: string; container: { name: string } };
}

export interface TetragonKprobeArg {
  string_arg?: string;
  int_arg?:    number;
  size_arg?:   number;
}

export type TetragonEvent = TetragonProcessExec | TetragonProcessKprobe;

/**
 * Parsed summary we export via exportEvent()
 */
export interface TetragonAlert {
  eventType:    'exec' | 'kprobe_connect' | 'kprobe_execve' | 'kprobe_openat' | 'unknown';
  action:       'POST' | 'SIGKILL' | 'UNKNOWN';
  binary:       string;
  pid:          number;
  cwd:          string;
  functionName?: string;
  args:         string[];
  technique:    string;
  pod?:         string;
  severity:     'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  ts:           number;
}

// ─── Event parser ─────────────────────────────────────────────────────────────

const TECHNIQUE_MAP: Record<string, string> = {
  sys_connect:  'T1071',
  sys_execve:   'T1059',
  sys_openat:   'T1565.001',
};

function parseSeverity(fn: string, action: string, args: string[]): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO' {
  if (action === 'KPROBE_ACTION_SIGKILL') return 'CRITICAL';
  if (fn === 'sys_connect')              return 'HIGH';
  if (fn === 'sys_openat') {
    const path = args[1] ?? '';
    if (path.startsWith('/etc/') || path.startsWith('/root') || path.startsWith('/home')) return 'HIGH';
    return 'MEDIUM';
  }
  if (fn === 'sys_execve') return 'MEDIUM';
  return 'INFO';
}

export function parseTetragonEvent(raw: unknown): TetragonAlert | null {
  if (typeof raw !== 'object' || raw === null) return null;

  const obj = raw as Record<string, unknown>;

  // ── process_exec ────────────────────────────────────────────────────────
  if ('process_exec' in obj) {
    const ev = (obj as unknown as TetragonProcessExec).process_exec;
    return {
      eventType:  'exec',
      action:     'POST',
      binary:     ev.process.binary,
      pid:        ev.process.pid,
      cwd:        ev.process.cwd,
      args:       ev.process.arguments ? [ev.process.arguments] : [],
      technique:  'T1059',
      pod:        ev.process.pod
        ? `${ev.process.pod.namespace}/${ev.process.pod.name}/${ev.process.pod.container.name}`
        : undefined,
      severity:   'INFO',
      ts:         Date.now(),
    };
  }

  // ── process_kprobe ───────────────────────────────────────────────────────
  if ('process_kprobe' in obj) {
    const ev = (obj as unknown as TetragonProcessKprobe).process_kprobe;
    const fn  = ev.function_name;
    const rawArgs = ev.args ?? [];
    const args = rawArgs.map((a) => a.string_arg ?? String(a.int_arg ?? a.size_arg ?? ''));

    const eventType: TetragonAlert['eventType'] =
      fn === 'sys_connect'  ? 'kprobe_connect'  :
      fn === 'sys_execve'   ? 'kprobe_execve'   :
      fn === 'sys_openat'   ? 'kprobe_openat'   : 'unknown';

    const action: TetragonAlert['action'] =
      ev.action === 'KPROBE_ACTION_SIGKILL' ? 'SIGKILL' :
      ev.action === 'KPROBE_ACTION_POST'    ? 'POST'    : 'UNKNOWN';

    return {
      eventType,
      action,
      binary:       ev.process.binary,
      pid:          ev.process.pid,
      cwd:          ev.process.cwd,
      functionName: fn,
      args,
      technique:    TECHNIQUE_MAP[fn] ?? 'T1059',
      pod:          ev.process.pod
        ? `${ev.process.pod.namespace}/${ev.process.pod.name}/${ev.process.pod.container.name}`
        : undefined,
      severity:     parseSeverity(fn, ev.action, args),
      ts:           Date.now(),
    };
  }

  return null;
}

// ─── Socket connection + readline loop ───────────────────────────────────────

let _socket: net.Socket | null = null;
let _reconnects = 0;
let _stopped    = false;

function connect(): void {
  if (_stopped) return;

  logger.info('tetragon-events: connecting', { sock: SOCK_PATH });

  const sock = net.createConnection(SOCK_PATH);
  _socket = sock;

  const rl = readline.createInterface({ input: sock, crlfDelay: Infinity });

  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      const raw = JSON.parse(line);
      const alert = parseTetragonEvent(raw);
      if (!alert) return;

      logger.warn(`tetragon-events: ${alert.severity} ${alert.eventType} [${alert.action}]`, {
        binary:    alert.binary,
        pid:       alert.pid,
        technique: alert.technique,
        pod:       alert.pod,
      });

      exportEvent(`homelab/threats/tetragon/${alert.technique}/${alert.pid}`, alert)
        .catch((err) => logger.error('tetragon-events: export failed', { err }));

    } catch {
      logger.debug('tetragon-events: non-JSON line', { line: line.slice(0, 200) });
    }
  });

  sock.on('connect', () => {
    logger.info('tetragon-events: connected', { sock: SOCK_PATH });
    _reconnects = 0;
  });

  sock.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'ENOENT') {
      logger.warn('tetragon-events: socket not found — Tetragon not running', {
        sock: SOCK_PATH,
        hint: 'Install tetragon: https://tetragon.io/docs/installation/',
      });
      _stopped = true;   // don't retry if daemon is absent
      return;
    }
    logger.error('tetragon-events: socket error', { err: err.message });
  });

  sock.on('close', () => {
    _socket = null;
    rl.close();
    if (_stopped) return;

    if (_reconnects >= MAX_RECONNECTS) {
      logger.error('tetragon-events: max reconnects reached — giving up', {
        reconnects: _reconnects,
      });
      _stopped = true;
      return;
    }

    _reconnects++;
    const delay = Math.min(BASE_BACKOFF_MS * 2 ** _reconnects, MAX_BACKOFF_MS);
    logger.warn('tetragon-events: connection closed — reconnecting', {
      reconnects: _reconnects,
      delayMs: delay,
    });
    setTimeout(connect, delay);
  });
}

/**
 * Start reading Tetragon events.
 * Non-blocking — connects asynchronously.
 * Safe to call multiple times — subsequent calls are no-ops.
 */
export function startTetragonEvents(): void {
  if (process.env.TETRAGON_EVENTS_DISABLE === '1') {
    logger.debug('tetragon-events: disabled via env');
    return;
  }
  if (_socket || _stopped) return;
  connect();
}

/** Stop the bridge and prevent reconnects. */
export function stopTetragonEvents(): void {
  _stopped = true;
  if (_socket) {
    _socket.destroy();
    _socket = null;
  }
}

/** Exposed for tests */
export function _resetForTest(): void {
  _stopped    = false;
  _reconnects = 0;
  _socket     = null;
}
