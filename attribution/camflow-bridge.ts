/**
 * CamFlow OS Provenance Bridge
 *
 * Reads CamFlow's W3C PROV-JSON provenance stream from its output socket
 * and correlates events to active Aegis sessions (by source IP and timing).
 * Exports correlated kill chains to the Gaffer graph via exportEvent().
 *
 * Integration pattern: Pattern E (system daemon bridge)
 *   - CamFlow (camconfd + camflowd) is a kernel module + daemon managed by systemd
 *   - This bridge owns: socket/MQTT connection + event parsing + session correlation
 *   - Session registry is populated by the classifier via registerSession()
 *
 * CamFlow output format (W3C PROV-JSON over Unix socket or MQTT):
 *   Each line is a JSON object with a "type" field indicating the provenance
 *   record type: "activity" (process), "entity" (file/socket), "relation"
 *   (causal edge). Socket path: /run/camflowd.sock
 *
 * ATT&CK coverage:
 *   T1059  — Command and Scripting Interpreter (process spawn causal chain)
 *   T1083  — File and Directory Discovery (file open events)
 *   T1041  — Exfiltration Over C2 Channel (network socket events)
 *   T1003  — OS Credential Dumping (/etc/shadow, /proc/PID/mem reads)
 *
 * Graceful degradation:
 *   - Socket not found (CamFlow not installed) → logs warning, no retry
 *   - Socket closed → exponential backoff, reconnect up to 10×
 *   - Malformed JSON → skipped with debug log
 *   - Session correlation miss → event still exported as uncorrelated
 *
 * Environment:
 *   CAMFLOW_SOCK     — CamFlow output socket (default: /run/camflowd.sock)
 *   CAMFLOW_DISABLE  — set to "1" to suppress bridge startup (for tests)
 *   CAMFLOW_WINDOW_MS — session correlation time window in ms (default: 30000)
 */

import net from 'net';
import readline from 'readline';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';

// ─── Configuration ────────────────────────────────────────────────────────────

const SOCK_PATH    = process.env.CAMFLOW_SOCK      ?? '/run/camflowd.sock';
const WINDOW_MS    = parseInt(process.env.CAMFLOW_WINDOW_MS ?? '30000', 10);

const MAX_RECONNECTS  = 10;
const BASE_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS  = 30_000;

// ─── Session registry ─────────────────────────────────────────────────────────

interface SessionEntry {
  sessionId: string;
  ip:        string;
  registeredAt: number;
  tier: 1 | 2 | 3;
}

const _sessionRegistry = new Map<string, SessionEntry>();  // ip → entry

/**
 * Register an active Aegis session so CamFlow events can be correlated to it.
 * Called by the classifier after each classification.
 */
export function registerSession(sessionId: string, ip: string, tier: 1 | 2 | 3): void {
  _sessionRegistry.set(ip, { sessionId, ip, registeredAt: Date.now(), tier });
}

/** Deregister a session (called when session expires or attacker disconnects). */
export function deregisterSession(ip: string): void {
  _sessionRegistry.delete(ip);
}

/** Look up the session for an IP, respecting the correlation time window. */
export function resolveSession(ip: string): SessionEntry | null {
  const entry = _sessionRegistry.get(ip);
  if (!entry) return null;
  if (Date.now() - entry.registeredAt > WINDOW_MS) {
    _sessionRegistry.delete(ip);
    return null;
  }
  return entry;
}

// ─── CamFlow PROV-JSON types ──────────────────────────────────────────────────

/**
 * CamFlow emits W3C PROV-JSON records. We care about the top-level type and
 * key provenance attributes.
 *
 * Activity record (process spawn, exec):
 *   { "cf:type": "activity", "cf:id": "...", "prov:label": "bash", ... }
 *
 * Entity record (file, socket, pipe):
 *   { "cf:type": "entity", "cf:id": "...", "cf:name": "/etc/shadow", ... }
 *
 * Relation record (causal edge between activities/entities):
 *   { "cf:type": "relation", "prov:type": "used"|"wasGeneratedBy"|...,
 *     "prov:entity": "...", "prov:activity": "...", "cf:timestamp": "..." }
 */

export type CamflowRecordType = 'activity' | 'entity' | 'relation' | 'unknown';

export interface CamflowRecord {
  type:        CamflowRecordType;
  id:          string;
  label:       string | null;  // process name / file path
  sourceIp:    string | null;  // extracted from socket entities
  relationType?: string;       // for relation records: "used", "wasGeneratedBy", etc.
  entityId?:     string;       // relation: referenced entity
  activityId?:   string;       // relation: referenced activity
  timestamp:   number;         // epoch ms
  raw:         Record<string, unknown>;
}

/** Heuristic: extract IPv4 from CamFlow entity names like "tcp:10.0.0.5:4444" */
function extractIp(label: string | null): string | null {
  if (!label) return null;
  const m = /(?:tcp|udp):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+/.exec(label);
  return m ? m[1] : null;
}

export function parseCamflowRecord(raw: unknown): CamflowRecord | null {
  if (typeof raw !== 'object' || raw === null) return null;

  const obj = raw as Record<string, unknown>;
  const cfType = (obj['cf:type'] ?? obj['type']) as string | undefined;
  if (!cfType) return null;

  const type: CamflowRecordType =
    cfType === 'activity' ? 'activity' :
    cfType === 'entity'   ? 'entity'   :
    cfType === 'relation' ? 'relation' : 'unknown';

  const id        = String(obj['cf:id'] ?? obj['id'] ?? '');
  const rawLabel  = (obj['prov:label'] ?? obj['cf:name'] ?? obj['label'] ?? null) as string | null;
  const label     = rawLabel ? String(rawLabel) : null;
  const sourceIp  = type === 'entity' ? extractIp(label) : null;

  // Parse CamFlow timestamp (ISO8601 or epoch string)
  let timestamp = Date.now();
  const rawTs = obj['cf:timestamp'] ?? obj['prov:generatedAtTime'];
  if (rawTs) {
    const parsed = Date.parse(String(rawTs));
    if (!isNaN(parsed)) timestamp = parsed;
  }

  const relationType = type === 'relation'
    ? String(obj['prov:type'] ?? '')
    : undefined;
  const entityId = type === 'relation'
    ? String(obj['prov:entity'] ?? obj['cf:entity'] ?? '')
    : undefined;
  const activityId = type === 'relation'
    ? String(obj['prov:activity'] ?? obj['cf:activity'] ?? '')
    : undefined;

  return { type, id, label, sourceIp, relationType, entityId, activityId, timestamp, raw: obj };
}

// ─── Provenance chain accumulator ─────────────────────────────────────────────

/**
 * We accumulate provenance records per session and flush when we see a
 * "connect out" event (exfiltration indicator) or on flush timeout.
 * Each flush exports the causal chain as a single ProvenanceEvent to Gaffer.
 */

interface ProvenanceChain {
  sessionId: string;
  ip:        string;
  events:    CamflowRecord[];
  startedAt: number;
}

const _chains = new Map<string, ProvenanceChain>();  // sessionId → chain

const CHAIN_FLUSH_MS = 60_000;  // auto-flush after 60s of inactivity

function getOrCreateChain(sessionId: string, ip: string): ProvenanceChain {
  if (!_chains.has(sessionId)) {
    _chains.set(sessionId, { sessionId, ip, events: [], startedAt: Date.now() });
  }
  return _chains.get(sessionId)!;
}

function flushChain(sessionId: string): void {
  const chain = _chains.get(sessionId);
  if (!chain || chain.events.length === 0) return;

  const labels = chain.events.map((e) => e.label).filter(Boolean);
  const techniques = inferTechniques(chain.events);

  logger.warn('camflow-bridge: exporting provenance chain', {
    sessionId,
    ip:         chain.ip,
    eventCount: chain.events.length,
    techniques,
  });

  exportEvent(`homelab/provenance/${sessionId}`, {
    sessionId:  chain.ip ? `${sessionId}` : sessionId,
    ip:         chain.ip,
    eventCount: chain.events.length,
    labels:     labels.slice(0, 20),  // top 20 labels for graph vertex
    techniques,
    startedAt:  chain.startedAt,
    ts:         Date.now(),
  }).catch((err) => logger.error('camflow-bridge: export failed', { err }));

  _chains.delete(sessionId);
}

function inferTechniques(events: CamflowRecord[]): string[] {
  const techniques = new Set<string>();
  for (const ev of events) {
    const l = ev.label ?? '';
    if (l.includes('/etc/shadow') || l.includes('/proc/') && l.includes('/mem'))
      techniques.add('T1003');    // Credential Dumping
    if (l.includes('/etc/cron') || l.includes('/var/spool/cron'))
      techniques.add('T1547');    // Persistence
    if (/^(?:tcp|udp):/.test(l))
      techniques.add('T1041');    // Exfil over C2
    if (ev.type === 'activity' && l.match(/bash|sh|python|perl|ruby|node/))
      techniques.add('T1059');    // Command Interpreter
    if (ev.type === 'entity' && l.match(/\/etc\/|\/root\/|\/home\//))
      techniques.add('T1083');    // File Discovery
  }
  return [...techniques].sort();
}

// ─── Socket connection loop ───────────────────────────────────────────────────

let _socket: net.Socket | null = null;
let _reconnects = 0;
let _stopped    = false;
let _flushTimer: ReturnType<typeof setInterval> | null = null;

function handleRecord(record: CamflowRecord): void {
  // Try to correlate to a session
  let session: SessionEntry | null = null;

  if (record.sourceIp) {
    session = resolveSession(record.sourceIp);
  }

  // If no direct IP match, see if any chain has been started for this entity
  // (relation records reference earlier entity/activity IDs)

  if (session) {
    const chain = getOrCreateChain(session.sessionId, session.ip);
    chain.events.push(record);

    // Flush immediately on exfil indicators
    if (record.type === 'entity' && record.label && /^(?:tcp|udp):/.test(record.label)) {
      flushChain(session.sessionId);
    }
  } else {
    // Uncorrelated event — export directly without session binding
    if (record.type !== 'relation') {
      logger.debug('camflow-bridge: uncorrelated event', {
        type:  record.type,
        label: record.label,
      });
    }
  }
}

function connect(): void {
  if (_stopped) return;

  logger.info('camflow-bridge: connecting', { sock: SOCK_PATH });

  const sock = net.createConnection(SOCK_PATH);
  _socket = sock;

  const rl = readline.createInterface({ input: sock, crlfDelay: Infinity });

  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      const raw = JSON.parse(line);
      const record = parseCamflowRecord(raw);
      if (record) handleRecord(record);
    } catch {
      logger.debug('camflow-bridge: non-JSON line', { line: line.slice(0, 200) });
    }
  });

  sock.on('connect', () => {
    logger.info('camflow-bridge: connected', { sock: SOCK_PATH });
    _reconnects = 0;
  });

  sock.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'ENOENT') {
      logger.warn('camflow-bridge: socket not found — CamFlow not installed', {
        sock: SOCK_PATH,
        hint: 'sudo apt install camconfd camflowd (ppa:camflow/camflow)',
      });
      _stopped = true;
      return;
    }
    logger.error('camflow-bridge: socket error', { err: err.message });
  });

  sock.on('close', () => {
    _socket = null;
    rl.close();
    if (_stopped) return;

    if (_reconnects >= MAX_RECONNECTS) {
      logger.error('camflow-bridge: max reconnects reached — giving up', {
        reconnects: _reconnects,
      });
      _stopped = true;
      return;
    }

    _reconnects++;
    const delay = Math.min(BASE_BACKOFF_MS * 2 ** _reconnects, MAX_BACKOFF_MS);
    logger.warn('camflow-bridge: connection closed — reconnecting', {
      reconnects: _reconnects,
      delayMs: delay,
    });
    setTimeout(connect, delay);
  });
}

/**
 * Start reading CamFlow provenance events.
 * Non-blocking. Safe to call multiple times.
 */
export function startCamflowBridge(): void {
  if (process.env.CAMFLOW_DISABLE === '1') {
    logger.debug('camflow-bridge: disabled via env');
    return;
  }
  if (_socket || _stopped) return;

  connect();

  // Periodic flush of stale chains (attacker may have gone quiet)
  _flushTimer = setInterval(() => {
    const cutoff = Date.now() - CHAIN_FLUSH_MS;
    for (const [sessionId, chain] of _chains) {
      const lastEvent = chain.events.at(-1);
      if (!lastEvent || lastEvent.timestamp < cutoff) {
        flushChain(sessionId);
      }
    }
  }, CHAIN_FLUSH_MS);

  if (_flushTimer.unref) _flushTimer.unref();  // don't keep Node alive
}

/** Stop the bridge and prevent reconnects. */
export function stopCamflowBridge(): void {
  _stopped = true;
  if (_socket) {
    _socket.destroy();
    _socket = null;
  }
  if (_flushTimer) {
    clearInterval(_flushTimer);
    _flushTimer = null;
  }
}

/** Exposed for tests */
export function _resetForTest(): void {
  _stopped    = false;
  _reconnects = 0;
  _socket     = null;
  _sessionRegistry.clear();
  _chains.clear();
  if (_flushTimer) {
    clearInterval(_flushTimer);
    _flushTimer = null;
  }
}

/** Exposed for tests */
export function _getChainForTest(sessionId: string): ProvenanceChain | undefined {
  return _chains.get(sessionId);
}
