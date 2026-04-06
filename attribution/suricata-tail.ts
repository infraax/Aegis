/**
 * Suricata EVE JSON Tail Reader
 *
 * Reads Suricata's EVE JSON output (one JSON object per line) and extracts
 * JA3/JA4 TLS fingerprints + alert events, storing them keyed by source IP
 * in a shared in-memory map (or Redis in production).
 *
 * Pattern E: this module runs as a long-lived process alongside the classifier.
 * It feeds data INTO the classifier's Redis-based context, not directly into
 * a request handler — so it enriches future requests, not the current one.
 *
 * Flow:
 *   Suricata → /var/log/suricata/eve.json → this module → Map<ip, JA3Data>
 *   Classifier POST /event → reads JA3Data for the session IP → passes to classify()
 *
 * Graceful degradation:
 *   If the EVE log file doesn't exist (Suricata not running), this module
 *   logs a warning and exits cleanly. The classifier continues without JA3 data.
 *
 * Environment:
 *   SURICATA_EVE_PATH — default /var/log/suricata/eve.json
 *   SURICATA_TAIL_POLL_MS — poll interval in ms, default 500
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';

const EVE_PATH = process.env.SURICATA_EVE_PATH ?? '/var/log/suricata/eve.json';
const POLL_MS  = parseInt(process.env.SURICATA_TAIL_POLL_MS ?? '500', 10);

// ─── In-memory JA3 store ──────────────────────────────────────────────────────
// In production: replace with Redis SETEX with a short TTL (e.g. 60s)

export interface JA3Entry {
  ja3: string | null;
  ja4: string | null;
  sni: string | null;
  seenAt: number;
}

const ja3Store = new Map<string, JA3Entry>();

export function getJA3ForIp(ip: string): JA3Entry | null {
  return ja3Store.get(ip) ?? null;
}

// ─── EVE record types (only the fields we care about) ─────────────────────────

interface EveAlertRecord {
  event_type: 'alert';
  src_ip: string;
  alert: { signature: string; signature_id: number; severity: number; category: string };
  timestamp: string;
}

interface EveTLSRecord {
  event_type: 'tls';
  src_ip: string;
  tls: {
    sni?: string;
    ja3?: { hash: string };
    ja4?: string;
  };
  timestamp: string;
}

type EveRecord = EveAlertRecord | EveTLSRecord | { event_type: string };

// ─── Tail implementation ──────────────────────────────────────────────────────

function processLine(line: string): void {
  if (!line.trim()) return;

  let record: EveRecord;
  try {
    record = JSON.parse(line);
  } catch {
    return; // partial write — skip
  }

  if (record.event_type === 'tls') {
    const tls = record as EveTLSRecord;
    const entry: JA3Entry = {
      ja3: tls.tls.ja3?.hash ?? null,
      ja4: tls.tls.ja4 ?? null,
      sni: tls.tls.sni ?? null,
      seenAt: Date.now(),
    };
    ja3Store.set(tls.src_ip, entry);
    logger.debug('suricata-tail: JA3 recorded', {
      ip: tls.src_ip, ja3: entry.ja3, ja4: entry.ja4, sni: entry.sni,
    });
  }

  if (record.event_type === 'alert') {
    const alert = record as EveAlertRecord;
    logger.warn('suricata-tail: ALERT', {
      ip: alert.src_ip,
      signature: alert.alert.signature,
      sid: alert.alert.signature_id,
      severity: alert.alert.severity,
      category: alert.alert.category,
    });
    // Export to intel graph — same pattern as all other events
    exportEvent(`homelab/threats/suricata/${alert.src_ip}`, {
      ip: alert.src_ip,
      signature: alert.alert.signature,
      sid: alert.alert.signature_id,
      severity: alert.alert.severity,
      category: alert.alert.category,
      ts: Date.now(),
    }).catch((err) => logger.error('suricata-tail: export failed', { err }));
  }
}

/**
 * Start tailing the EVE JSON log.
 * Reads from the current end of the file and processes new lines as they appear.
 * Non-blocking — uses setInterval to poll for new data.
 */
export function startEveTail(): void {
  if (!fs.existsSync(EVE_PATH)) {
    logger.warn('suricata-tail: EVE log not found — JA3 enrichment disabled', {
      path: EVE_PATH,
      hint: 'Start the suricata container: docker compose up -d suricata',
    });
    return;
  }

  let fileSize = fs.statSync(EVE_PATH).size;
  logger.info('suricata-tail: starting EVE tail', { path: EVE_PATH, pollMs: POLL_MS });

  setInterval(() => {
    try {
      const stat = fs.statSync(EVE_PATH);
      if (stat.size <= fileSize) return; // no new data

      const stream = fs.createReadStream(EVE_PATH, {
        start: fileSize,
        end: stat.size - 1,
        encoding: 'utf-8',
      });

      const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
      rl.on('line', processLine);
      rl.on('close', () => { fileSize = stat.size; });
    } catch (err) {
      logger.error('suricata-tail: read error', { err });
    }
  }, POLL_MS);

  // Evict stale JA3 entries every 5 minutes
  setInterval(() => {
    const cutoff = Date.now() - 5 * 60 * 1000;
    for (const [ip, entry] of ja3Store) {
      if (entry.seenAt < cutoff) ja3Store.delete(ip);
    }
  }, 5 * 60 * 1000);
}

/** Exposed for tests */
export function _clearStoreForTest(): void {
  ja3Store.clear();
}

export function _injectEntryForTest(ip: string, entry: JA3Entry): void {
  ja3Store.set(ip, entry);
}
