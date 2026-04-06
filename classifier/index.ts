/**
 * Aegis Classifier Service
 *
 * Listens on an internal port for session metadata forwarded from the
 * deception-interface proxy (nginx/envoy), runs all signals, and routes
 * the session to the appropriate tier handler via the Tier Router.
 *
 * Traffic flow:
 *   deception-if → proxy → classifier (:9000) → tier-router → tarpit|honeypot|escalate
 */

import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import 'dotenv/config';

import { analyzeTimings } from './signals/timing.js';
import { analyzeHeaders } from './signals/headers.js';
import { analyzeTLS } from './signals/tls.js';
import { analyzeBehavior } from './signals/behavioral.js';
import { analyzeLLMSignals } from './signals/llm-detector.js';
import { matchToolSignature } from './signals/tool-sigs.js';
import { loadStixBundle } from './signals/attack-db.js';
import { classify } from './scorer.js';
import { route } from '../router/tier-router.js';
import { startEveTail, getJA3ForIp } from '../attribution/suricata-tail.js';
import { startTetragonEvents } from '../attribution/tetragon-events.js';
import { logger } from '../shared/logger.js';

// Load ATT&CK STIX bundle once at startup — non-fatal if bundle absent
loadStixBundle();

// Start Suricata EVE tail for JA3/JA4 enrichment — non-fatal if Suricata absent
startEveTail();

// Start Tetragon eBPF event bridge — non-fatal if Tetragon not installed
startTetragonEvents();

const app = express();
app.use(express.json());

// Session state (in-memory; replace with Redis for multi-process)
const sessions = new Map<string, SessionState>();

const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes — evict idle sessions

interface SessionState {
  id: string;
  ip: string;
  timestamps: number[];
  requests: Array<{ method: string; path: string }>;
  requestDelays: number[];
  responsesActedOn: Array<{ responseSnippet: string; followUpPath: string }>;
  headers: Record<string, string>;
  ja3: string | null;
  ja4: string | null;
  lastSeen: number;
  tier: 1 | 2 | 3 | null;    // cached classification — only route once per tier change
  routedAt: number | null;    // last time we called route()
}

// Periodic session eviction to prevent unbounded memory growth
setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, s] of sessions) {
    if (s.lastSeen < cutoff) sessions.delete(id);
  }
}, 5 * 60 * 1000);

app.post('/event', (req, res) => {
  const { sessionId: existingId, ip, method, path, headers, ja3, ja4, delayMs, responseSnippet } =
    req.body as {
      sessionId?: string;
      ip: string;
      method: string;
      path: string;
      headers: Record<string, string>;
      ja3?: string;   // from body OR extracted from X-Aegis-JA3 header below
      ja4?: string;   // from body OR extracted from X-Aegis-JA4 header below
      delayMs?: number;
      responseSnippet?: string;
    };

  // Resolve JA3/JA4: body fields > proxy-injected headers > Suricata EVE store (by IP)
  const eveEntry = getJA3ForIp(ip);
  const resolvedJa3 = ja3 ?? headers['x-aegis-ja3'] ?? eveEntry?.ja3 ?? null;
  const resolvedJa4 = ja4 ?? headers['x-aegis-ja4'] ?? eveEntry?.ja4 ?? null;

  const sessionId = existingId ?? uuidv4();
  const now = Date.now();

  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {
      id: sessionId,
      ip,
      timestamps: [],
      requests: [],
      requestDelays: [],
      responsesActedOn: [],
      headers,
      ja3: ja3 ?? null,
      ja4: ja4 ?? null,
      lastSeen: now,
      tier: null,
      routedAt: null,
    });
  }

  const s = sessions.get(sessionId)!;
  s.timestamps.push(now);
  s.requests.push({ method, path });
  if (delayMs !== undefined) s.requestDelays.push(delayMs);
  if (responseSnippet) s.responsesActedOn.push({ responseSnippet, followUpPath: path });
  s.lastSeen = now;

  // Run classification after we have at least 2 events
  if (s.timestamps.length >= 2) {
    const timing = analyzeTimings(s.timestamps);
    const headerSig = analyzeHeaders(s.headers);
    const tls = analyzeTLS(s.ja3, s.ja4);
    const behavioral = analyzeBehavior(s.requests);
    const llm = analyzeLLMSignals({
      requestDelays: s.requestDelays,
      paths: s.requests.map((r) => r.path),
      responsesActedOn: s.responsesActedOn,
    });
    const toolMatch = matchToolSignature(s.headers['user-agent'] ?? '', s.headers);

    const classification = classify({ sessionId, timing, headers: headerSig, tls, behavioral, llm, toolMatch, ja3: resolvedJa3, ja4: resolvedJa4 });

    logger.info('classified', { sessionId, ip, tier: classification.tier, confidence: classification.confidence, tool: classification.toolIdentified });

    // Only route when tier changes (or on first classification) — prevent routing spam
    if (classification.tier !== s.tier) {
      s.tier = classification.tier;
      s.routedAt = now;
      route(classification, { ip, sessionId }).catch((err) =>
        logger.error('routing error', { err }),
      );
    }

    res.json({
      sessionId,
      tier: classification.tier,
      confidence: classification.confidence,
      techniqueIds: classification.techniqueIds,
    });
  } else {
    res.json({ sessionId, tier: null, confidence: 0 });
  }
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

const PORT = parseInt(process.env.CLASSIFIER_PORT ?? '9000', 10);
app.listen(PORT, '127.0.0.1', () => {
  logger.info(`Aegis classifier listening on 127.0.0.1:${PORT}`);
});
