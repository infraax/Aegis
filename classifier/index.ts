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
import { startCamflowBridge, registerSession } from '../attribution/camflow-bridge.js';
import { startWazuhBridge } from '../attribution/wazuh-bridge.js';
import { startDNSMonitor } from '../attribution/dns-monitor.js';
import { startProcessNetMonitor } from '../attribution/process-net-monitor.js';
import { analyzeAIAgentSignals } from './signals/ai-agent-detector.js';
import { isTrapTriggered } from '../honeypot/prompt-injection-traps.js';
import { logger } from '../shared/logger.js';

// Load ATT&CK STIX bundle once at startup — non-fatal if bundle absent
loadStixBundle();

// Start Suricata EVE tail for JA3/JA4 enrichment — non-fatal if Suricata absent
startEveTail();

// Start Tetragon eBPF event bridge — non-fatal if Tetragon not installed
startTetragonEvents();

// Start CamFlow provenance bridge — non-fatal if CamFlow not installed
startCamflowBridge();

// Start Wazuh HIDS alert bridge — non-fatal if Wazuh not running
startWazuhBridge();

// Start DNS anomaly monitor — non-fatal if scapy not installed
startDNSMonitor();

// Start process-to-network attribution monitor — non-fatal if psutil not installed
startProcessNetMonitor();

const app = express();
app.use(express.json());

// Session state (in-memory; replace with Redis for multi-process)
const sessions = new Map<string, SessionState>();

const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes — evict idle sessions

interface SessionState {
  id: string;
  ip: string;
  timestamps: number[];
  requests: Array<{ method: string; path: string; headers?: Record<string, string> }>;
  requestDelays: number[];
  responsesActedOn: Array<{ responseSnippet: string; followUpPath: string }>;
  payloads: string[];           // request body snippets for prompt injection detection
  headers: Record<string, string>;
  ja3: string | null;
  ja4: string | null;
  canaryTriggered: boolean;     // set true when a trap fires
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
  const { sessionId: existingId, ip, method, path, headers, ja3, ja4, delayMs, responseSnippet, payload } =
    req.body as {
      sessionId?: string;
      ip: string;
      method: string;
      path: string;
      headers: Record<string, string>;
      ja3?: string;
      ja4?: string;
      delayMs?: number;
      responseSnippet?: string;
      payload?: string;         // request body snippet for prompt injection detection
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
      payloads: [],
      headers,
      ja3: ja3 ?? null,
      ja4: ja4 ?? null,
      canaryTriggered: false,
      lastSeen: now,
      tier: null,
      routedAt: null,
    });
  }

  const s = sessions.get(sessionId)!;
  s.timestamps.push(now);
  s.requests.push({ method, path, headers });
  if (delayMs !== undefined) s.requestDelays.push(delayMs);
  if (responseSnippet) s.responsesActedOn.push({ responseSnippet, followUpPath: path });
  if (payload) s.payloads.push(payload.slice(0, 500));
  s.lastSeen = now;

  // Check for prompt injection trap trigger
  const trap = isTrapTriggered(path, headers, sessionId);
  if (trap) {
    s.canaryTriggered = true;
    logger.warn('classifier: AI agent trap triggered', {
      sessionId, ip, trapType: trap.trapType,
    });
  }

  // Run classification after we have at least 2 events
  if (s.timestamps.length >= 2) {
    const timing     = analyzeTimings(s.timestamps);
    const headerSig  = analyzeHeaders(s.headers);
    const tls        = analyzeTLS(s.ja3, s.ja4);
    const behavioral = analyzeBehavior(s.requests);

    // AI agent signal — runs in parallel with base LLM signal
    const aiAgent = analyzeAIAgentSignals({
      requestDelays:  s.requestDelays,
      requests:       s.requests.map((r) => ({
        method:  r.method,
        path:    r.path,
        headers: r.headers ?? {},
      })),
      pathsRequested: s.requests.map((r) => r.path),
      payloads:       s.payloads,
      canaryTriggered: s.canaryTriggered,
      userAgent:      s.headers['user-agent'] ?? '',
    });

    const baseLLM = analyzeLLMSignals({
      requestDelays:    s.requestDelays,
      paths:            s.requests.map((r) => r.path),
      responsesActedOn: s.responsesActedOn,
    });

    // Merge: take max confidence, prefer AI agent's framework detection
    const llm = {
      ...baseLLM,
      confidence:     Math.min(1, Math.max(baseLLM.confidence, aiAgent.confidence)),
      detectedFormat: aiAgent.detectedFramework ?? baseLLM.detectedFormat,
    };

    const toolMatch = matchToolSignature(s.headers['user-agent'] ?? '', s.headers);

    const classification = classify({
      sessionId, timing, headers: headerSig, tls, behavioral, llm, toolMatch,
      ja3: resolvedJa3, ja4: resolvedJa4,
    });

    logger.info('classified', {
      sessionId, ip,
      tier:       classification.tier,
      confidence: classification.confidence,
      tool:       classification.toolIdentified,
      aiAgent:    aiAgent.confidence > 0.3 ? aiAgent.confidence.toFixed(2) : undefined,
    });

    // Only route when tier changes (or on first classification) — prevent routing spam
    if (classification.tier !== s.tier) {
      s.tier = classification.tier;
      s.routedAt = now;
      // Register with CamFlow bridge for provenance correlation
      registerSession(sessionId, ip, classification.tier);
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
