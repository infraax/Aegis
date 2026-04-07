/**
 * Adaptive Honeypot Engine
 *
 * Watches a Tier 2 session's behaviour in real-time and modifies what the
 * fake services serve — ensuring the deception deepens the longer the
 * agent stays engaged.
 */

import { v4 as uuidv4 } from 'uuid';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { signCanaryToken } from './canary-crypto.js';
import { logger } from '../shared/logger.js';

export interface BehaviorEvent {
  type:
    | 'endpoint_enum'
    | 'credential_found'
    | 'file_read'
    | 'sqli_probe'
    | 'rce_probe'
    | 'port_scan';
  detail: string;
  timestamp: number;
}

export interface AdaptiveSession {
  sessionId: string;
  tier: 2;
  toolIdentified: string | null;
  behaviorSequence: BehaviorEvent[];
  currentDepth: number;           // how deep in the fake infra (0 = surface)
  canaryTokensExposed: string[];  // canary IDs shown to this session
  contextBombsServed: string[];   // which injection files served
  startedAt: number;
  lastEventAt: number;
}

const sessions = new Map<string, AdaptiveSession>();

export function getOrCreateSession(sessionId: string, tool: string | null): AdaptiveSession {
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {
      sessionId,
      tier: 2,
      toolIdentified: tool,
      behaviorSequence: [],
      currentDepth: 0,
      canaryTokensExposed: [],
      contextBombsServed: [],
      startedAt: Date.now(),
      lastEventAt: Date.now(),
    });
  }
  return sessions.get(sessionId)!;
}

export async function recordEvent(sessionId: string, event: BehaviorEvent): Promise<void> {
  const s = getOrCreateSession(sessionId, null);
  s.behaviorSequence.push(event);
  s.lastEventAt = event.timestamp;

  const durationMinutes = (Date.now() - s.startedAt) / 60_000;

  // Increase depth as engagement grows
  if (durationMinutes > 1 && s.currentDepth < 1) s.currentDepth = 1;
  if (durationMinutes > 5 && s.currentDepth < 2) {
    s.currentDepth = 2;
    logger.info('agent highly engaged — serving deep fake infrastructure', { sessionId });
    await exportEvent('homelab/threats/sessions/' + sessionId, { depth: 2, sessionId });
  }
  if (durationMinutes > 10 && s.currentDepth < 3) {
    s.currentDepth = 3;
    logger.info('agent at maximum depth — generating fake pivot target', { sessionId });
  }
}

export function selectContextBomb(session: AdaptiveSession): string {
  // Return path to a context bomb not yet served to this session
  const bombs = [
    'env-file.txt',
    'readme-internal.md',
    'api-spec.json',
    'deploy-keys.txt',
    'backup-creds.json',
  ];
  const unserved = bombs.filter((b) => !session.contextBombsServed.includes(b));
  if (unserved.length === 0) return bombs[0]; // cycle
  const chosen = unserved[0];
  session.contextBombsServed.push(chosen);
  return chosen;
}

export function issueCanaryToken(session: AdaptiveSession, type: string): string {
  const token = signCanaryToken({
    sessionId: session.sessionId,
    type,
    issuedAt: Date.now(),
  });
  session.canaryTokensExposed.push(token);
  logger.info('canary token issued', {
    sessionId: session.sessionId,
    type,
    tokenLength: token.length,
  });
  return token;
}
