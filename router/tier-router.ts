/**
 * Tier Router — dispatches a classified session to the correct response system.
 *
 * Tier 1 (scanner):       → tarpit
 * Tier 2 (AI agent):      → adaptive honeypot
 * Tier 3 (targeted/human):→ immediate escalation alert
 */

import type { Classification } from '../classifier/scorer.js';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { triggerHunt } from './velociraptor-client.js';
import { logger } from '../shared/logger.js';

export async function route(
  classification: Classification,
  meta: { ip: string; sessionId: string },
): Promise<void> {
  const { tier, confidence, toolIdentified, techniqueIds } = classification;
  const { ip, sessionId } = meta;

  const base = { ip, sessionId, tier, confidence, tool: toolIdentified, techniqueIds, ts: Date.now() };

  switch (tier) {
    case 1:
      logger.info('routing to tarpit', base);
      // Signal to the nginx/proxy layer to forward this client to the tarpit upstream.
      // The actual tarpit (endlessh / http-tarpit) is always running; routing is done
      // by writing the decision to a shared Redis key read by the proxy config.
      await markDestination(sessionId, 'tarpit');
      await exportEvent('homelab/threats/tarpits/' + ip, base);
      break;

    case 2:
      logger.info('routing to adaptive honeypot', base);
      await markDestination(sessionId, 'honeypot');
      await exportEvent('homelab/threats/sessions/' + sessionId, base);
      break;

    case 3:
      logger.warn('TIER 3 — escalating to human operator', base);
      await markDestination(sessionId, 'escalate');
      await exportEvent('homelab/alerts/security/tier3-' + sessionId, {
        ...base,
        alert: 'POTENTIAL TARGETED ATTACKER — human review required',
      });
      // Fire Velociraptor hunt — collect forensics before the attacker cleans up.
      // Non-blocking relative to the alert: if Velociraptor is down the alert
      // still fires; hunt result is exported as a linked sub-event.
      triggerHunt(ip, sessionId, techniqueIds).then(async (hunt) => {
        if (!hunt.skipped) {
          await exportEvent('homelab/alerts/security/tier3-' + sessionId + '/hunt', {
            huntId: hunt.huntId,
            huntUrl: hunt.huntUrl,
            artifacts: hunt.artifacts,
            ts: Date.now(),
          });
          logger.warn('TIER 3 — forensic hunt started', {
            sessionId, ip, huntId: hunt.huntId, huntUrl: hunt.huntUrl,
          });
        }
      }).catch((err) => logger.error('tier-router: hunt dispatch failed', { err, sessionId }));
      break;
  }
}

async function markDestination(sessionId: string, dest: 'tarpit' | 'honeypot' | 'escalate'): Promise<void> {
  // In production: write to Redis → read by proxy (nginx lua / envoy ext-proc)
  // For local dev: log only
  logger.debug('destination marked', { sessionId, dest });
}
