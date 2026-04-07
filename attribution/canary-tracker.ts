/**
 * Canary Token Callback Server
 *
 * Receives HTTP callbacks when a canary token fires anywhere in the world
 * (fake AWS key used, fake DNS hostname resolved, canary URL fetched, etc.)
 * and enriches the event with IP intelligence before exporting to GUN.
 */

import express from 'express';
import { lookupASN } from './asn-lookup.js';
import { detectVPN } from './vpn-detector.js';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';

// Simple in-memory rate limiter per source IP: max 10 canary callbacks/minute
const rateLimits = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT = 10;
const RATE_WINDOW_MS = 60_000;

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimits.get(ip);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    rateLimits.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count++;
  if (entry.count > RATE_LIMIT) {
    logger.warn('canary rate limit exceeded', { ip, count: entry.count });
    return true;
  }
  return false;
}

export interface CanaryEvent {
  tokenId: string;
  tokenType: 'credential' | 'document' | 'dns' | 'url' | 'image';
  triggerTime: number;
  sourceIP: string;
  sourcePort: number;
  userAgent: string;
  referer: string;
  headers: Record<string, string>;
  asn: ReturnType<typeof lookupASN> extends Promise<infer T> ? T : never;
  vpnDetected: boolean;
  vpnProvider: string | null;
  sessionCorrelation: string | null;
}

const app = express();
app.use(express.json());

// Generic canary callback endpoint
// Canary tokens embed a unique URL: GET /canary/<tokenId>?type=<type>
app.get('/canary/:tokenId', async (req, res) => {
  const { tokenId } = req.params;
  const tokenType = (req.query['type'] as string) ?? 'url';
  const sourceIP = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim()
    ?? req.socket.remoteAddress
    ?? 'unknown';

  // Return 1x1 GIF immediately — enrichment happens async so attacker doesn't know we're logging
  const gif = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  res.setHeader('Content-Type', 'image/gif');
  res.end(gif);

  if (isRateLimited(sourceIP)) return; // drop silently after response sent

  logger.warn('CANARY FIRED', { tokenId, sourceIP, tokenType });

  const [asn, vpn] = await Promise.all([
    lookupASN(sourceIP),
    detectVPN(sourceIP, null),
  ]);

  const event: Omit<CanaryEvent, 'asn'> & { asn: typeof asn } = {
    tokenId,
    tokenType: tokenType as CanaryEvent['tokenType'],
    triggerTime: Date.now(),
    sourceIP,
    sourcePort: req.socket.remotePort ?? 0,
    userAgent: req.headers['user-agent'] ?? '',
    referer: req.headers['referer'] ?? '',
    headers: req.headers as Record<string, string>,
    asn,
    vpnDetected: vpn.isVPN,
    vpnProvider: vpn.provider,
    sessionCorrelation: (req.query['sid'] as string) ?? null,
  };

  await exportEvent('homelab/alerts/canary/' + tokenId, event);
});

// DNS canary callback (set NS record for your canary domain to point here)
app.get('/dns-canary/:subdomain', (req, res) => {
  const { subdomain } = req.params;
  logger.warn('DNS CANARY FIRED', { subdomain, ip: req.socket.remoteAddress });
  exportEvent('homelab/alerts/canary/dns-' + subdomain, {
    subdomain,
    ip: req.socket.remoteAddress,
    ts: Date.now(),
  }).catch(() => {});
  res.status(204).end();
});

const PORT = parseInt(process.env.CANARY_SERVER_PORT ?? '4444', 10);
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Canary server listening on :${PORT}`);
});
