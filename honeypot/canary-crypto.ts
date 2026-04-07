/**
 * Canary Token Cryptography
 *
 * Generates and verifies HMAC-SHA256 signed canary tokens using Node's
 * built-in crypto module (no external dependencies).
 *
 * Token format (hex encoded, ~80 chars total):
 *   <8-char timestamp prefix> | <16-char session fingerprint> | <32-char HMAC>
 *
 * Properties:
 *   - Unforgeable: HMAC prevents attacker from crafting a valid token
 *   - Self-describing: timestamp + session embedded in token body
 *   - Verifiable: callback handler proves session provenance without a DB lookup
 *   - Graceful degradation: if CANARY_HMAC_KEY is unset, falls back to
 *     a process-scoped ephemeral key (tokens valid only for current process lifetime)
 *
 * Environment:
 *   CANARY_HMAC_KEY — 32+ char hex or passphrase.  Set in .env for persistence
 *                     across restarts so previously-issued tokens remain verifiable.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { logger } from '../shared/logger.js';

// ─── Key management ───────────────────────────────────────────────────────────

/**
 * Resolved once per process.  Ephemeral if env var is absent — tokens issued
 * before a restart will fail verification after restart (acceptable for most
 * honeypot use cases; set CANARY_HMAC_KEY for persistence).
 */
let _key: string | null = null;

function getKey(): string {
  if (_key) return _key;

  const envKey = process.env.CANARY_HMAC_KEY;
  if (envKey && envKey.length >= 32) {
    _key = envKey;
    logger.debug('canary-crypto: using CANARY_HMAC_KEY from environment');
  } else {
    _key = randomBytes(32).toString('hex');
    logger.warn(
      'canary-crypto: CANARY_HMAC_KEY not set or too short — using ephemeral key. ' +
      'Tokens will not survive process restarts.',
    );
  }
  return _key;
}

// ─── Token structure ──────────────────────────────────────────────────────────

export interface CanaryPayload {
  sessionId: string;
  type: string;       // e.g. 'file', 'url', 'credential'
  issuedAt: number;   // Unix ms
}

// ─── Sign ─────────────────────────────────────────────────────────────────────

/**
 * Generate a signed canary token for the given payload.
 *
 * Returns a hex string safe to embed in URLs, filenames, or fake credentials.
 * Format: <hex-encoded JSON payload>.<hex-encoded HMAC-SHA256 signature>
 */
export function signCanaryToken(payload: CanaryPayload): string {
  const body = Buffer.from(JSON.stringify(payload)).toString('hex');
  const sig = createHmac('sha256', getKey())
    .update(body)
    .digest('hex');
  const token = `${body}.${sig}`;
  logger.debug('canary-crypto: token signed', {
    sessionId: payload.sessionId,
    type: payload.type,
    tokenLength: token.length,
  });
  return token;
}

// ─── Verify ───────────────────────────────────────────────────────────────────

export interface VerifyResult {
  valid: boolean;
  payload: CanaryPayload | null;
  reason?: string;
}

/**
 * Verify a canary token on callback.
 *
 * Uses timingSafeEqual to prevent timing-oracle attacks — an attacker who
 * controls a canary URL cannot learn anything by measuring verify time.
 *
 * Returns { valid: true, payload } if the token is genuine.
 * Returns { valid: false, payload: null, reason } otherwise.
 */
export function verifyCanaryToken(token: string): VerifyResult {
  const dotIdx = token.lastIndexOf('.');
  if (dotIdx === -1) {
    return { valid: false, payload: null, reason: 'malformed — missing separator' };
  }

  const body = token.slice(0, dotIdx);
  const receivedSig = token.slice(dotIdx + 1);

  const expectedSig = createHmac('sha256', getKey())
    .update(body)
    .digest('hex');

  // Constant-time comparison
  let sigMatch: boolean;
  try {
    sigMatch = timingSafeEqual(
      Buffer.from(receivedSig, 'hex'),
      Buffer.from(expectedSig, 'hex'),
    );
  } catch {
    // Buffer.from throws if hex string has odd length / invalid chars
    return { valid: false, payload: null, reason: 'malformed — invalid hex in signature' };
  }

  if (!sigMatch) {
    logger.warn('canary-crypto: invalid token — signature mismatch', {
      tokenLength: token.length,
    });
    return { valid: false, payload: null, reason: 'signature mismatch' };
  }

  let payload: CanaryPayload;
  try {
    payload = JSON.parse(Buffer.from(body, 'hex').toString('utf-8'));
  } catch {
    return { valid: false, payload: null, reason: 'malformed — body is not valid JSON' };
  }

  logger.info('canary-crypto: token verified — canary triggered', {
    sessionId: payload.sessionId,
    type: payload.type,
    issuedAt: new Date(payload.issuedAt).toISOString(),
    ageMs: Date.now() - payload.issuedAt,
  });

  return { valid: true, payload };
}

/** Exposed for tests — reset the key so a fresh ephemeral key is generated */
export function _resetKeyForTest(): void {
  _key = null;
}
