/**
 * Tests for honeypot/canary-crypto.ts
 *
 * Covers:
 *  - sign/verify round-trip succeeds for valid token
 *  - tampered signature fails verify
 *  - tampered body fails verify
 *  - malformed tokens return { valid: false }
 *  - payload round-trips exactly (sessionId, type, issuedAt preserved)
 *  - separate key contexts (reset between tests)
 *  - timing-safe comparison path (can't test timing, but test the rejection path)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  signCanaryToken,
  verifyCanaryToken,
  _resetKeyForTest,
  type CanaryPayload,
} from '../honeypot/canary-crypto.js';
import { getOrCreateSession, issueCanaryToken } from '../honeypot/adaptive-engine.js';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

describe('canary-crypto — sign / verify', () => {
  beforeEach(() => {
    silenceLogger();
    _resetKeyForTest();
    // Set a stable key so tokens are predictably verifiable within a test run
    process.env.CANARY_HMAC_KEY = 'test-key-that-is-long-enough-32chars!!';
  });

  afterEach(() => {
    restoreLogger();
    delete process.env.CANARY_HMAC_KEY;
    _resetKeyForTest();
  });

  it('valid token verifies successfully', () => {
    const payload: CanaryPayload = {
      sessionId: 'session-abc',
      type: 'file',
      issuedAt: Date.now(),
    };
    const token = signCanaryToken(payload);
    const result = verifyCanaryToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload).not.toBeNull();
    expect(result.payload!.sessionId).toBe('session-abc');
    expect(result.payload!.type).toBe('file');
  });

  it('payload is preserved exactly through sign/verify', () => {
    const now = Date.now();
    const payload: CanaryPayload = {
      sessionId: 'session-xyz-123',
      type: 'credential',
      issuedAt: now,
    };
    const token = signCanaryToken(payload);
    const result = verifyCanaryToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload!.sessionId).toBe(payload.sessionId);
    expect(result.payload!.type).toBe(payload.type);
    expect(result.payload!.issuedAt).toBe(payload.issuedAt);
  });

  it('tampered signature is rejected', () => {
    const token = signCanaryToken({ sessionId: 's1', type: 'url', issuedAt: Date.now() });
    // Flip a character in the signature (after the last dot)
    const dotIdx = token.lastIndexOf('.');
    const tampered = token.slice(0, dotIdx + 1) + 'aaaa' + token.slice(dotIdx + 5);

    const result = verifyCanaryToken(tampered);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/signature mismatch|malformed/);
  });

  it('tampered body is rejected', () => {
    const token = signCanaryToken({ sessionId: 's1', type: 'url', issuedAt: Date.now() });
    const dotIdx = token.lastIndexOf('.');
    // Corrupt a byte in the body
    const body = token.slice(0, dotIdx);
    const sig = token.slice(dotIdx);
    const tamperedBody = 'ff' + body.slice(2); // change first byte
    const tampered = tamperedBody + sig;

    const result = verifyCanaryToken(tampered);
    expect(result.valid).toBe(false);
  });

  it('returns invalid for empty string', () => {
    const result = verifyCanaryToken('');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('malformed');
  });

  it('returns invalid for token with no separator', () => {
    const result = verifyCanaryToken('deadbeefdeadbeef');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('malformed');
  });

  it('returns invalid for token with invalid hex', () => {
    const result = verifyCanaryToken('zzzz.zzzz');
    expect(result.valid).toBe(false);
  });

  it('two different sessions produce different tokens', () => {
    const t1 = signCanaryToken({ sessionId: 'session-A', type: 'file', issuedAt: 1000 });
    const t2 = signCanaryToken({ sessionId: 'session-B', type: 'file', issuedAt: 1000 });
    expect(t1).not.toBe(t2);
  });

  it('ephemeral key mode: token signed with one key fails with a different key', () => {
    // Sign with first key
    process.env.CANARY_HMAC_KEY = 'first-key-that-is-long-enough-32chars!!';
    _resetKeyForTest();
    const token = signCanaryToken({ sessionId: 'sess', type: 'x', issuedAt: 0 });

    // Rotate key
    process.env.CANARY_HMAC_KEY = 'second-key-different-value-32chars!!!';
    _resetKeyForTest();
    const result = verifyCanaryToken(token);
    expect(result.valid).toBe(false);
  });
});

describe('canary-crypto — adaptive engine integration', () => {
  beforeEach(() => {
    silenceLogger();
    _resetKeyForTest();
    process.env.CANARY_HMAC_KEY = 'test-key-that-is-long-enough-32chars!!';
  });

  afterEach(() => {
    restoreLogger();
    delete process.env.CANARY_HMAC_KEY;
    _resetKeyForTest();
  });

  it('issued token can be verified on callback', () => {
    // Simulates the full flow: engine issues token → attacker uses URL → callback verifies
    const session = getOrCreateSession('test-session-999', 'AutoGPT');
    const token = issueCanaryToken(session, 'url');

    expect(token.length).toBeGreaterThan(40); // should be a hex string, not a UUID

    const result = verifyCanaryToken(token);
    expect(result.valid).toBe(true);
    expect(result.payload!.sessionId).toBe('test-session-999');
    expect(result.payload!.type).toBe('url');
  });
});
