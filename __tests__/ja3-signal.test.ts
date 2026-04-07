/**
 * Tests for classifier/signals/ja3-signal.ts
 *
 * Covers:
 *  - Known-malicious JA3 → confidence 0.95, correct tool name
 *  - Known-malicious JA4 prefix → confidence 0.75
 *  - Unknown JA3 (non-browser) → confidence 0.10 (mild signal)
 *  - Both null → confidence 0, isKnownMalicious false
 *  - Case insensitivity for JA3 hashes
 *  - matchedTool set correctly for JA3 vs JA4
 *  - getBlocklistSize returns non-zero counts
 *  - Test fingerprint injection/removal helpers
 */

import { describe, it, expect, afterEach } from 'vitest';
import {
  analyzeJA3,
  getBlocklistSize,
  _addFingerprintForTest,
  _removeFingerprintForTest,
} from '../classifier/signals/ja3-signal.js';

// A known-malicious hash from the built-in Metasploit list
const METASPLOIT_JA3 = 'fd7c1f7c58f7e35ab9eb31c2b39d5ee7';
const COBALT_STRIKE_JA3 = '72a589da586844d7f0818ce684948eea';
const METASPLOIT_JA4_PREFIX = 't13d190900_';

describe('ja3-signal — null / missing inputs', () => {
  it('both null → confidence 0, not malicious', () => {
    const r = analyzeJA3(null, null);
    expect(r.confidence).toBe(0);
    expect(r.isKnownMalicious).toBe(false);
    expect(r.matchedTool).toBeNull();
  });

  it('empty strings treated same as null', () => {
    const r = analyzeJA3('', '');
    expect(r.confidence).toBe(0);
    expect(r.isKnownMalicious).toBe(false);
  });
});

describe('ja3-signal — known-malicious JA3', () => {
  it('Metasploit JA3 → confidence 0.95', () => {
    const r = analyzeJA3(METASPLOIT_JA3, null);
    expect(r.confidence).toBe(0.95);
    expect(r.isKnownMalicious).toBe(true);
    expect(r.matchedTool).toBe('Metasploit');
    expect(r.ja3Hash).toBe(METASPLOIT_JA3);
  });

  it('Cobalt Strike JA3 → confidence 0.95, tool CobaltStrike', () => {
    const r = analyzeJA3(COBALT_STRIKE_JA3, null);
    expect(r.confidence).toBe(0.95);
    expect(r.matchedTool).toBe('CobaltStrike');
  });

  it('JA3 lookup is case-insensitive', () => {
    const r = analyzeJA3(METASPLOIT_JA3.toUpperCase(), null);
    expect(r.isKnownMalicious).toBe(true);
    expect(r.matchedTool).toBe('Metasploit');
  });

  it('JA3 match takes priority over JA4 prefix', () => {
    const r = analyzeJA3(METASPLOIT_JA3, METASPLOIT_JA4_PREFIX + 'abc_def');
    expect(r.matchedTool).toBe('Metasploit');
    expect(r.confidence).toBe(0.95);
  });
});

describe('ja3-signal — known-malicious JA4', () => {
  it('Metasploit JA4 prefix → confidence 0.75', () => {
    const r = analyzeJA3(null, METASPLOIT_JA4_PREFIX + 'somehash_anotherhash');
    expect(r.confidence).toBe(0.75);
    expect(r.isKnownMalicious).toBe(true);
    expect(r.matchedTool).toBe('Metasploit');
    expect(r.ja4Hash).toContain(METASPLOIT_JA4_PREFIX);
  });

  it('JA4 with non-malicious prefix → confidence 0.10', () => {
    const r = analyzeJA3(null, 't13d010000_aabbcc_ddeeff');
    expect(r.confidence).toBe(0.10);
    expect(r.isKnownMalicious).toBe(false);
    expect(r.matchedTool).toBeNull();
  });
});

describe('ja3-signal — unknown fingerprint (non-browser)', () => {
  it('unknown JA3 → confidence 0.10, not malicious', () => {
    const r = analyzeJA3('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', null);
    expect(r.confidence).toBe(0.10);
    expect(r.isKnownMalicious).toBe(false);
    expect(r.matchedTool).toBeNull();
  });
});

describe('ja3-signal — test helpers', () => {
  afterEach(() => {
    _removeFingerprintForTest('deadbeefdeadbeefdeadbeefdeadbeef');
  });

  it('_addFingerprintForTest makes hash detectable', () => {
    _addFingerprintForTest('deadbeefdeadbeefdeadbeefdeadbeef', 'TestTool');
    const r = analyzeJA3('deadbeefdeadbeefdeadbeefdeadbeef', null);
    expect(r.isKnownMalicious).toBe(true);
    expect(r.matchedTool).toBe('TestTool');
    expect(r.confidence).toBe(0.95);
  });

  it('_removeFingerprintForTest removes hash', () => {
    _addFingerprintForTest('deadbeefdeadbeefdeadbeefdeadbeef', 'TestTool');
    _removeFingerprintForTest('deadbeefdeadbeefdeadbeefdeadbeef');
    const r = analyzeJA3('deadbeefdeadbeefdeadbeefdeadbeef', null);
    expect(r.isKnownMalicious).toBe(false);
  });
});

describe('ja3-signal — blocklist metadata', () => {
  it('getBlocklistSize returns non-zero counts', () => {
    const size = getBlocklistSize();
    expect(size.ja3).toBeGreaterThan(0);
    expect(size.ja4Prefixes).toBeGreaterThan(0);
  });
});
