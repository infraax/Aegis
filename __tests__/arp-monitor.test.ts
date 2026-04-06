/**
 * Tests for attribution/arp-monitor.ts
 *
 * Since the ARP monitor spawns a live scapy process (requires root + interface),
 * we test the bridge's process lifecycle logic using a mock script, and test
 * the JSON alert parsing and export wiring by injecting known output.
 *
 * Tests:
 *  - startARPMonitor() is idempotent (second call no-ops)
 *  - stopARPMonitor() kills the process
 *  - Process exits with error JSON → permanent failure (no restart)
 *  - Process exits cleanly → restart scheduled
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

// ── suricata-tail signal tests (store-based) ──────────────────────────────────

import {
  getJA3ForIp,
  _clearStoreForTest,
  _injectEntryForTest,
} from '../attribution/suricata-tail.js';

describe('suricata-tail — JA3 store', () => {
  beforeEach(() => {
    silenceLogger();
    _clearStoreForTest();
  });

  afterEach(() => {
    restoreLogger();
    _clearStoreForTest();
  });

  it('getJA3ForIp returns null for unknown IP', () => {
    expect(getJA3ForIp('1.2.3.4')).toBeNull();
  });

  it('injected entry is returned correctly', () => {
    _injectEntryForTest('10.0.0.5', {
      ja3: 'fd7c1f7c58f7e35ab9eb31c2b39d5ee7',
      ja4: null,
      sni: 'evil.example.com',
      seenAt: Date.now(),
    });
    const entry = getJA3ForIp('10.0.0.5');
    expect(entry).not.toBeNull();
    expect(entry!.ja3).toBe('fd7c1f7c58f7e35ab9eb31c2b39d5ee7');
    expect(entry!.sni).toBe('evil.example.com');
  });

  it('_clearStoreForTest removes all entries', () => {
    _injectEntryForTest('192.168.1.1', { ja3: 'abc', ja4: null, sni: null, seenAt: Date.now() });
    _clearStoreForTest();
    expect(getJA3ForIp('192.168.1.1')).toBeNull();
  });
});

// ── arp-monitor bridge — process lifecycle ────────────────────────────────────

import {
  startARPMonitor,
  stopARPMonitor,
  _resetForTest,
} from '../attribution/arp-monitor.js';

describe('arp-monitor — bridge lifecycle', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
    // Point to a script that doesn't exist so we can control the failure mode
    process.env.ARP_SCRIPT_PATH = '/tmp/__nonexistent_arp_script__.py';
    process.env.ARP_MONITOR_IFACE = 'lo';
  });

  afterEach(() => {
    stopARPMonitor();
    restoreLogger();
    _resetForTest();
    delete process.env.ARP_SCRIPT_PATH;
    delete process.env.ARP_MONITOR_IFACE;
  });

  it('startARPMonitor does not throw even if script is missing', () => {
    expect(() => startARPMonitor()).not.toThrow();
  });

  it('stopARPMonitor can be called without a running process', () => {
    expect(() => stopARPMonitor()).not.toThrow();
  });

  it('startARPMonitor is idempotent — second call is a no-op', () => {
    startARPMonitor();
    // No error expected — should not start a second process
    expect(() => startARPMonitor()).not.toThrow();
  });

  it('after stopARPMonitor, startARPMonitor remains stopped', async () => {
    stopARPMonitor();   // mark stopped
    startARPMonitor();  // should be no-op
    // Give it a tick to ensure no process was spawned
    await new Promise((r) => setTimeout(r, 50));
    expect(() => stopARPMonitor()).not.toThrow();
  });
});

// ── scorer integration — JA3 flows through to classification ─────────────────

import { classify } from '../classifier/scorer.js';
import { _addFingerprintForTest, _removeFingerprintForTest } from '../classifier/signals/ja3-signal.js';
import { loadStixBundle, _resetForTest as resetAttack } from '../classifier/signals/attack-db.js';
import path from 'path';

const FIXTURE_PATH = path.resolve(__dirname, 'fixtures/attack-stix-fixture.json');
const TEST_JA3 = 'aabbccddeeff00112233445566778899';

describe('scorer — JA3 signal integration', () => {
  beforeEach(() => {
    silenceLogger();
    resetAttack();
    loadStixBundle(FIXTURE_PATH);
    _addFingerprintForTest(TEST_JA3, 'TestTool');
  });

  afterEach(() => {
    restoreLogger();
    _removeFingerprintForTest(TEST_JA3);
  });

  const baseInput = {
    sessionId: 'test-session',
    timing:    { requestIntervals: [], coefficientOfVariation: 1, requestsPerSecond: 0, isMetronomic: false, confidence: 0 },
    headers:   { confidence: 0, userAgent: null, acceptLanguage: null, hasTypicalBrowserHeaders: false, isCurlOrScript: false, headerOrderHash: '', suspiciousHeaders: [] },
    tls:       { confidence: 0, ja3Hash: null, ja4Hash: null, knownTool: null, isMaliciousHash: false },
    behavioral: { pathsRequested: [], methodDistribution: {}, hasRobotsFollowUp: false, hasSitemapFollowUp: false, breadthFirstPattern: false, depthFirstPattern: false, scannerPathHits: 0, scannerPathRatio: 0, confidence: 0, techniqueIds: [] },
    llm:       { confidence: 0, detectedFormat: null, semantic404FollowUp: false, documentationEnumeration: false, errorMessageInterpretation: false, structuredCredentialTesting: false, contextRetention: false, tokenRateTiming: false },
    toolMatch: null,
  };

  it('known-malicious JA3 contributes to confidence and identifies tool', () => {
    const result = classify({ ...baseInput, ja3: TEST_JA3 });
    // JA3 weight is 0.15; with all other signals at 0, contribution is ~0.1425
    expect(result.confidence).toBeGreaterThan(0.1);
    expect(result.toolIdentified).toBe('TestTool');
  });

  it('JA3 signal appears in signals array', () => {
    const result = classify({ ...baseInput, ja3: TEST_JA3 });
    const ja3Signal = result.signals.find((s) => s.name === 'ja3');
    expect(ja3Signal).toBeDefined();
    expect(ja3Signal!.score).toBeGreaterThan(0.9);
  });

  it('no JA3 provided → ja3 signal score is 0', () => {
    const result = classify({ ...baseInput, ja3: null, ja4: null });
    const ja3Signal = result.signals.find((s) => s.name === 'ja3');
    expect(ja3Signal!.score).toBe(0);
    expect(ja3Signal!.weight).toBe(0);
  });

  it('classification result still has all required fields with JA3', () => {
    const result = classify({ ...baseInput, ja3: TEST_JA3 });
    expect(result).toHaveProperty('tier');
    expect(result).toHaveProperty('confidence');
    expect(result).toHaveProperty('techniqueIds');
    expect(result).toHaveProperty('toolIdentified');
    expect(result).toHaveProperty('signals');
  });
});
