/**
 * Tests for classifier/signals/behavioral.ts
 *
 * Covers:
 *  - analyzeBehavior() returns correct flags for known patterns
 *  - techniqueIds populated correctly from observed paths
 *  - confidence scoring thresholds
 *  - edge cases (empty requests, single request)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'path';
import { analyzeBehavior } from '../classifier/signals/behavioral.js';
import { loadStixBundle, _resetForTest } from '../classifier/signals/attack-db.js';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

const FIXTURE_PATH = path.resolve(__dirname, 'fixtures/attack-stix-fixture.json');

describe('analyzeBehavior — technique ID integration', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
    loadStixBundle(FIXTURE_PATH);
  });

  afterEach(() => {
    restoreLogger();
  });

  it('returns techniqueIds for scan paths', () => {
    const signal = analyzeBehavior([
      { method: 'GET', path: '/wp-login.php' },
      { method: 'GET', path: '/.env' },
    ]);
    expect(signal.techniqueIds).toContain('T1190');
  });

  it('returns empty techniqueIds for benign paths', () => {
    const signal = analyzeBehavior([
      { method: 'GET', path: '/api/v1/users' },
      { method: 'POST', path: '/api/v1/orders' },
    ]);
    expect(signal.techniqueIds).toHaveLength(0);
  });

  it('deduplicates techniqueIds when multiple paths match same technique', () => {
    const signal = analyzeBehavior([
      { method: 'GET', path: '/wp-login.php' },
      { method: 'GET', path: '/phpmyadmin' },
      { method: 'GET', path: '/admin.php' },
    ]);
    const t1190Occurrences = signal.techniqueIds.filter((id) => id === 'T1190').length;
    expect(t1190Occurrences).toBe(1);
  });

  it('techniqueIds are sorted', () => {
    const signal = analyzeBehavior([
      { method: 'GET', path: '/wp-login.php' }, // T1190
      { method: 'GET', path: '/robots.txt' },   // T1046
      { method: 'GET', path: '/etc/passwd' },   // T1003
    ]);
    expect(signal.techniqueIds).toEqual([...signal.techniqueIds].sort());
  });
});

describe('analyzeBehavior — pattern detection', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
    loadStixBundle(FIXTURE_PATH);
  });

  afterEach(() => {
    restoreLogger();
  });

  it('detects breadth-first pattern', () => {
    // 11 unique top-level paths out of 11 requests → > 0.7 ratio
    const requests = Array.from({ length: 11 }, (_, i) => ({
      method: 'GET',
      path: `/section${i}/index`,
    }));
    const signal = analyzeBehavior(requests);
    expect(signal.breadthFirstPattern).toBe(true);
  });

  it('detects robots.txt follow-up', () => {
    const signal = analyzeBehavior([
      { method: 'GET', path: '/robots.txt' },
      { method: 'GET', path: '/sitemap.xml' },
      { method: 'GET', path: '/api/v1' },
    ]);
    expect(signal.hasRobotsFollowUp).toBe(true);
  });

  it('detects scanner path hits', () => {
    const signal = analyzeBehavior([
      { method: 'GET', path: '/wp-login.php' },
      { method: 'GET', path: '/phpmyadmin/index.php' },
      { method: 'GET', path: '/.env' },
    ]);
    expect(signal.scannerPathHits).toBe(3);
    expect(signal.scannerPathRatio).toBeGreaterThan(0.9);
    expect(signal.confidence).toBeGreaterThanOrEqual(0.8);
  });

  it('returns zero confidence for single benign request', () => {
    const signal = analyzeBehavior([{ method: 'GET', path: '/' }]);
    expect(signal.confidence).toBe(0);
    expect(signal.techniqueIds).toHaveLength(0);
  });

  it('handles empty request array', () => {
    const signal = analyzeBehavior([]);
    expect(signal.confidence).toBe(0);
    expect(signal.scannerPathHits).toBe(0);
    expect(signal.techniqueIds).toHaveLength(0);
    expect(signal.pathsRequested).toHaveLength(0);
  });

  it('high scanner path ratio drives confidence above 0.8', () => {
    const signal = analyzeBehavior([
      { method: 'GET', path: '/wp-login.php' },
      { method: 'GET', path: '/phpmyadmin' },
      { method: 'GET', path: '/.env' },
      { method: 'GET', path: '/shell.php' },
    ]);
    expect(signal.confidence).toBeGreaterThanOrEqual(0.8);
  });
});
