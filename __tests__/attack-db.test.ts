/**
 * Tests for classifier/signals/attack-db.ts
 *
 * Covers:
 *  - loadStixBundle() with a known fixture
 *  - resolveTechniques() returns correct names
 *  - lookupTechniquesForPaths() maps paths to expected technique IDs
 *  - graceful no-op when bundle file is missing
 *  - deduplication and deterministic ordering
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'path';
import {
  loadStixBundle,
  resolveTechniques,
  lookupTechniquesForPaths,
  _resetForTest,
} from '../classifier/signals/attack-db.js';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

const FIXTURE_PATH = path.resolve(__dirname, 'fixtures/attack-stix-fixture.json');

describe('attack-db — STIX bundle loader', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
  });

  afterEach(() => {
    restoreLogger();
  });

  it('loads technique index from fixture', () => {
    loadStixBundle(FIXTURE_PATH);
    const resolved = resolveTechniques(['T1190']);
    expect(resolved).toHaveLength(1);
    expect(resolved[0].id).toBe('T1190');
    expect(resolved[0].name).toBe('Exploit Public-Facing Application');
  });

  it('resolves multiple known technique IDs', () => {
    loadStixBundle(FIXTURE_PATH);
    const resolved = resolveTechniques(['T1046', 'T1110', 'T1003']);
    expect(resolved).toHaveLength(3);
    const ids = resolved.map((t) => t.id);
    expect(ids).toContain('T1046');
    expect(ids).toContain('T1110');
    expect(ids).toContain('T1003');
  });

  it('returns stub for unknown technique ID (graceful fallback)', () => {
    loadStixBundle(FIXTURE_PATH);
    const resolved = resolveTechniques(['T9999']);
    expect(resolved).toHaveLength(1);
    expect(resolved[0].id).toBe('T9999');
    expect(resolved[0].name).toContain('Unknown');
  });

  it('is a no-op if bundle file does not exist', () => {
    // Should not throw, should log warn (silenced) and continue
    expect(() => loadStixBundle('/nonexistent/path/bundle.json')).not.toThrow();
  });

  it('second loadStixBundle() call is a no-op (idempotent)', () => {
    loadStixBundle(FIXTURE_PATH);
    const first = resolveTechniques(['T1190']);

    // Reset loaded flag but NOT the index — second call should be no-op
    loadStixBundle(FIXTURE_PATH); // should not re-parse or clear index
    const second = resolveTechniques(['T1190']);
    expect(second[0].name).toBe(first[0].name);
  });
});

describe('attack-db — path-to-technique mapping', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
    loadStixBundle(FIXTURE_PATH);
  });

  afterEach(() => {
    restoreLogger();
  });

  it('maps wp-login.php to T1190', () => {
    const ids = lookupTechniquesForPaths(['/wp-login.php']);
    expect(ids).toContain('T1190');
  });

  it('maps /etc/passwd to T1003', () => {
    const ids = lookupTechniquesForPaths(['/etc/passwd']);
    expect(ids).toContain('T1003');
  });

  it('maps /robots.txt to T1046', () => {
    const ids = lookupTechniquesForPaths(['/robots.txt']);
    expect(ids).toContain('T1046');
  });

  it('maps /login to T1110 (brute force)', () => {
    const ids = lookupTechniquesForPaths(['/login']);
    expect(ids).toContain('T1110');
  });

  it('deduplicates technique IDs across multiple matching paths', () => {
    // Both /wp-login.php and /admin.php map to T1190 — should appear once
    const ids = lookupTechniquesForPaths(['/wp-login.php', '/admin.php']);
    const t1190Count = ids.filter((id) => id === 'T1190').length;
    expect(t1190Count).toBe(1);
  });

  it('returns sorted IDs for deterministic output', () => {
    const ids = lookupTechniquesForPaths([
      '/wp-login.php',   // T1190
      '/robots.txt',     // T1046
      '/etc/passwd',     // T1003
    ]);
    expect(ids).toEqual([...ids].sort());
  });

  it('returns empty array for benign paths', () => {
    const ids = lookupTechniquesForPaths(['/api/v1/users', '/health', '/']);
    expect(ids).toHaveLength(0);
  });

  it('handles empty path array', () => {
    const ids = lookupTechniquesForPaths([]);
    expect(ids).toHaveLength(0);
  });

  it('mixed scan session maps to multiple distinct techniques', () => {
    const ids = lookupTechniquesForPaths([
      '/wp-login.php',  // T1190
      '/robots.txt',    // T1046
      '/login',         // T1110
      '/etc/passwd',    // T1003
      '/.git/',         // T1083
    ]);
    expect(ids).toContain('T1190');
    expect(ids).toContain('T1046');
    expect(ids).toContain('T1110');
    expect(ids).toContain('T1003');
    expect(ids).toContain('T1083');
  });
});
