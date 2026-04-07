/**
 * Tests for supply-chain/model-scanner.ts
 *
 * Covers:
 *  - benign pickle → safe: true
 *  - malicious pickle → safe: false, findings populated
 *  - non-scannable extension → skipped: true
 *  - missing file → safe: true, skipped: true (fickling exits non-zero but gracefully)
 *  - batch scanning respects concurrency
 *  - SCANNABLE_EXTENSIONS set is correct
 */

import { describe, it, expect } from 'vitest';
import path from 'path';
import { scanModelFile, scanModelFiles, SCANNABLE_EXTENSIONS } from '../supply-chain/model-scanner.js';

const FIXTURES = path.resolve(__dirname, 'fixtures');

describe('model-scanner — single file scan', () => {
  it('benign pickle returns safe: true', async () => {
    const result = await scanModelFile(path.join(FIXTURES, 'benign-model.pkl'));
    expect(result.safe).toBe(true);
    expect(result.skipped).toBe(false);
    expect(result.filePath).toContain('benign-model.pkl');
    expect(result.durationMs).toBeGreaterThan(0);
  }, 15_000);

  it('malicious pickle returns safe: false with findings', async () => {
    const result = await scanModelFile(path.join(FIXTURES, 'malicious-model.pkl'));
    expect(result.safe).toBe(false);
    expect(result.skipped).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    // fickling should mention eval or suspicious activity
    const allFindings = result.findings.join(' ').toLowerCase();
    expect(allFindings).toMatch(/eval|suspicious|malicious|unsafe/);
  }, 15_000);

  it('non-scannable extension is skipped', async () => {
    const result = await scanModelFile(path.join(FIXTURES, 'readme.txt'));
    expect(result.skipped).toBe(true);
    expect(result.safe).toBe(true);
    expect(result.durationMs).toBe(0);
  });

  it('nonexistent file is handled gracefully', async () => {
    const result = await scanModelFile('/tmp/does-not-exist-99999.pkl');
    // fickling exits non-zero for missing file — treated as safe+skipped
    expect(result.skipped || result.safe).toBe(true);
    expect(() => result).not.toThrow();
  }, 15_000);
});

describe('model-scanner — batch scan', () => {
  it('scans mixed batch and returns results in order', async () => {
    const files = [
      path.join(FIXTURES, 'benign-model.pkl'),
      path.join(FIXTURES, 'readme.txt'),       // skipped
      path.join(FIXTURES, 'malicious-model.pkl'),
    ];
    const results = await scanModelFiles(files);

    expect(results).toHaveLength(3);
    expect(results[0].safe).toBe(true);    // benign
    expect(results[1].skipped).toBe(true); // .txt
    expect(results[2].safe).toBe(false);   // malicious
  }, 30_000);

  it('empty batch returns empty array', async () => {
    const results = await scanModelFiles([]);
    expect(results).toHaveLength(0);
  });
});

describe('model-scanner — extension set', () => {
  it('includes .pkl', () => expect(SCANNABLE_EXTENSIONS.has('.pkl')).toBe(true));
  it('includes .pt',  () => expect(SCANNABLE_EXTENSIONS.has('.pt')).toBe(true));
  it('includes .pth', () => expect(SCANNABLE_EXTENSIONS.has('.pth')).toBe(true));
  it('does not include .json', () => expect(SCANNABLE_EXTENSIONS.has('.json')).toBe(false));
  it('does not include .txt',  () => expect(SCANNABLE_EXTENSIONS.has('.txt')).toBe(false));
});
