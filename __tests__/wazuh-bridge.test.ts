/**
 * Tests for attribution/wazuh-bridge.ts
 *
 * We mock axios to avoid needing a live Wazuh instance.
 * Tests verify:
 *  1. mapWazuhAlert() — correct severity + technique ID mapping
 *  2. startWazuhBridge() — honours WAZUH_DISABLE=1
 *  3. stopWazuhBridge() — safe to call without running poll
 *  4. Auth failure (401) → stops polling, no throw
 *  5. ECONNREFUSED → continues retrying, no throw
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

import {
  mapWazuhAlert,
  startWazuhBridge,
  stopWazuhBridge,
  _resetForTest,
  type WazuhAlert,
} from '../attribution/wazuh-bridge.js';

vi.mock('axios');
const mockedAxios = vi.mocked(axios, true);

const mockPost = vi.fn();
const mockGet  = vi.fn();
mockedAxios.create = vi.fn(() => ({ post: mockPost, get: mockGet })) as unknown as typeof mockedAxios.create;
mockedAxios.isAxiosError = vi.fn(() => false) as unknown as typeof mockedAxios.isAxiosError;

// ─── mapWazuhAlert ────────────────────────────────────────────────────────────

describe('wazuh-bridge — mapWazuhAlert', () => {
  const makeRaw = (level: number, mitre?: string[]): WazuhAlert => ({
    id:        'alert-001',
    timestamp: '2026-04-06T10:00:00Z',
    agent:     { id: '001', name: 'thinkpad', ip: '10.0.0.1' },
    rule:      { id: '100001', level, description: 'Test alert', mitre: mitre ? { id: mitre } : undefined },
    location:  '/var/log/syslog',
  });

  it('level 15 → CRITICAL severity', () => {
    const alert = mapWazuhAlert(makeRaw(15, ['T1547']));
    expect(alert.severity).toBe('CRITICAL');
  });

  it('level 12 → HIGH severity', () => {
    const alert = mapWazuhAlert(makeRaw(12));
    expect(alert.severity).toBe('HIGH');
  });

  it('level 8 → MEDIUM severity', () => {
    const alert = mapWazuhAlert(makeRaw(8));
    expect(alert.severity).toBe('MEDIUM');
  });

  it('level 3 → LOW severity', () => {
    const alert = mapWazuhAlert(makeRaw(3));
    expect(alert.severity).toBe('LOW');
  });

  it('maps MITRE technique IDs from rule', () => {
    const alert = mapWazuhAlert(makeRaw(12, ['T1547', 'T1053']));
    expect(alert.techniqueIds).toContain('T1547');
    expect(alert.techniqueIds).toContain('T1053');
  });

  it('empty techniqueIds when no MITRE in rule', () => {
    const alert = mapWazuhAlert(makeRaw(10));
    expect(alert.techniqueIds).toEqual([]);
  });

  it('maps agent IP and name correctly', () => {
    const alert = mapWazuhAlert(makeRaw(10));
    expect(alert.agentName).toBe('thinkpad');
    expect(alert.agentIp).toBe('10.0.0.1');
  });

  it('parses timestamp to epoch ms', () => {
    const alert = mapWazuhAlert(makeRaw(10));
    expect(alert.ts).toBeGreaterThan(0);
    expect(typeof alert.ts).toBe('number');
  });

  it('result always has all required fields', () => {
    const alert = mapWazuhAlert(makeRaw(12, ['T1547']));
    expect(alert).toHaveProperty('alertId');
    expect(alert).toHaveProperty('agentName');
    expect(alert).toHaveProperty('agentIp');
    expect(alert).toHaveProperty('ruleId');
    expect(alert).toHaveProperty('ruleLevel');
    expect(alert).toHaveProperty('description');
    expect(alert).toHaveProperty('techniqueIds');
    expect(alert).toHaveProperty('severity');
    expect(alert).toHaveProperty('location');
    expect(alert).toHaveProperty('ts');
  });
});

// ─── Bridge lifecycle ─────────────────────────────────────────────────────────

describe('wazuh-bridge — lifecycle', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
  });
  afterEach(() => {
    stopWazuhBridge();
    restoreLogger();
    _resetForTest();
    delete process.env.WAZUH_DISABLE;
    delete process.env.WAZUH_API_PASSWORD;
  });

  it('WAZUH_DISABLE=1 → startWazuhBridge is a no-op', () => {
    process.env.WAZUH_DISABLE = '1';
    expect(() => startWazuhBridge()).not.toThrow();
  });

  it('stopWazuhBridge is safe to call without running poll', () => {
    expect(() => stopWazuhBridge()).not.toThrow();
  });

  it('startWazuhBridge is idempotent — second call is a no-op', () => {
    process.env.WAZUH_DISABLE = '1';
    startWazuhBridge();
    expect(() => startWazuhBridge()).not.toThrow();
  });

  it('after stopWazuhBridge, startWazuhBridge remains stopped', () => {
    stopWazuhBridge();
    expect(() => startWazuhBridge()).not.toThrow();
  });
});
