/**
 * Tests for intel-export/gaffer-exporter.ts
 *
 * We mock axios to avoid needing a live Gaffer instance.
 * Tests verify:
 *  1. buildElements-level logic via exportEvent's behaviour
 *  2. Session namespace → entities + edges (correct element groups)
 *  3. Tetragon namespace → TetragonEvent entity
 *  4. ARP namespace → ARPEvent entity + IPAddress entity + edge
 *  5. ECONNREFUSED → skipped silently (no throw)
 *  6. querySessionsByIp — returns session IDs from edge responses
 *  7. isGafferReachable — returns true/false based on /status response
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

import {
  exportEvent,
  querySessionsByIp,
  isGafferReachable,
  _resetClientForTest,
  type GafferElement,
} from '../intel-export/gaffer-exporter.js';

vi.mock('axios');
const mockedAxios = vi.mocked(axios, true);

// Build a fake axios instance to intercept calls
const mockPost = vi.fn();
const mockGet  = vi.fn();
const mockCreate = vi.fn(() => ({ post: mockPost, get: mockGet }));

beforeEach(() => {
  silenceLogger();
  _resetClientForTest();
  vi.resetAllMocks();
  mockedAxios.create = mockCreate as unknown as typeof mockedAxios.create;
  // Default: successful POST
  mockPost.mockResolvedValue({ data: {} });
  mockGet.mockResolvedValue({ data: { status: 'UP' } });
});

afterEach(() => {
  restoreLogger();
  _resetClientForTest();
});

// ─── Session namespace ────────────────────────────────────────────────────────

describe('gaffer-exporter — session namespace', () => {
  const sessionData = {
    ip: '10.0.0.42',
    tier: 2,
    confidence: 0.87,
    techniqueIds: ['T1190', 'T1059'],
    toolIdentified: 'CobaltStrike',
    ts: 1700000000000,
  };

  it('POSTs AddElements to Gaffer with session elements', async () => {
    await exportEvent('homelab/sessions/sess-abc', sessionData);
    expect(mockPost).toHaveBeenCalledOnce();
    const body = mockPost.mock.calls[0][1] as { class: string; input: GafferElement[] };
    expect(body.class).toBe('uk.gov.gchq.gaffer.operation.impl.add.AddElements');
    expect(Array.isArray(body.input)).toBe(true);
    expect(body.input.length).toBeGreaterThan(0);
  });

  it('includes a Session entity with correct vertex', async () => {
    await exportEvent('homelab/sessions/sess-abc', sessionData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const session = elements.find((e) => e.group === 'Session' && e.vertex === 'sess-abc');
    expect(session).toBeDefined();
    expect(session!.properties['tier']).toBe(2);
    expect(session!.properties['confidence']).toBe(0.87);
  });

  it('includes an IPAddress entity', async () => {
    await exportEvent('homelab/sessions/sess-abc', sessionData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const ip = elements.find((e) => e.group === 'IPAddress' && e.vertex === '10.0.0.42');
    expect(ip).toBeDefined();
  });

  it('includes a SessionFromIP edge', async () => {
    await exportEvent('homelab/sessions/sess-abc', sessionData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const edge = elements.find((e) => e.group === 'SessionFromIP');
    expect(edge).toBeDefined();
    expect(edge!.source).toBe('sess-abc');
    expect(edge!.destination).toBe('10.0.0.42');
    expect(edge!.directed).toBe(true);
  });

  it('includes a Tool entity and SessionUsedTool edge', async () => {
    await exportEvent('homelab/sessions/sess-abc', sessionData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const tool = elements.find((e) => e.group === 'Tool');
    expect(tool).toBeDefined();
    expect(tool!.properties['name']).toBe('CobaltStrike');
    const edge = elements.find((e) => e.group === 'SessionUsedTool');
    expect(edge).toBeDefined();
    expect(edge!.destination).toBe('CobaltStrike');
  });

  it('includes Technique entities and SessionUsedTechnique edges per techniqueId', async () => {
    await exportEvent('homelab/sessions/sess-abc', sessionData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const techniques = elements.filter((e) => e.group === 'Technique');
    expect(techniques).toHaveLength(2);
    const techIds = techniques.map((t) => t.vertex);
    expect(techIds).toContain('T1190');
    expect(techIds).toContain('T1059');
    const edges = elements.filter((e) => e.group === 'SessionUsedTechnique');
    expect(edges).toHaveLength(2);
  });

  it('handles techniqueIds as a comma-joined string', async () => {
    await exportEvent('homelab/sessions/sess-x', {
      ...sessionData,
      techniqueIds: 'T1071,T1059',
    });
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const techniques = elements.filter((e) => e.group === 'Technique');
    expect(techniques).toHaveLength(2);
  });

  it('no Tool entity or edge when toolIdentified is absent', async () => {
    const noTool = { ...sessionData, toolIdentified: undefined };
    await exportEvent('homelab/sessions/sess-notool', noTool);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    expect(elements.find((e) => e.group === 'Tool')).toBeUndefined();
    expect(elements.find((e) => e.group === 'SessionUsedTool')).toBeUndefined();
  });
});

// ─── Tetragon namespace ───────────────────────────────────────────────────────

describe('gaffer-exporter — tetragon namespace', () => {
  const tetragonData = {
    eventType:  'kprobe_connect',
    action:     'SIGKILL',
    binary:     '/opt/aegis/honeypot/server',
    pid:        9999,
    technique:  'T1071',
    severity:   'CRITICAL',
    ts:         1700000001000,
  };

  it('includes a TetragonEvent entity', async () => {
    await exportEvent('homelab/threats/tetragon/T1071/9999', tetragonData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const ev = elements.find((e) => e.group === 'TetragonEvent');
    expect(ev).toBeDefined();
    expect(ev!.properties['action']).toBe('SIGKILL');
    expect(ev!.properties['severity']).toBe('CRITICAL');
    expect(ev!.properties['technique']).toBe('T1071');
  });

  it('TetragonEvent vertex encodes namespace + ts', async () => {
    await exportEvent('homelab/threats/tetragon/T1071/9999', tetragonData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const ev = elements.find((e) => e.group === 'TetragonEvent');
    expect(ev!.vertex).toContain('homelab/threats/tetragon/T1071/9999');
  });
});

// ─── ARP namespace ────────────────────────────────────────────────────────────

describe('gaffer-exporter — ARP namespace', () => {
  const arpData = {
    eventType:  'gateway_spoof',
    senderMac:  'de:ad:be:ef:00:01',
    trustedMac: 'aa:bb:cc:dd:ee:ff',
    severity:   'CRITICAL',
    ts:         1700000002000,
  };

  it('includes an ARPEvent entity', async () => {
    await exportEvent('homelab/threats/arp/192.168.1.99', arpData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const ev = elements.find((e) => e.group === 'ARPEvent');
    expect(ev).toBeDefined();
    expect(ev!.properties['senderIp']).toBe('192.168.1.99');
    expect(ev!.properties['eventType']).toBe('gateway_spoof');
  });

  it('includes an IPAddress entity for the sender', async () => {
    await exportEvent('homelab/threats/arp/192.168.1.99', arpData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const ip = elements.find((e) => e.group === 'IPAddress' && e.vertex === '192.168.1.99');
    expect(ip).toBeDefined();
  });

  it('includes an IPTriggeredARPEvent edge', async () => {
    await exportEvent('homelab/threats/arp/192.168.1.99', arpData);
    const elements = mockPost.mock.calls[0][1].input as GafferElement[];
    const edge = elements.find((e) => e.group === 'IPTriggeredARPEvent');
    expect(edge).toBeDefined();
    expect(edge!.source).toBe('192.168.1.99');
    expect(edge!.directed).toBe(true);
  });
});

// ─── Error handling ───────────────────────────────────────────────────────────

describe('gaffer-exporter — error handling', () => {
  it('ECONNREFUSED → does not throw', async () => {
    const err = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    vi.mocked(axios.isAxiosError).mockReturnValue(true);
    mockPost.mockRejectedValue(err);
    await expect(exportEvent('homelab/sessions/x', { ip: '1.2.3.4' })).resolves.toBeUndefined();
  });

  it('generic error → does not throw', async () => {
    mockPost.mockRejectedValue(new Error('timeout'));
    await expect(exportEvent('homelab/sessions/x', { ip: '1.2.3.4' })).resolves.toBeUndefined();
  });
});

// ─── querySessionsByIp ────────────────────────────────────────────────────────

describe('gaffer-exporter — querySessionsByIp', () => {
  it('returns session source IDs from edge response', async () => {
    mockPost.mockResolvedValue({
      data: [
        { class: '...Edge', group: 'SessionFromIP', source: 'sess-111', destination: '10.0.0.1', properties: {} },
        { class: '...Edge', group: 'SessionFromIP', source: 'sess-222', destination: '10.0.0.1', properties: {} },
      ],
    });
    const sessions = await querySessionsByIp('10.0.0.1');
    expect(sessions).toContain('sess-111');
    expect(sessions).toContain('sess-222');
  });

  it('returns empty array on error', async () => {
    mockPost.mockRejectedValue(new Error('timeout'));
    const sessions = await querySessionsByIp('1.2.3.4');
    expect(sessions).toEqual([]);
  });
});

// ─── isGafferReachable ────────────────────────────────────────────────────────

describe('gaffer-exporter — isGafferReachable', () => {
  it('returns true when /status responds', async () => {
    expect(await isGafferReachable()).toBe(true);
  });

  it('returns false when connection refused', async () => {
    mockGet.mockRejectedValue(new Error('ECONNREFUSED'));
    expect(await isGafferReachable()).toBe(false);
  });
});
