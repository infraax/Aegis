/**
 * Tests for router/velociraptor-client.ts
 *
 * We mock axios at the module level — Velociraptor is never running in CI.
 * Tests verify:
 *  - Happy path: CreateHunt + ModifyHunt succeed → correct HuntResult
 *  - Connection refused → skipped: true, Tier 3 alert unaffected
 *  - Non-network error → skipped: true with error message
 *  - isVelociraptorReachable() returns true/false correctly
 *  - Hunt URL constructed from env var base
 *  - techniqueIds forwarded as environment params in hunt request
 *  - HuntResult always has all required fields
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

// ── Mock axios before importing the module under test ─────────────────────────
vi.mock('axios', async () => {
  const actual = await vi.importActual<typeof import('axios')>('axios');
  return {
    ...actual,
    default: {
      ...actual.default,
      create: vi.fn(),
    },
  };
});

// Import after mock is set up
import {
  triggerHunt,
  isVelociraptorReachable,
  _resetClientForTest,
} from '../router/velociraptor-client.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeMockClient(overrides: {
  getResult?: unknown;
  getError?: Error;
  postResults?: unknown[];
  postError?: Error;
}) {
  const postMock = overrides.postError
    ? vi.fn().mockRejectedValue(overrides.postError)
    : vi.fn()
        .mockResolvedValueOnce({ data: { hunt_id: 'H.test-hunt-001' } })   // CreateHunt
        .mockResolvedValueOnce({ data: {} });                               // ModifyHunt

  const getMock = overrides.getError
    ? vi.fn().mockRejectedValue(overrides.getError)
    : vi.fn().mockResolvedValue(overrides.getResult ?? { data: { version: '0.72' } });

  return { post: postMock, get: getMock };
}

// ─────────────────────────────────────────────────────────────────────────────

describe('velociraptor-client — triggerHunt', () => {
  beforeEach(() => {
    silenceLogger();
    _resetClientForTest();
    process.env.VELOCIRAPTOR_API_URL = 'http://127.0.0.1:8889';
    delete process.env.VELOCIRAPTOR_API_KEY;
  });

  afterEach(() => {
    restoreLogger();
    vi.clearAllMocks();
    _resetClientForTest();
  });

  it('happy path: returns huntId and huntUrl on success', async () => {
    const mockClient = makeMockClient({});
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    const result = await triggerHunt('10.0.0.5', 'session-abc', ['T1190']);

    expect(result.skipped).toBe(false);
    expect(result.huntId).toBe('H.test-hunt-001');
    expect(result.huntUrl).toContain('H.test-hunt-001');
    expect(result.artifacts.length).toBeGreaterThan(0);
    expect(result.error).toBeUndefined();
  });

  it('hunt URL contains the base API URL', async () => {
    process.env.VELOCIRAPTOR_API_URL = 'http://192.168.1.100:8889';
    _resetClientForTest();
    const mockClient = makeMockClient({});
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    const result = await triggerHunt('1.2.3.4', 'sess-1');

    expect(result.huntUrl).toContain('http://192.168.1.100:8889');
  });

  it('techniqueIds are forwarded in the hunt request env params', async () => {
    const mockClient = makeMockClient({});
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    await triggerHunt('1.2.3.4', 'sess-tech', ['T1046', 'T1190', 'T1003']);

    const createCall = mockClient.post.mock.calls[0];
    const body = createCall[1] as Record<string, unknown>;
    const env = (body.start_request as Record<string, unknown>)
      .parameters as { env: Array<{ key: string; value: string }> };
    const techParam = env.env.find((e) => e.key === 'AegisTechniques');

    expect(techParam?.value).toBe('T1046,T1190,T1003');
  });

  it('sessionId and sourceIp forwarded in hunt description and env', async () => {
    const mockClient = makeMockClient({});
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    await triggerHunt('10.10.10.1', 'session-xyz');

    const createCall = mockClient.post.mock.calls[0];
    const body = createCall[1] as Record<string, unknown>;

    expect(body.hunt_description as string).toContain('session-xyz');
    expect(body.hunt_description as string).toContain('10.10.10.1');
  });

  it('ModifyHunt is called to start the hunt after creation', async () => {
    const mockClient = makeMockClient({});
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    await triggerHunt('1.2.3.4', 'sess-start');

    expect(mockClient.post).toHaveBeenCalledTimes(2);
    const modifyCall = mockClient.post.mock.calls[1];
    expect(modifyCall[0]).toBe('/api/v1/ModifyHunt');
    expect((modifyCall[1] as Record<string, unknown>).state).toBe(2); // RUNNING
  });

  it('ECONNREFUSED → skipped: true, no throw', async () => {
    const connErr = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8889'), {
      code: 'ECONNREFUSED',
    });
    const mockClient = makeMockClient({ postError: connErr });
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    const result = await triggerHunt('1.2.3.4', 'sess-down');

    expect(result.skipped).toBe(true);
    expect(result.huntId).toBe('');
    expect(result.error).toContain('ECONNREFUSED');
  });

  it('non-network error → skipped: true with error message', async () => {
    const apiErr = new Error('403 Forbidden');
    const mockClient = makeMockClient({ postError: apiErr });
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    const result = await triggerHunt('1.2.3.4', 'sess-err');

    expect(result.skipped).toBe(true);
    expect(result.error).toContain('403');
  });

  it('result always has all required fields even on error', async () => {
    const mockClient = makeMockClient({ postError: new Error('timeout') });
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    const result = await triggerHunt('1.2.3.4', 'sess-fields');

    expect(result).toHaveProperty('huntId');
    expect(result).toHaveProperty('huntUrl');
    expect(result).toHaveProperty('artifacts');
    expect(result).toHaveProperty('skipped');
    expect(Array.isArray(result.artifacts)).toBe(true);
  });

  it('API key is set in Authorization header when env var present', async () => {
    process.env.VELOCIRAPTOR_API_KEY = 'test-api-key-12345';
    _resetClientForTest();
    const mockClient = makeMockClient({});
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    await triggerHunt('1.2.3.4', 'sess-auth');

    const createCall = vi.mocked(axios.create).mock.calls[0][0];
    const headers = createCall?.headers as Record<string, string> | undefined;
    expect(headers?.['Authorization']).toBe('Bearer test-api-key-12345');
  });
});

describe('velociraptor-client — isVelociraptorReachable', () => {
  beforeEach(() => {
    silenceLogger();
    _resetClientForTest();
  });

  afterEach(() => {
    restoreLogger();
    vi.clearAllMocks();
    _resetClientForTest();
  });

  it('returns true when server responds', async () => {
    const mockClient = makeMockClient({ getResult: { data: { version: '0.72' } } });
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    const reachable = await isVelociraptorReachable();
    expect(reachable).toBe(true);
  });

  it('returns false when connection is refused', async () => {
    const mockClient = makeMockClient({ getError: new Error('ECONNREFUSED') });
    vi.mocked(axios.create).mockReturnValue(mockClient as never);

    const reachable = await isVelociraptorReachable();
    expect(reachable).toBe(false);
  });
});
