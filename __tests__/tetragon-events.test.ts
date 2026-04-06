/**
 * Tests for attribution/tetragon-events.ts
 *
 * Tetragon connects to a Unix socket at runtime. We test:
 *  1. parseTetragonEvent() — JSON event → TetragonAlert conversion
 *  2. startTetragonEvents() — honours TETRAGON_EVENTS_DISABLE
 *  3. stopTetragonEvents() — can be called without a running socket
 *  4. Graceful: ENOENT (socket not found) → stops, no retry
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

import {
  parseTetragonEvent,
  startTetragonEvents,
  stopTetragonEvents,
  _resetForTest,
  type TetragonAlert,
} from '../attribution/tetragon-events.js';

// ─── parseTetragonEvent ───────────────────────────────────────────────────────

describe('tetragon-events — parseTetragonEvent', () => {
  it('returns null for non-object input', () => {
    expect(parseTetragonEvent(null)).toBeNull();
    expect(parseTetragonEvent('string')).toBeNull();
    expect(parseTetragonEvent(42)).toBeNull();
  });

  it('returns null for unknown event type', () => {
    expect(parseTetragonEvent({ some_other_field: {} })).toBeNull();
  });

  it('parses process_exec event correctly', () => {
    const raw = {
      process_exec: {
        process: {
          exec_id: 'abc123',
          pid: 1234,
          uid: 0,
          cwd: '/tmp',
          binary: '/bin/sh',
          arguments: '-c id',
          pod: undefined,
        },
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert).not.toBeNull();
    expect(alert.eventType).toBe('exec');
    expect(alert.action).toBe('POST');
    expect(alert.binary).toBe('/bin/sh');
    expect(alert.pid).toBe(1234);
    expect(alert.args).toContain('-c id');
    expect(alert.technique).toBe('T1059');
    expect(alert.severity).toBe('INFO');
  });

  it('parses process_exec with pod info', () => {
    const raw = {
      process_exec: {
        process: {
          exec_id: 'x',
          pid: 42,
          uid: 1000,
          cwd: '/',
          binary: '/usr/bin/python3',
          arguments: 'exploit.py',
          pod: { namespace: 'aegis', name: 'honeypot-1', container: { name: 'web' } },
        },
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert.pod).toBe('aegis/honeypot-1/web');
  });

  it('parses sys_connect kprobe with SIGKILL action → CRITICAL severity', () => {
    const raw = {
      process_kprobe: {
        process: {
          exec_id: 'def456',
          pid: 9999,
          uid: 0,
          cwd: '/opt/aegis/honeypot',
          binary: '/opt/aegis/honeypot/server',
          arguments: '',
        },
        function_name: 'sys_connect',
        args: [{ int_arg: 4 }, { string_arg: '192.168.1.100:4444' }],
        action: 'KPROBE_ACTION_SIGKILL',
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert).not.toBeNull();
    expect(alert.eventType).toBe('kprobe_connect');
    expect(alert.action).toBe('SIGKILL');
    expect(alert.technique).toBe('T1071');
    expect(alert.severity).toBe('CRITICAL');
    expect(alert.functionName).toBe('sys_connect');
  });

  it('parses sys_execve kprobe with POST action → MEDIUM severity', () => {
    const raw = {
      process_kprobe: {
        process: {
          exec_id: 'ghi',
          pid: 777,
          uid: 33,
          cwd: '/opt/aegis/honeypot',
          binary: '/bin/bash',
          arguments: '',
        },
        function_name: 'sys_execve',
        args: [{ string_arg: '/bin/bash' }, { string_arg: '-c' }, { string_arg: 'id' }],
        action: 'KPROBE_ACTION_POST',
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert.eventType).toBe('kprobe_execve');
    expect(alert.action).toBe('POST');
    expect(alert.severity).toBe('MEDIUM');
    expect(alert.technique).toBe('T1059');
  });

  it('parses sys_openat write to /etc → HIGH severity', () => {
    const raw = {
      process_kprobe: {
        process: {
          exec_id: 'jkl',
          pid: 555,
          uid: 0,
          cwd: '/',
          binary: '/opt/aegis/honeypot/implant',
          arguments: '',
        },
        function_name: 'sys_openat',
        args: [{ int_arg: -100 }, { string_arg: '/etc/passwd' }, { int_arg: 1 }],
        action: 'KPROBE_ACTION_POST',
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert.eventType).toBe('kprobe_openat');
    expect(alert.technique).toBe('T1565.001');
    expect(alert.severity).toBe('HIGH');
    expect(alert.args[1]).toBe('/etc/passwd');
  });

  it('parses sys_openat read from /root → HIGH severity', () => {
    const raw = {
      process_kprobe: {
        process: {
          exec_id: 'mno',
          pid: 222,
          uid: 0,
          cwd: '/',
          binary: '/opt/aegis/honeypot/implant',
          arguments: '',
        },
        function_name: 'sys_openat',
        args: [{ int_arg: -100 }, { string_arg: '/root/.ssh/id_rsa' }, { int_arg: 0 }],
        action: 'KPROBE_ACTION_POST',
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert.severity).toBe('HIGH');
  });

  it('parses sys_openat cron write → SIGKILL action', () => {
    const raw = {
      process_kprobe: {
        process: {
          exec_id: 'pqr',
          pid: 444,
          uid: 0,
          cwd: '/',
          binary: '/opt/aegis/honeypot/implant',
          arguments: '',
        },
        function_name: 'sys_openat',
        args: [{ int_arg: -100 }, { string_arg: '/etc/cron.d/backdoor' }, { int_arg: 1 }],
        action: 'KPROBE_ACTION_SIGKILL',
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert.action).toBe('SIGKILL');
    expect(alert.severity).toBe('CRITICAL');  // SIGKILL overrides path severity
  });

  it('unknown function name → eventType unknown, technique T1059 fallback', () => {
    const raw = {
      process_kprobe: {
        process: { exec_id: 'z', pid: 1, uid: 0, cwd: '/', binary: '/bin/x', arguments: '' },
        function_name: 'sys_mmap',
        args: [],
        action: 'KPROBE_ACTION_POST',
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert.eventType).toBe('unknown');
    expect(alert.technique).toBe('T1059');
  });

  it('alert always has all required fields', () => {
    const raw = {
      process_exec: {
        process: { exec_id: 'a', pid: 1, uid: 0, cwd: '/', binary: '/bin/ls', arguments: '' },
      },
    };
    const alert = parseTetragonEvent(raw) as TetragonAlert;
    expect(alert).toHaveProperty('eventType');
    expect(alert).toHaveProperty('action');
    expect(alert).toHaveProperty('binary');
    expect(alert).toHaveProperty('pid');
    expect(alert).toHaveProperty('cwd');
    expect(alert).toHaveProperty('args');
    expect(alert).toHaveProperty('technique');
    expect(alert).toHaveProperty('severity');
    expect(alert).toHaveProperty('ts');
  });
});

// ─── Bridge lifecycle ─────────────────────────────────────────────────────────

describe('tetragon-events — bridge lifecycle', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
    // Disable socket connections in tests — we point to a non-existent path
    process.env.TETRAGON_SOCK = '/tmp/__nonexistent_tetragon_test__.sock';
  });

  afterEach(() => {
    stopTetragonEvents();
    restoreLogger();
    _resetForTest();
    delete process.env.TETRAGON_SOCK;
    delete process.env.TETRAGON_EVENTS_DISABLE;
  });

  it('TETRAGON_EVENTS_DISABLE=1 → startTetragonEvents is a no-op', () => {
    process.env.TETRAGON_EVENTS_DISABLE = '1';
    expect(() => startTetragonEvents()).not.toThrow();
  });

  it('stopTetragonEvents can be called without a running socket', () => {
    expect(() => stopTetragonEvents()).not.toThrow();
  });

  it('startTetragonEvents does not throw when socket is absent', () => {
    process.env.TETRAGON_EVENTS_DISABLE = '0';
    expect(() => startTetragonEvents()).not.toThrow();
  });

  it('startTetragonEvents is idempotent — second call is a no-op', () => {
    process.env.TETRAGON_EVENTS_DISABLE = '1';
    startTetragonEvents();
    expect(() => startTetragonEvents()).not.toThrow();
  });

  it('after stopTetragonEvents, restart is prevented', () => {
    stopTetragonEvents();
    expect(() => startTetragonEvents()).not.toThrow();
  });
});
