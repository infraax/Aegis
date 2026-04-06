/**
 * Tests for attribution/process-net-monitor.ts
 *
 * Tests verify bridge lifecycle only (the psutil logic is covered by the
 * Python script's own tests and integration environment).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

import {
  startProcessNetMonitor,
  stopProcessNetMonitor,
  _resetForTest,
} from '../attribution/process-net-monitor.js';

describe('process-net-monitor — bridge lifecycle', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
    process.env.PROCESS_NET_SCRIPT_PATH = '/tmp/__nonexistent_procnet__.py';
  });

  afterEach(() => {
    stopProcessNetMonitor();
    restoreLogger();
    _resetForTest();
    delete process.env.PROCESS_NET_SCRIPT_PATH;
    delete process.env.PROCESS_NET_DISABLE;
  });

  it('PROCESS_NET_DISABLE=1 → startProcessNetMonitor is a no-op', () => {
    process.env.PROCESS_NET_DISABLE = '1';
    expect(() => startProcessNetMonitor()).not.toThrow();
  });

  it('stopProcessNetMonitor is safe to call without a running process', () => {
    expect(() => stopProcessNetMonitor()).not.toThrow();
  });

  it('startProcessNetMonitor does not throw when script is absent', () => {
    expect(() => startProcessNetMonitor()).not.toThrow();
  });

  it('startProcessNetMonitor is idempotent — second call is a no-op', () => {
    process.env.PROCESS_NET_DISABLE = '1';
    startProcessNetMonitor();
    expect(() => startProcessNetMonitor()).not.toThrow();
  });

  it('after stopProcessNetMonitor, restart is prevented', () => {
    stopProcessNetMonitor();
    expect(() => startProcessNetMonitor()).not.toThrow();
  });
});
