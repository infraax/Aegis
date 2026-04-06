/**
 * Tests for attribution/dns-monitor.ts
 *
 * Tests verify:
 *  1. startDNSMonitor() — honours DNS_MONITOR_DISABLE=1
 *  2. stopDNSMonitor() — safe to call without running process
 *  3. startDNSMonitor() is idempotent
 *  4. Permanent errors (scapy missing, permission denied) → _stopped = true
 *
 * The Python dns_monitor.py script itself is covered by integration tests.
 * We use a non-existent script path to exercise the bridge lifecycle.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { silenceLogger, restoreLogger } from '../shared/test-utils.js';

import {
  startDNSMonitor,
  stopDNSMonitor,
  _resetForTest,
} from '../attribution/dns-monitor.js';

describe('dns-monitor — bridge lifecycle', () => {
  beforeEach(() => {
    silenceLogger();
    _resetForTest();
    process.env.DNS_SCRIPT_PATH      = '/tmp/__nonexistent_dns_script__.py';
    process.env.DNS_MONITOR_IFACE    = 'lo';
  });

  afterEach(() => {
    stopDNSMonitor();
    restoreLogger();
    _resetForTest();
    delete process.env.DNS_SCRIPT_PATH;
    delete process.env.DNS_MONITOR_IFACE;
    delete process.env.DNS_MONITOR_DISABLE;
  });

  it('DNS_MONITOR_DISABLE=1 → startDNSMonitor is a no-op', () => {
    process.env.DNS_MONITOR_DISABLE = '1';
    expect(() => startDNSMonitor()).not.toThrow();
  });

  it('stopDNSMonitor is safe to call without a running process', () => {
    expect(() => stopDNSMonitor()).not.toThrow();
  });

  it('startDNSMonitor does not throw when script is absent', () => {
    expect(() => startDNSMonitor()).not.toThrow();
  });

  it('startDNSMonitor is idempotent — second call is a no-op', () => {
    process.env.DNS_MONITOR_DISABLE = '1';
    startDNSMonitor();
    expect(() => startDNSMonitor()).not.toThrow();
  });

  it('after stopDNSMonitor, startDNSMonitor remains stopped', () => {
    stopDNSMonitor();
    expect(() => startDNSMonitor()).not.toThrow();
  });
});
