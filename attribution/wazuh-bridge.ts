/**
 * Wazuh HIDS Alert Bridge
 *
 * Polls the Wazuh Manager REST API for new security alerts and exports
 * them into the Gaffer/GUN intelligence graph via exportEvent().
 *
 * Integration pattern: Pattern D (Docker sidecar + REST)
 *   - Wazuh manager runs as a Docker container with REST API on port 55000
 *   - This bridge polls /security/events every POLL_INTERVAL_MS
 *   - Stores the last-seen alert ID to avoid re-exporting
 *
 * ATT&CK coverage (via Wazuh rules):
 *   T1547  — Boot/Logon Autostart Execution (FIM on cron/systemd)
 *   T1574  — Hijack Execution Flow (DLL/service changes)
 *   T1053  — Scheduled Task/Job (cron writes)
 *   T1543  — Create/Modify System Process (service creation)
 *   T1055  — Process Injection (rootcheck)
 *   T1110  — Brute Force (SSH failures)
 *   T1078  — Valid Accounts (canary token triggers)
 *   T1557.002 — ARP Cache Poisoning (ARP alerts forwarded)
 *
 * Graceful degradation:
 *   - ECONNREFUSED (Wazuh not running) → logs debug, retries after interval
 *   - 401 Unauthorized → logs warning, stops polling
 *   - Any API error → logs warning, continues next poll cycle
 *
 * Environment:
 *   WAZUH_API_URL      — Wazuh manager REST API (default: https://127.0.0.1:55000)
 *   WAZUH_API_USER     — API username (default: wazuh-wui)
 *   WAZUH_API_PASSWORD — API password (from .env — never hardcoded)
 *   WAZUH_POLL_MS      — poll interval in ms (default: 15000)
 *   WAZUH_DISABLE      — set to "1" to suppress (for tests)
 */

import axios, { type AxiosInstance } from 'axios';
import https from 'https';
import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';

// ─── Configuration ────────────────────────────────────────────────────────────

const API_URL    = (process.env.WAZUH_API_URL      ?? 'https://127.0.0.1:55000').replace(/\/$/, '');
const API_USER   = process.env.WAZUH_API_USER      ?? 'wazuh-wui';
const API_PASS   = process.env.WAZUH_API_PASSWORD  ?? '';
const POLL_MS    = parseInt(process.env.WAZUH_POLL_MS ?? '15000', 10);

// ─── Wazuh alert types ────────────────────────────────────────────────────────

export interface WazuhAlert {
  id:          string;
  timestamp:   string;
  agent:       { id: string; name: string; ip?: string };
  rule:        { id: string; level: number; description: string; mitre?: { id: string[] } };
  data?:       Record<string, unknown>;
  location:    string;
  full_log?:   string;
}

export interface WazuhBridgeAlert {
  alertId:     string;
  agentName:   string;
  agentIp:     string;
  ruleId:      string;
  ruleLevel:   number;
  description: string;
  techniqueIds: string[];
  severity:    'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  location:    string;
  ts:          number;
}

function levelToSeverity(level: number): WazuhBridgeAlert['severity'] {
  if (level >= 13) return 'CRITICAL';
  if (level >= 10) return 'HIGH';
  if (level >= 7)  return 'MEDIUM';
  return 'LOW';
}

export function mapWazuhAlert(raw: WazuhAlert): WazuhBridgeAlert {
  return {
    alertId:      raw.id,
    agentName:    raw.agent.name,
    agentIp:      raw.agent.ip ?? 'unknown',
    ruleId:       raw.rule.id,
    ruleLevel:    raw.rule.level,
    description:  raw.rule.description,
    techniqueIds: raw.rule.mitre?.id ?? [],
    severity:     levelToSeverity(raw.rule.level),
    location:     raw.location,
    ts:           new Date(raw.timestamp).getTime(),
  };
}

// ─── API client ───────────────────────────────────────────────────────────────

let _client: AxiosInstance | null = null;
let _token:  string | null = null;
let _tokenExpiry = 0;

function getClient(): AxiosInstance {
  if (!_client) {
    _client = axios.create({
      baseURL: API_URL,
      timeout: 10_000,
      // Wazuh self-signed cert — acceptable for local deployment
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    });
  }
  return _client;
}

async function getToken(): Promise<string> {
  if (_token && Date.now() < _tokenExpiry) return _token;

  const resp = await getClient().post('/security/user/authenticate', null, {
    auth: { username: API_USER, password: API_PASS },
  });
  _token = (resp.data as { data: { token: string } }).data.token;
  _tokenExpiry = Date.now() + 14 * 60 * 1000;  // tokens expire after 15min; refresh at 14
  return _token;
}

/** Exposed for tests */
export function _resetClientForTest(): void {
  _client = null;
  _token  = null;
  _tokenExpiry = 0;
  _lastAlertId = null;
}

// ─── Poll loop ────────────────────────────────────────────────────────────────

let _lastAlertId: string | null = null;
let _pollTimer: ReturnType<typeof setInterval> | null = null;
let _stopped = false;
let _authFailed = false;

async function pollAlerts(): Promise<void> {
  if (_stopped || _authFailed) return;

  try {
    const token = await getToken();
    const client = getClient();

    const params: Record<string, unknown> = {
      limit:   500,
      sort:    '+id',
      select:  'id,timestamp,agent,rule,data,location',
    };
    if (_lastAlertId) params['search'] = `id>${_lastAlertId}`;

    const resp = await client.get('/security/events', {
      headers: { Authorization: `Bearer ${token}` },
      params,
    });

    const items = ((resp.data as { data: { affected_items: WazuhAlert[] } }).data.affected_items) ?? [];

    for (const raw of items) {
      const alert = mapWazuhAlert(raw);
      _lastAlertId = raw.id;

      if (alert.ruleLevel < 5) continue;  // skip low-noise informational

      logger.warn(`wazuh-bridge: ${alert.severity} rule=${alert.ruleId} agent=${alert.agentName}`, {
        description:  alert.description,
        techniqueIds: alert.techniqueIds,
        agentIp:      alert.agentIp,
      });

      await exportEvent(`homelab/wazuh/${alert.agentName}/${alert.ruleId}`, alert)
        .catch((err) => logger.error('wazuh-bridge: export failed', { err }));
    }
  } catch (err) {
    if (axios.isAxiosError(err)) {
      if (err.response?.status === 401) {
        logger.warn('wazuh-bridge: authentication failed — check WAZUH_API_PASSWORD', {
          hint: 'Set WAZUH_API_PASSWORD in .env',
        });
        _authFailed = true;
        _token = null;
        return;
      }
      if (err.code === 'ECONNREFUSED') {
        logger.debug('wazuh-bridge: Wazuh not reachable — will retry', { url: API_URL });
        return;
      }
    }
    logger.warn('wazuh-bridge: poll error', { err });
  }
}

/**
 * Start polling Wazuh alerts. Non-blocking.
 * Safe to call multiple times — subsequent calls are no-ops.
 */
export function startWazuhBridge(): void {
  if (process.env.WAZUH_DISABLE === '1') {
    logger.debug('wazuh-bridge: disabled via env');
    return;
  }
  if (_pollTimer || _stopped) return;

  logger.info('wazuh-bridge: starting', { url: API_URL, pollMs: POLL_MS });

  // First poll immediately, then on interval
  pollAlerts().catch((err) => logger.error('wazuh-bridge: initial poll error', { err }));
  _pollTimer = setInterval(() => {
    pollAlerts().catch((err) => logger.error('wazuh-bridge: poll error', { err }));
  }, POLL_MS);

  if (_pollTimer.unref) _pollTimer.unref();
}

/** Stop polling. */
export function stopWazuhBridge(): void {
  _stopped = true;
  if (_pollTimer) {
    clearInterval(_pollTimer);
    _pollTimer = null;
  }
}

/** Exposed for tests */
export function _resetForTest(): void {
  _stopped    = false;
  _authFailed = false;
  _token      = null;
  _tokenExpiry = 0;
  _lastAlertId = null;
  if (_pollTimer) {
    clearInterval(_pollTimer);
    _pollTimer = null;
  }
  _client = null;
}
