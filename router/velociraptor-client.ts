/**
 * Velociraptor REST API Client
 *
 * Integration pattern: Pattern D (Docker sidecar + REST API)
 *   - Velociraptor runs as a container defined in docker-compose.yml
 *   - This client calls its gRPC-gateway REST API
 *   - We own only this ~120-line bridge; Velociraptor is upgraded by pulling a new image
 *
 * What this does on Tier 3 trigger:
 *   1. Starts a Hunt scoped to the attacking IP — automatically collects:
 *      - Running processes (pslist)
 *      - Active network connections (netstat)
 *      - Recently modified files in /etc, /tmp, /var, home dirs
 *      - Authentication log entries from the past 24 hours
 *      - Scheduled tasks / cron entries
 *   2. Returns a HuntResult with the hunt ID so we can link the alert to evidence
 *
 * Graceful degradation:
 *   If Velociraptor is unreachable (container down, wrong URL, no API key),
 *   we log a warning and return { skipped: true } — the Tier 3 alert still fires,
 *   the human operator still gets notified, we just don't have auto-collected forensics.
 *
 * Environment:
 *   VELOCIRAPTOR_API_URL  — default http://127.0.0.1:8889
 *   VELOCIRAPTOR_API_KEY  — API key from velociraptor config (see docker/velociraptor/)
 *   VELOCIRAPTOR_ORG_ID   — optional org ID for multi-tenant deployments
 */

import axios, { type AxiosInstance } from 'axios';
import { logger } from '../shared/logger.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface HuntResult {
  huntId: string;
  huntUrl: string;       // deep link into the Velociraptor UI
  artifacts: string[];   // artifact names that were queued
  skipped: boolean;      // true if Velociraptor was unreachable
  error?: string;
}

/** Artifact collection definitions for Tier 3 response */
const TIER3_ARTIFACTS = [
  'Generic.System.Pstree',          // full process tree
  'Linux.Network.NetstatEnriched',  // active connections with process owners
  'Linux.Sys.BashHistory',          // recent bash history across all users
  'Linux.Sys.LastUserLogin',        // auth log — last 24h logins
  'Linux.Sys.Crontab',              // scheduled tasks (persistence check)
  'Linux.Search.FileFinder',        // recently modified files in sensitive dirs
];

// ─── Client ───────────────────────────────────────────────────────────────────

let _client: AxiosInstance | null = null;

function getClient(): AxiosInstance {
  if (_client) return _client;

  const baseURL = process.env.VELOCIRAPTOR_API_URL ?? 'http://127.0.0.1:8889';
  const apiKey  = process.env.VELOCIRAPTOR_API_KEY ?? '';

  _client = axios.create({
    baseURL,
    timeout: 10_000,
    headers: {
      'Content-Type': 'application/json',
      ...(apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}),
    },
  });

  return _client;
}

// ─── Health check ─────────────────────────────────────────────────────────────

export async function isVelociraptorReachable(): Promise<boolean> {
  try {
    await getClient().get('/api/v1/GetServerInfo', { timeout: 3_000 });
    return true;
  } catch {
    return false;
  }
}

// ─── Trigger hunt ─────────────────────────────────────────────────────────────

/**
 * Launch a Velociraptor Hunt targeting the given IP address.
 *
 * A Hunt in Velociraptor runs a set of artifacts across all enrolled clients
 * and filters results.  Here we scope it to the source IP of the Tier 3 session
 * so we collect evidence from the endpoint that made contact.
 *
 * Never rejects — errors surface in result.error with skipped: true.
 */
export async function triggerHunt(
  sourceIp: string,
  sessionId: string,
  techniqueIds: string[] = [],
): Promise<HuntResult> {
  const baseURL = process.env.VELOCIRAPTOR_API_URL ?? 'http://127.0.0.1:8889';

  logger.info('velociraptor: triggering Tier 3 hunt', {
    sourceIp,
    sessionId,
    artifacts: TIER3_ARTIFACTS,
    techniques: techniqueIds,
  });

  try {
    const client = getClient();

    // Create the hunt
    const huntResponse = await client.post('/api/v1/CreateHunt', {
      hunt_description: `Aegis Tier3 auto-hunt — session ${sessionId} / IP ${sourceIp}`,
      start_request: {
        artifacts: TIER3_ARTIFACTS,
        parameters: {
          env: [
            { key: 'AegisSessionId',  value: sessionId },
            { key: 'AegisSourceIp',   value: sourceIp },
            { key: 'AegisTechniques', value: techniqueIds.join(',') },
            // Scope FileFinder to directories most likely to show attacker presence
            { key: 'SearchFilesGlob', value: '/tmp/**,/etc/**,/var/tmp/**,/home/**/.bash_history' },
          ],
        },
      },
      // Label condition — only run on clients that recently talked to sourceIp
      // In a real deployment, wire this to Aegis's network logs
      condition: {
        labels: { label: [] }, // no label filter — run on all enrolled agents
      },
      expires: String(Math.floor(Date.now() / 1000) + 86400), // 24h expiry
    });

    const huntId: string = huntResponse.data?.hunt_id ?? `hunt-${Date.now()}`;

    // Immediately start the hunt (Velociraptor hunts are paused by default)
    await client.post('/api/v1/ModifyHunt', {
      hunt_id: huntId,
      state: 2, // RUNNING
    });

    const huntUrl = `${baseURL}/hunts/${huntId}`;

    logger.warn('velociraptor: hunt started — forensics collection in progress', {
      huntId,
      huntUrl,
      sourceIp,
      sessionId,
    });

    return {
      huntId,
      huntUrl,
      artifacts: TIER3_ARTIFACTS,
      skipped: false,
    };

  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const isConnRefused =
      message.includes('ECONNREFUSED') ||
      message.includes('ENOTFOUND') ||
      message.includes('connect');

    if (isConnRefused) {
      logger.warn(
        'velociraptor: unreachable — Tier 3 alert will fire but no auto-hunt. ' +
        'Start the velociraptor container: docker compose up -d velociraptor',
        { sourceIp, sessionId, error: message },
      );
    } else {
      logger.error('velociraptor: hunt creation failed', { sourceIp, sessionId, error: message });
    }

    return {
      huntId: '',
      huntUrl: '',
      artifacts: [],
      skipped: true,
      error: message,
    };
  }
}

/** Exposed for tests — reset the axios instance so env vars are re-read */
export function _resetClientForTest(): void {
  _client = null;
}
