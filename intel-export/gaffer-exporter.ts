/**
 * Gaffer Intelligence Exporter
 *
 * Replaces GUN as the backend for exportEvent(). Same function signature —
 * no changes required in callers. Switch via:
 *   INTEL_BACKEND=gaffer   (default: gun)
 *
 * Gaffer is a GCHQ open-source graph database that stores all entities
 * (Sessions, IPAddresses, Tools, Techniques, Tetragon/ARP events) and
 * their relationships as queryable graph edges.
 *
 * Integration pattern: Pattern D (Docker sidecar + REST)
 *   - Gaffer runs as a Docker container exposing REST on 127.0.0.1:8080
 *   - This exporter translates Aegis namespace paths into graph elements
 *   - Graceful degradation: any Gaffer error is logged and swallowed;
 *     the main pipeline never throws
 *
 * Namespace → graph mapping:
 *   homelab/sessions/<sessionId>                → Session entity + edges
 *   homelab/threats/tetragon/<technique>/<pid>  → TetragonEvent entity
 *   homelab/threats/arp/<senderIp>              → ARPEvent entity + edge
 *   homelab/supply-chain/<pkg>                  → IPAddress/Tool hints
 *   (everything else)                           → generic key-value put
 *
 * Environment:
 *   GAFFER_URL   — Gaffer REST API base URL (default: http://127.0.0.1:8080)
 *   GAFFER_GRAPH — graph ID (default: aegis)
 */

import axios, { type AxiosInstance } from 'axios';
import { logger } from '../shared/logger.js';

// ─── Configuration ────────────────────────────────────────────────────────────

const GAFFER_URL   = (process.env.GAFFER_URL   ?? 'http://127.0.0.1:8080').replace(/\/$/, '');
const GAFFER_GRAPH = process.env.GAFFER_GRAPH  ?? 'aegis';

let _client: AxiosInstance | null = null;

function getClient(): AxiosInstance {
  if (!_client) {
    _client = axios.create({
      baseURL: `${GAFFER_URL}/rest/v2/graph/${GAFFER_GRAPH}`,
      timeout: 5_000,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return _client;
}

/** Exposed for tests */
export function _resetClientForTest(): void {
  _client = null;
}

// ─── Graph element builders ───────────────────────────────────────────────────

export interface GafferElement {
  class: string;
  group: string;
  vertex?: string;
  source?: string;
  destination?: string;
  directed?: boolean;
  properties: Record<string, unknown>;
}

const NS_SESSION    = /^homelab\/sessions\/(.+)$/;
const NS_TETRAGON   = /^homelab\/threats\/tetragon\//;
const NS_ARP        = /^homelab\/threats\/arp\/(.+)$/;

function buildElements(namespace: string, data: Record<string, unknown>): GafferElement[] {
  const ts = (data['ts'] as number | undefined) ?? Date.now();
  const elements: GafferElement[] = [];

  // ── Session ──────────────────────────────────────────────────────────────
  const sessionMatch = NS_SESSION.exec(namespace);
  if (sessionMatch) {
    const sessionId = sessionMatch[1];
    const ip        = (data['ip'] as string | undefined) ?? 'unknown';

    elements.push({
      class:  'uk.gov.gchq.gaffer.data.element.Entity',
      group:  'Session',
      vertex: sessionId,
      properties: {
        sessionId,
        ip,
        tier:           data['tier']           ?? 1,
        confidence:     data['confidence']      ?? 0,
        techniqueIds:   Array.isArray(data['techniqueIds'])
          ? (data['techniqueIds'] as string[]).join(',')
          : (data['techniqueIds'] as string | undefined) ?? '',
        toolIdentified: data['toolIdentified']  ?? '',
        firstSeen:      ts,
        lastSeen:       ts,
      },
    });

    // Session → IPAddress entity
    elements.push({
      class:  'uk.gov.gchq.gaffer.data.element.Entity',
      group:  'IPAddress',
      vertex: ip,
      properties: {
        ip,
        country:      data['country']      ?? '',
        firstSeen:    ts,
        lastSeen:     ts,
        sessionCount: 1,
      },
    });

    // Session → IPAddress edge
    elements.push({
      class:       'uk.gov.gchq.gaffer.data.element.Edge',
      group:       'SessionFromIP',
      source:      sessionId,
      destination: ip,
      directed:    true,
      properties:  { firstSeen: ts },
    });

    // Session → Tool edge (when toolIdentified present)
    if (data['toolIdentified']) {
      const tool = data['toolIdentified'] as string;
      elements.push({
        class:  'uk.gov.gchq.gaffer.data.element.Entity',
        group:  'Tool',
        vertex: tool,
        properties: { name: tool, firstSeen: ts, seenCount: 1 },
      });
      elements.push({
        class:       'uk.gov.gchq.gaffer.data.element.Edge',
        group:       'SessionUsedTool',
        source:      sessionId,
        destination: tool,
        directed:    true,
        properties:  { confidence: data['confidence'] ?? 0 },
      });
    }

    // Session → Technique edges (one per techniqueId)
    const techniqueIds = Array.isArray(data['techniqueIds'])
      ? (data['techniqueIds'] as string[])
      : String(data['techniqueIds'] ?? '').split(',').filter(Boolean);

    for (const tid of techniqueIds) {
      elements.push({
        class:  'uk.gov.gchq.gaffer.data.element.Entity',
        group:  'Technique',
        vertex: tid,
        properties: { techniqueId: tid, firstSeen: ts, seenCount: 1 },
      });
      elements.push({
        class:       'uk.gov.gchq.gaffer.data.element.Edge',
        group:       'SessionUsedTechnique',
        source:      sessionId,
        destination: tid,
        directed:    true,
        properties:  { seenAt: ts },
      });
    }

    return elements;
  }

  // ── Tetragon enforcement event ────────────────────────────────────────────
  if (NS_TETRAGON.test(namespace)) {
    const vertexId = `${namespace}@${ts}`;
    elements.push({
      class:  'uk.gov.gchq.gaffer.data.element.Entity',
      group:  'TetragonEvent',
      vertex: vertexId,
      properties: {
        eventType:  data['eventType']    ?? 'unknown',
        action:     data['action']       ?? 'UNKNOWN',
        binary:     data['binary']       ?? '',
        pid:        data['pid']          ?? 0,
        technique:  data['technique']    ?? '',
        severity:   data['severity']     ?? 'INFO',
        ts,
      },
    });
    return elements;
  }

  // ── ARP event ─────────────────────────────────────────────────────────────
  const arpMatch = NS_ARP.exec(namespace);
  if (arpMatch) {
    const senderIp = arpMatch[1];
    const vertexId = `arp:${senderIp}@${ts}`;

    elements.push({
      class:  'uk.gov.gchq.gaffer.data.element.Entity',
      group:  'ARPEvent',
      vertex: vertexId,
      properties: {
        eventType:  data['eventType']  ?? 'arp_conflict',
        senderIp,
        senderMac:  data['senderMac']  ?? '',
        trustedMac: data['trustedMac'] ?? '',
        severity:   data['severity']   ?? 'HIGH',
        ts,
      },
    });

    // IPAddress → ARPEvent edge
    elements.push({
      class:  'uk.gov.gchq.gaffer.data.element.Entity',
      group:  'IPAddress',
      vertex: senderIp,
      properties: { ip: senderIp, firstSeen: ts, lastSeen: ts, sessionCount: 0 },
    });
    elements.push({
      class:       'uk.gov.gchq.gaffer.data.element.Edge',
      group:       'IPTriggeredARPEvent',
      source:      senderIp,
      destination: vertexId,
      directed:    true,
      properties:  { seenAt: ts },
    });

    return elements;
  }

  // ── Generic fallback — key-value style entity ──────────────────────────────
  elements.push({
    class:  'uk.gov.gchq.gaffer.data.element.Entity',
    group:  'Session',
    vertex: namespace,
    properties: { ...data, firstSeen: ts, lastSeen: ts },
  });

  return elements;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Export an Aegis event into the Gaffer graph.
 * Translates the namespace + data into graph elements and POSTs to Gaffer.
 * Non-throwing — any error is logged and swallowed.
 */
export async function exportEvent(
  namespace: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any,
): Promise<void> {
  let elements: GafferElement[];
  try {
    elements = buildElements(namespace, data as Record<string, unknown>);
  } catch (err) {
    logger.warn('gaffer-exporter: element build failed', { namespace, err });
    return;
  }

  try {
    const client = getClient();
    // Gaffer AddElements operation
    await client.post('/operations/execute', {
      class: 'uk.gov.gchq.gaffer.operation.impl.add.AddElements',
      input: elements,
      options: {},
    });
  } catch (err) {
    if (axios.isAxiosError(err) && err.code === 'ECONNREFUSED') {
      logger.debug('gaffer-exporter: Gaffer not reachable — skipping', { namespace });
    } else {
      logger.warn('gaffer-exporter: export failed', { namespace, err });
    }
  }
}

/**
 * Query Gaffer for all sessions originating from a given IP.
 * Returns an array of session vertex IDs or empty array on error.
 */
export async function querySessionsByIp(ip: string): Promise<string[]> {
  try {
    const client = getClient();
    const resp = await client.post('/operations/execute', {
      class: 'uk.gov.gchq.gaffer.operation.OperationChain',
      operations: [
        {
          class: 'uk.gov.gchq.gaffer.operation.impl.get.GetElements',
          input: [{ class: 'uk.gov.gchq.gaffer.operation.data.EntitySeed', vertex: ip }],
          view: {
            edges: { SessionFromIP: {} },
          },
        },
      ],
    });
    const results: string[] = [];
    if (Array.isArray(resp.data)) {
      for (const el of resp.data as GafferElement[]) {
        if (el.source) results.push(el.source);
      }
    }
    return results;
  } catch {
    return [];
  }
}

/**
 * Check if Gaffer is reachable.
 */
export async function isGafferReachable(): Promise<boolean> {
  try {
    const client = getClient();
    await client.get('/status');
    return true;
  } catch {
    return false;
  }
}
