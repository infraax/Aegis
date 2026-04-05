/**
 * ATT&CK STIX Database
 *
 * Loads the MITRE ATT&CK enterprise STIX bundle (JSON) at startup and builds
 * an in-memory index that maps observed request path patterns to technique IDs.
 *
 * Data source: https://github.com/mitre-attack/attack-stix-data
 * Production bundle path: /opt/aegis/data/enterprise-attack.json
 * Test bundle path:       set ATTACK_STIX_PATH env var or use the fixture
 *
 * We own zero ATT&CK code — we only read their published JSON format.
 */

import fs from 'fs';
import path from 'path';
import { logger } from '../../shared/logger.js';

// ─── STIX types (only the fields we care about) ───────────────────────────────

interface StixExternalRef {
  source_name: string;
  external_id?: string;
}

interface StixAttackPattern {
  type: 'attack-pattern';
  id: string;
  name: string;
  external_references: StixExternalRef[];
}

interface StixBundle {
  type: 'bundle';
  objects: Array<StixAttackPattern | { type: string }>;
}

// ─── Technique record ─────────────────────────────────────────────────────────

export interface Technique {
  id: string;   // e.g. "T1190"
  name: string; // e.g. "Exploit Public-Facing Application"
}

// ─── Path → technique mapping ─────────────────────────────────────────────────
//
// Each entry maps a regex (matched against request paths) to one or more
// ATT&CK technique IDs.  These are hand-maintained mappings — the STIX file
// gives us the authoritative name/ID, but path→technique is our analysis layer.

interface PathRule {
  pattern: RegExp;
  techniqueIds: string[];
}

const PATH_RULES: PathRule[] = [
  // T1190  Exploit Public-Facing Application
  { pattern: /\/wp-login\.php/i,          techniqueIds: ['T1190'] },
  { pattern: /\/phpmyadmin/i,             techniqueIds: ['T1190'] },
  { pattern: /\/admin\.php$/i,            techniqueIds: ['T1190'] },
  { pattern: /\/xmlrpc\.php/i,            techniqueIds: ['T1190'] },
  { pattern: /\/config\.php/i,            techniqueIds: ['T1190'] },
  { pattern: /\/shell\.php/i,             techniqueIds: ['T1190'] },
  { pattern: /\/backup\.(zip|tar|gz)/i,   techniqueIds: ['T1190'] },
  { pattern: /\/\.env$/i,                 techniqueIds: ['T1190'] },

  // T1046  Network Service Discovery
  { pattern: /\/robots\.txt/i,            techniqueIds: ['T1046'] },
  { pattern: /\/sitemap\.xml/i,           techniqueIds: ['T1046'] },
  { pattern: /\/_cat\/indices/i,          techniqueIds: ['T1046'] }, // Elasticsearch enum

  // T1110  Brute Force (repeated /login probes)
  { pattern: /\/login/i,                  techniqueIds: ['T1110'] },
  { pattern: /\/wp-admin/i,               techniqueIds: ['T1110', 'T1190'] },

  // T1003  OS Credential Dumping (path traversal attempts)
  { pattern: /\/etc\/passwd/i,            techniqueIds: ['T1003'] },
  { pattern: /\/etc\/shadow/i,            techniqueIds: ['T1003'] },
  { pattern: /\/proc\/self/i,             techniqueIds: ['T1003'] },

  // T1083  File and Directory Discovery
  { pattern: /\/\.git\//i,               techniqueIds: ['T1083'] },
  { pattern: /\/cgi-bin/i,               techniqueIds: ['T1083', 'T1190'] },
];

// ─── In-memory index ──────────────────────────────────────────────────────────

/** techniqueId → Technique — populated by loadStixBundle() */
const techniqueIndex = new Map<string, Technique>();
let loaded = false;

/**
 * Load the ATT&CK STIX bundle.  Called once at startup.
 * Safe to call multiple times — subsequent calls are no-ops.
 */
export function loadStixBundle(bundlePath?: string): void {
  if (loaded) return;

  const filePath =
    bundlePath ??
    process.env.ATTACK_STIX_PATH ??
    '/opt/aegis/data/enterprise-attack.json';

  if (!fs.existsSync(filePath)) {
    logger.warn('ATT&CK STIX bundle not found — technique mapping disabled', {
      path: filePath,
      hint: 'Run scripts/download-attack-stix.sh to fetch the bundle',
    });
    loaded = true; // Mark loaded so we don't spam the warning
    return;
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const bundle: StixBundle = JSON.parse(raw);

    let count = 0;
    for (const obj of bundle.objects) {
      if (obj.type !== 'attack-pattern') continue;
      const ap = obj as StixAttackPattern;
      const ref = ap.external_references?.find(
        (r) => r.source_name === 'mitre-attack' && r.external_id,
      );
      if (!ref?.external_id) continue;
      techniqueIndex.set(ref.external_id, { id: ref.external_id, name: ap.name });
      count++;
    }

    logger.info('ATT&CK STIX bundle loaded', {
      path: filePath,
      techniques: count,
    });
    loaded = true;
  } catch (err) {
    logger.error('Failed to parse ATT&CK STIX bundle', { err, path: filePath });
    loaded = true; // Don't retry on every request
  }
}

/**
 * Resolve a set of technique IDs to full Technique objects.
 * Returns only IDs that exist in the loaded index.
 * Falls back gracefully if the bundle was never loaded.
 */
export function resolveTechniques(ids: string[]): Technique[] {
  const result: Technique[] = [];
  for (const id of ids) {
    const t = techniqueIndex.get(id);
    if (t) {
      result.push(t);
    } else {
      // Return stub so callers always get a Technique even if bundle missing
      result.push({ id, name: 'Unknown — STIX bundle not loaded' });
    }
  }
  return result;
}

/**
 * Map observed request paths to ATT&CK technique IDs.
 * Returns deduplicated IDs sorted for deterministic output.
 */
export function lookupTechniquesForPaths(paths: string[]): string[] {
  const matched = new Set<string>();

  for (const p of paths) {
    for (const rule of PATH_RULES) {
      if (rule.pattern.test(p)) {
        for (const id of rule.techniqueIds) matched.add(id);
      }
    }
  }

  return [...matched].sort();
}

/** Exposed for tests — reset state between test runs. */
export function _resetForTest(): void {
  techniqueIndex.clear();
  loaded = false;
}
