/**
 * Intel Export Router
 *
 * Selects the active export backend at startup based on INTEL_BACKEND env var.
 * All callers import from 'intel-export/index.js' and get the right backend.
 *
 * INTEL_BACKEND=gun    (default) — GUN.js P2P relay → Pi5 dashboard
 * INTEL_BACKEND=gaffer           — Gaffer graph DB for queryable intelligence
 *
 * Both backends expose the same exportEvent(namespace, data) signature.
 */

import * as gunExporter    from './gun-exporter.js';
import * as gafferExporter from './gaffer-exporter.js';
import { logger } from '../shared/logger.js';

const BACKEND = (process.env.INTEL_BACKEND ?? 'gun').toLowerCase();

const backend = (() => {
  if (BACKEND === 'gaffer') {
    logger.info('intel-export: using Gaffer backend');
    return gafferExporter;
  }
  logger.info('intel-export: using GUN backend');
  return gunExporter;
})();

export async function exportEvent(namespace: string, data: unknown): Promise<void> {
  return backend.exportEvent(namespace, data);
}
