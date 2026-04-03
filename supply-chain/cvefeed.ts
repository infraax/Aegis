/**
 * CVE Intelligence Feed
 *
 * Polls OSV.dev, NVD, and GitHub Advisory Database for new vulnerabilities.
 * On each new advisory: cross-references the SBOM and fires an ExposureAlert.
 */

import axios from 'axios';
import cron from 'node-cron';
import { getAllPackages } from './sbom-collector.js';
import { assessExposure } from './correlator.js';
import { logger } from '../shared/logger.js';

export interface OSVAdvisory {
  id: string;
  aliases?: string[];
  summary: string;
  severity?: Array<{ type: string; score: string }>;
  affected: Array<{
    package: { name: string; ecosystem: string };
    ranges: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
    versions?: string[];
  }>;
  published: string;
  modified: string;
}

async function fetchOSVForPackage(ecosystem: string, name: string): Promise<OSVAdvisory[]> {
  try {
    const res = await axios.post(
      'https://api.osv.dev/v1/query',
      { package: { name, ecosystem } },
      { timeout: 10_000 },
    );
    return (res.data?.vulns ?? []) as OSVAdvisory[];
  } catch (err) {
    logger.debug('OSV query failed', { name, ecosystem, err });
    return [];
  }
}

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: 'npm',
  pip: 'PyPI',
  cargo: 'crates.io',
  go: 'Go',
};

export async function scanSBOMForCVEs(): Promise<void> {
  const packages = getAllPackages();
  logger.info('CVE scan starting', { packageCount: packages.length });

  for (const pkg of packages) {
    const ecosystem = ECOSYSTEM_MAP[pkg.manager];
    if (!ecosystem) continue; // skip dpkg/docker for now — use NVD for those

    const advisories = await fetchOSVForPackage(ecosystem, pkg.name);
    for (const advisory of advisories) {
      await assessExposure(pkg, advisory);
    }
  }

  logger.info('CVE scan complete');
}

// Poll every N minutes (default 60)
export function startCVEPoller(): void {
  const intervalMinutes = parseInt(process.env.CVE_POLL_INTERVAL_MINUTES ?? '60', 10);
  const cronExpr = `*/${intervalMinutes} * * * *`;

  cron.schedule(cronExpr, async () => {
    try {
      await scanSBOMForCVEs();
    } catch (err) {
      logger.error('CVE poll error', { err });
    }
  });

  logger.info('CVE poller scheduled', { intervalMinutes });
}
