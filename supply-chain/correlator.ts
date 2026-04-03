/**
 * SBOM vs CVE Correlator
 * Determines if a discovered advisory affects any installed package version.
 */

import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';
import type { Package } from './sbom-collector.js';
import type { OSVAdvisory } from './cvefeed.js';

export interface ExposureAlert {
  severity: 'critical' | 'high' | 'medium' | 'low';
  cveId: string;
  cvssScore: number;
  package: string;
  version: string;
  affectedNodes: string[];
  exploitAvailable: boolean;
  reachableFromInternet: boolean;
  isSupplyChainAttack: boolean;
  remediationOptions: string[];
  autoIsolationRecommended: boolean;
  timeToDisclosureHours: number;
}

function parseCVSS(score: string | undefined): number {
  const n = parseFloat(score ?? '0');
  return isNaN(n) ? 0 : n;
}

function isVersionAffected(version: string, advisory: OSVAdvisory): boolean {
  for (const affected of advisory.affected) {
    if (affected.versions?.includes(version)) return true;
    // Range-based check (simplified — use semver library for production)
    for (const range of affected.ranges ?? []) {
      if (range.type === 'SEMVER' || range.type === 'ECOSYSTEM') {
        const introduced = range.events.find((e) => e.introduced)?.introduced ?? '0';
        const fixed = range.events.find((e) => e.fixed)?.fixed;
        if (!fixed) return true; // unfixed
        // Naive string compare — replace with semver in prod
        if (version >= introduced && version < fixed) return true;
      }
    }
  }
  return false;
}

export async function assessExposure(pkg: Package, advisory: OSVAdvisory): Promise<void> {
  if (!isVersionAffected(pkg.version, advisory)) return;

  const cvssScore = parseCVSS(advisory.severity?.[0]?.score);
  const cveId = advisory.aliases?.find((a) => a.startsWith('CVE-')) ?? advisory.id;

  let severity: ExposureAlert['severity'];
  if (cvssScore >= 9) severity = 'critical';
  else if (cvssScore >= 7) severity = 'high';
  else if (cvssScore >= 4) severity = 'medium';
  else severity = 'low';

  const isSupplyChainAttack = advisory.summary?.toLowerCase().includes('malicious') ?? false;
  if (isSupplyChainAttack) severity = 'critical'; // always critical per doctrine

  const disclosureAge =
    (Date.now() - new Date(advisory.published).getTime()) / 3_600_000;

  const alert: ExposureAlert = {
    severity,
    cveId,
    cvssScore,
    package: pkg.name,
    version: pkg.version,
    affectedNodes: [pkg.node],
    exploitAvailable: false, // enrich from CISA KEV in production
    reachableFromInternet: false, // enrich from topology map
    isSupplyChainAttack,
    remediationOptions: [`Update ${pkg.name} to a version after the fixed release`],
    autoIsolationRecommended: severity === 'critical' && isSupplyChainAttack,
    timeToDisclosureHours: Math.round(disclosureAge),
  };

  logger.warn('EXPOSURE ALERT', alert);
  await exportEvent('homelab/supply-chain/cves/' + cveId, alert);
}
