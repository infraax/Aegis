/**
 * Exposure Report Generator
 * Produces a human-readable exposure summary from active ExposureAlerts.
 */

import type { ExposureAlert } from './correlator.js';

export interface ExposureSummary {
  generatedAt: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  affectedNodes: string[];
  supplyChainAttacks: number;
  alerts: ExposureAlert[];
}

const activeAlerts: ExposureAlert[] = [];

export function recordAlert(alert: ExposureAlert): void {
  // Deduplicate by cveId
  if (!activeAlerts.some((a) => a.cveId === alert.cveId && a.package === alert.package)) {
    activeAlerts.push(alert);
  }
}

export function generateSummary(): ExposureSummary {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  const nodeSet = new Set<string>();
  let supplyChain = 0;

  for (const alert of activeAlerts) {
    counts[alert.severity]++;
    alert.affectedNodes.forEach((n) => nodeSet.add(n));
    if (alert.isSupplyChainAttack) supplyChain++;
  }

  return {
    generatedAt: Date.now(),
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    affectedNodes: Array.from(nodeSet),
    supplyChainAttacks: supplyChain,
    alerts: activeAlerts,
  };
}
