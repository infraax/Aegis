/**
 * Compartmentalisation Response
 *
 * When an ExposureAlert recommends auto-isolation, generates an isolation plan,
 * pushes an alert to the PWA, and waits for human confirmation before executing.
 * Exception: critical + exploitable + internet-facing supply-chain attack → auto-isolate.
 */

import { exportEvent } from '../intel-export/gun-exporter.js';
import { logger } from '../shared/logger.js';
import type { ExposureAlert } from './correlator.js';
import { v4 as uuidv4 } from 'uuid';

const COUNTDOWN_MS = 15 * 60 * 1000; // 15 minutes

export interface IsolationPlan {
  id: string;
  cveId: string;
  affectedNodes: string[];
  actions: string[];
  status: 'pending' | 'confirmed' | 'auto-executed' | 'dismissed';
  createdAt: number;
}

const pendingPlans = new Map<string, IsolationPlan>();

export async function handleExposureAlert(alert: ExposureAlert): Promise<void> {
  if (!alert.autoIsolationRecommended) return;

  const planId = uuidv4();
  const plan: IsolationPlan = {
    id: planId,
    cveId: alert.cveId,
    affectedNodes: alert.affectedNodes,
    actions: [
      `Remove WireGuard routes to sensitive services from: ${alert.affectedNodes.join(', ')}`,
      `Stop affected Docker containers on: ${alert.affectedNodes.join(', ')}`,
      `Block affected node from GUN relay writes`,
    ],
    status: 'pending',
    createdAt: Date.now(),
  };

  pendingPlans.set(planId, plan);
  await exportEvent('homelab/supply-chain/isolations/' + planId, plan);
  logger.warn('Isolation plan created — awaiting human confirmation', { planId, cveId: alert.cveId });

  // Auto-execute if: critical + known exploit + internet-facing + supply chain attack
  const shouldAutoExecute =
    alert.severity === 'critical' &&
    alert.exploitAvailable &&
    alert.reachableFromInternet &&
    alert.isSupplyChainAttack;

  if (shouldAutoExecute) {
    logger.warn('AUTO-ISOLATING — XZ-Utils-class scenario detected', { planId });
    await executeIsolation(planId);
  } else {
    // Start countdown — escalate if no human response
    setTimeout(async () => {
      const p = pendingPlans.get(planId);
      if (p?.status === 'pending') {
        await exportEvent('homelab/alerts/security/isolation-escalation-' + planId, {
          planId,
          message: 'No human response to isolation plan — ESCALATING',
          plan: p,
        });
        logger.error('Isolation plan unacknowledged — escalating', { planId });
      }
    }, COUNTDOWN_MS);
  }
}

export async function executeIsolation(planId: string): Promise<void> {
  const plan = pendingPlans.get(planId);
  if (!plan) { logger.error('Unknown isolation plan', { planId }); return; }

  plan.status = 'confirmed';
  logger.warn('Executing isolation plan', { planId, actions: plan.actions });

  // In production: call orchestrator MCP tools to:
  // 1. Remove WireGuard routes
  // 2. Stop Docker containers
  // 3. Block GUN relay writes
  // This is a stub — orchestrator integration implemented in mcp/index.ts

  await exportEvent('homelab/supply-chain/isolations/' + planId, plan);
}

export function getPendingPlans(): IsolationPlan[] {
  return Array.from(pendingPlans.values()).filter((p) => p.status === 'pending');
}
