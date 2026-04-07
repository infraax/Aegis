// Behavioral pattern analysis — tracks request sequences within a session.

import { lookupTechniquesForPaths } from './attack-db.js';

export interface BehavioralSignal {
  pathsRequested: string[];
  methodDistribution: Record<string, number>;
  hasRobotsFollowUp: boolean;
  hasSitemapFollowUp: boolean;
  breadthFirstPattern: boolean;
  depthFirstPattern: boolean;
  scannerPathHits: number;           // paths matching known exploit/scanner patterns
  scannerPathRatio: number;          // fraction of requests hitting scanner paths
  confidence: number;
  techniqueIds: string[];            // ATT&CK technique IDs inferred from observed paths
}

// Known exploit/scanner path signatures — scanner tools target these regardless of UA
const SCANNER_PATH_PATTERNS = [
  /\/wp-login\.php/i, /\/phpmyadmin/i, /\.env$/i, /\/config\.php/i,
  /\/backup\.(zip|tar|gz)/i, /\/shell\.php/i, /\/\.git\//i, /\/xmlrpc\.php/i,
  /\/admin\.php$/i, /\/etc\/passwd/i, /\/proc\/self/i, /cgi-bin/i,
];

export function analyzeBehavior(requests: Array<{ method: string; path: string }>): BehavioralSignal {
  const pathsRequested = requests.map((r) => r.path);
  const methodDistribution: Record<string, number> = {};

  for (const r of requests) {
    methodDistribution[r.method] = (methodDistribution[r.method] ?? 0) + 1;
  }

  const hasRobotsFollowUp =
    pathsRequested.includes('/robots.txt') && pathsRequested.length > 2;
  const hasSitemapFollowUp =
    pathsRequested.includes('/sitemap.xml') && pathsRequested.length > 2;

  // Breadth-first: many unique top-level paths, few revisits
  const topLevelPaths = pathsRequested.map((p) => '/' + p.split('/')[1]);
  const uniqueTopLevel = new Set(topLevelPaths).size;
  const breadthFirstPattern = uniqueTopLevel / Math.max(1, pathsRequested.length) > 0.7;

  // Depth-first: repeated prefix, increasing specificity
  const prefixGroups: Record<string, number> = {};
  for (const p of pathsRequested) {
    const prefix = p.split('/').slice(0, 2).join('/');
    prefixGroups[prefix] = (prefixGroups[prefix] ?? 0) + 1;
  }
  const maxGroup = Math.max(...Object.values(prefixGroups));
  const depthFirstPattern = maxGroup / Math.max(1, pathsRequested.length) > 0.6;

  // Scanner path hit-rate — real humans don't request /.env or /wp-login.php
  const scannerPathHits = pathsRequested.filter(
    (p) => SCANNER_PATH_PATTERNS.some((re) => re.test(p)),
  ).length;
  const scannerPathRatio = scannerPathHits / Math.max(1, pathsRequested.length);

  let confidence = 0;
  if (breadthFirstPattern && requests.length > 10) confidence += 0.4;
  if (hasRobotsFollowUp || hasSitemapFollowUp) confidence += 0.2;
  // Key fix: scanner paths override timing/header signals — regardless of UA or speed
  if (scannerPathRatio > 0.3) confidence += 0.5;
  if (scannerPathHits >= 2) confidence += 0.3;

  const techniqueIds = lookupTechniquesForPaths(pathsRequested);

  return {
    pathsRequested,
    methodDistribution,
    hasRobotsFollowUp,
    hasSitemapFollowUp,
    breadthFirstPattern,
    depthFirstPattern,
    confidence: Math.min(1, confidence),
    scannerPathHits,
    scannerPathRatio,
    techniqueIds,
  };
}
