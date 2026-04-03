/**
 * Threat Intelligence correlation.
 * Cross-references observed IPs against free-tier open threat databases.
 */

import axios from 'axios';
import { logger } from '../shared/logger.js';

export interface ThreatIntelMatch {
  source: string;
  category: string;
  confidence: number;
  detail: string;
}

export interface AttackerProfile {
  ip: string;
  firstSeen: number;
  lastSeen: number;
  sessionCount: number;
  tierClassification: 1 | 2 | 3;
  toolsUsed: string[];
  vpnChain: string[];
  estimatedRealASN: string | null;
  threatIntelMatches: ThreatIntelMatch[];
  canaryTokensTriggered: string[];
  contextBombsDelivered: string[];
  tacticsObserved: string[];
  attributionConfidence: number;
  fullDossier: Record<string, unknown>;
}

const profiles = new Map<string, AttackerProfile>();

export function getOrCreateProfile(ip: string): AttackerProfile {
  if (!profiles.has(ip)) {
    profiles.set(ip, {
      ip,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      sessionCount: 1,
      tierClassification: 1,
      toolsUsed: [],
      vpnChain: [],
      estimatedRealASN: null,
      threatIntelMatches: [],
      canaryTokensTriggered: [],
      contextBombsDelivered: [],
      tacticsObserved: [],
      attributionConfidence: 0,
      fullDossier: {},
    });
  }
  return profiles.get(ip)!;
}

export async function enrichProfile(ip: string): Promise<AttackerProfile> {
  const profile = getOrCreateProfile(ip);
  profile.lastSeen = Date.now();

  const matches: ThreatIntelMatch[] = [];

  // AbuseIPDB check
  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  if (abuseKey) {
    try {
      const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        headers: { Key: abuseKey, Accept: 'application/json' },
        params: { ipAddress: ip, maxAgeInDays: 90 },
        timeout: 8_000,
      });
      const d = res.data?.data;
      if (d?.abuseConfidenceScore > 0) {
        matches.push({
          source: 'AbuseIPDB',
          category: d.usageType ?? 'unknown',
          confidence: d.abuseConfidenceScore / 100,
          detail: `${d.totalReports} reports, last seen ${d.lastReportedAt}`,
        });
      }
    } catch (err) {
      logger.debug('AbuseIPDB lookup failed', { ip, err });
    }
  }

  // Shodan InternetDB (free, no key)
  try {
    const res = await axios.get(`https://internetdb.shodan.io/${ip}`, { timeout: 8_000 });
    const d = res.data as { ports?: number[]; vulns?: string[]; tags?: string[] };
    if (d.vulns && d.vulns.length > 0) {
      matches.push({
        source: 'Shodan',
        category: 'known_vulnerabilities',
        confidence: 0.9,
        detail: `Open ports: ${(d.ports ?? []).join(',')} | CVEs: ${d.vulns.join(',')}`,
      });
    }
  } catch {
    // Non-critical
  }

  profile.threatIntelMatches.push(...matches);
  profile.attributionConfidence = Math.min(
    1,
    matches.reduce((acc, m) => acc + m.confidence * 0.3, 0),
  );

  return profile;
}
