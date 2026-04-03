/**
 * VPN / Proxy / Tor detection — multi-method to make evasion harder.
 */

import axios from 'axios';
import dns from 'dns/promises';
import { logger } from '../shared/logger.js';

export interface VPNDetectionResult {
  ip: string;
  isVPN: boolean;
  isTor: boolean;
  isDatacenter: boolean;
  provider: string | null;
  method: string[];   // which methods triggered
  confidence: number;
}

// Known datacenter / VPN ASNs (small sample — load full list from file in production)
const DATACENTER_ASNS = new Set([
  'AS14061', // DigitalOcean
  'AS20473', // Vultr
  'AS63949', // Linode/Akamai
  'AS16509', // Amazon AWS
  'AS15169', // Google Cloud
  'AS8075',  // Azure
  'AS39351', // Mullvad VPN
  'AS9009',  // M247 (NordVPN infra)
]);

let torExitNodes: Set<string> | null = null;
let torExitFetchedAt = 0;
const TOR_CACHE_TTL_MS = 3_600_000; // 1 hour

async function getTorExitNodes(): Promise<Set<string>> {
  if (torExitNodes && Date.now() - torExitFetchedAt < TOR_CACHE_TTL_MS) {
    return torExitNodes;
  }
  try {
    const res = await axios.get(
      'https://check.torproject.org/torbulkexitlist',
      { timeout: 10_000, responseType: 'text' },
    );
    torExitNodes = new Set((res.data as string).split('\n').map((l: string) => l.trim()).filter(Boolean));
    torExitFetchedAt = Date.now();
    return torExitNodes;
  } catch (err) {
    logger.warn('failed to fetch Tor exit list', { err });
    return new Set();
  }
}

export async function detectVPN(ip: string, asn: string | null): Promise<VPNDetectionResult> {
  const triggeredMethods: string[] = [];
  let isVPN = false;
  let isTor = false;
  let isDatacenter = false;
  let provider: string | null = null;

  // Method 1: ASN reputation
  if (asn && DATACENTER_ASNS.has(asn)) {
    isDatacenter = true;
    triggeredMethods.push('asn_reputation');
    if (asn === 'AS39351') { isVPN = true; provider = 'Mullvad'; }
    else if (asn === 'AS9009') { isVPN = true; provider = 'NordVPN'; }
  }

  // Method 2: PTR record analysis
  try {
    const ptrs = await dns.reverse(ip);
    if (ptrs.length > 0) {
      const ptr = ptrs[0].toLowerCase();
      if (/vpn|mullvad|nordvpn|expressvpn|proton/.test(ptr)) {
        isVPN = true;
        triggeredMethods.push('ptr_record');
        provider = provider ?? ptr.split('.')[0];
      }
    } else {
      // No PTR → datacenter / VPN heuristic
      triggeredMethods.push('no_ptr');
      isDatacenter = true;
    }
  } catch {
    triggeredMethods.push('ptr_failed');
  }

  // Method 3: Tor exit node list
  const exits = await getTorExitNodes();
  if (exits.has(ip)) {
    isTor = true;
    isVPN = true;
    provider = 'Tor';
    triggeredMethods.push('tor_exit_list');
  }

  const confidence = Math.min(
    1,
    (isVPN ? 0.5 : 0) + (isTor ? 0.5 : 0) + (isDatacenter ? 0.2 : 0),
  );

  return { ip, isVPN, isTor, isDatacenter, provider, method: triggeredMethods, confidence };
}
