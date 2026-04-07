/**
 * ASN + BGP intelligence lookup.
 * Uses Shodan InternetDB (free, no key) and MaxMind GeoLite2.
 */

import axios from 'axios';
import { logger } from '../shared/logger.js';

export interface ASNData {
  ip: string;
  asn: string | null;
  org: string | null;
  country: string | null;
  city: string | null;
  prefixSize: number | null; // /24 = datacenter heuristic
}

// InternetDB actual response: { ip, ports, cpes, hostnames, tags, vulns }
// ASN/org/country are NOT in InternetDB — use ipapi.co (free, no key) for geo/ASN
export async function lookupASN(ip: string): Promise<ASNData> {
  try {
    // ipapi.co — free tier, 1000 req/day, no key needed
    const res = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 8_000 });
    const d = res.data as { asn?: string; org?: string; country_name?: string; city?: string };
    return {
      ip,
      asn: d.asn ?? null,
      org: d.org ?? null,
      country: d.country_name ?? null,
      city: d.city ?? null,
      prefixSize: null,
    };
  } catch (err) {
    logger.debug('ASN lookup failed', { ip, err });
    return { ip, asn: null, org: null, country: null, city: null, prefixSize: null };
  }
}

// Shodan InternetDB — open ports + vulns (separate concern from ASN)
export async function lookupShodanInternetDB(ip: string): Promise<{ ports: number[]; vulns: string[]; hostnames: string[] }> {
  try {
    const res = await axios.get(`https://internetdb.shodan.io/${ip}`, { timeout: 8_000 });
    const d = res.data as { ports?: number[]; vulns?: string[]; hostnames?: string[] };
    return { ports: d.ports ?? [], vulns: d.vulns ?? [], hostnames: d.hostnames ?? [] };
  } catch {
    return { ports: [], vulns: [], hostnames: [] };
  }
}
