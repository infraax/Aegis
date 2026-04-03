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

export async function lookupASN(ip: string): Promise<ASNData> {
  try {
    // Shodan InternetDB — free, no auth required
    const res = await axios.get(`https://internetdb.shodan.io/${ip}`, { timeout: 8_000 });
    const data = res.data as { asn?: string; org?: string; country?: string };
    return {
      ip,
      asn: data.asn ?? null,
      org: data.org ?? null,
      country: data.country ?? null,
      city: null,
      prefixSize: null,
    };
  } catch (err) {
    logger.debug('ASN lookup failed', { ip, err });
    return { ip, asn: null, org: null, country: null, city: null, prefixSize: null };
  }
}
