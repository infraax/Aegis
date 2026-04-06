/**
 * JA3/JA4 TLS Fingerprint Signal
 *
 * Scores a session based on its TLS client fingerprint.
 *
 * How the fingerprint reaches Aegis:
 *   Suricata computes JA3/JA4 from the raw TLS ClientHello on the wire and
 *   writes it to EVE JSON (tls.ja3.hash, tls.ja4).
 *   attribution/suricata-tail.ts reads the EVE stream and populates a shared
 *   Redis key: "aegis:ja3:<sourceIp>" = { ja3, ja4 }.
 *   The proxy (nginx lua / envoy ext-proc) reads that key and injects two
 *   headers into forwarded requests:
 *     X-Aegis-JA3: <md5-hex>
 *     X-Aegis-JA4: <ja4-string>
 *   classifier/index.ts extracts those headers and passes them here.
 *
 * Graceful degradation:
 *   If neither header is present (proxy hasn't seen the TLS hello yet, or
 *   Suricata isn't running), this signal returns confidence 0 and the
 *   classifier continues with existing signals unchanged.
 *
 * Known-malicious fingerprint lists:
 *   JA3: https://sslbl.abuse.ch/ja3-fingerprints/  (regularly updated)
 *   The list embedded here is a static bootstrap subset — update via
 *   scripts/update-ja3-blocklist.sh or the upcoming Stage 5 Gaffer feed.
 */

import { logger } from '../../shared/logger.js';

export interface JA3Signal {
  ja3Hash: string | null;
  ja4Hash: string | null;
  isKnownMalicious: boolean;
  matchedTool: string | null;  // e.g. "Metasploit", "CobaltStrike", "Sliver"
  confidence: number;
}

// ─── Known-malicious JA3 fingerprints ────────────────────────────────────────
// Source: abuse.ch SSLBL + community research
// Format: { hash: toolName }
// Keep sorted for binary search if this grows large.

const MALICIOUS_JA3: Record<string, string> = {
  // Metasploit (Meterpreter reverse HTTPS default)
  'fd7c1f7c58f7e35ab9eb31c2b39d5ee7': 'Metasploit',
  'ae4edc6faf64d08308082ad26be60767': 'Metasploit',
  '6734f37431670b3ab4292b8f60f29984': 'Metasploit',

  // Cobalt Strike default malleable C2
  '72a589da586844d7f0818ce684948eea': 'CobaltStrike',
  'a0e9f5d64349fb13191bc781f81f42e1': 'CobaltStrike',
  '1aa7bf6b9b8a685cde7b0c5bfe21e8b7': 'CobaltStrike',

  // Sliver implant (mTLS mode)
  'd0ec4b50a944b182fc10ff51f883ccf7': 'Sliver',
  '6676d40dafdb5e0c041f8ac9a53c7b36': 'Sliver',

  // Brute Ratel C4
  'e7d705a3286e19ea42f587b6f7761b7d': 'BruteRatelC4',

  // HAVOC C2 (Microsoft Graph channel fallback)
  'b32309a26951912be7dba376398d2d3f': 'Havoc',

  // Mythic C2
  '30c9e5c3e3a9e5a82b88a892db82c850': 'Mythic',
};

// ─── Known-malicious JA4 prefixes (first 12 chars identify the client) ────────
// JA4 format: t<version><sni><ciphers><extensions>_<cipher_hash>_<ext_hash>
// We match on the first segment which identifies TLS version + cipher profile

const MALICIOUS_JA4_PREFIXES: Record<string, string> = {
  't13d190900_': 'Metasploit',   // TLS 1.3, Metasploit cipher suite
  't12d190900_': 'Metasploit',   // TLS 1.2 variant
  't13d201100_': 'CobaltStrike',
  't13d881100_': 'Sliver',
};

// ─── Analysis ─────────────────────────────────────────────────────────────────

export function analyzeJA3(ja3: string | null, ja4: string | null): JA3Signal {
  if (!ja3 && !ja4) {
    return { ja3Hash: null, ja4Hash: null, isKnownMalicious: false, matchedTool: null, confidence: 0 };
  }

  let matchedTool: string | null = null;

  // Check exact JA3 match
  if (ja3) {
    const tool = MALICIOUS_JA3[ja3.toLowerCase()];
    if (tool) {
      matchedTool = tool;
      logger.warn('ja3-signal: known-malicious JA3 fingerprint', { ja3, tool });
    }
  }

  // Check JA4 prefix match (fallback if JA3 not available or not matched)
  if (!matchedTool && ja4) {
    for (const [prefix, tool] of Object.entries(MALICIOUS_JA4_PREFIXES)) {
      if (ja4.toLowerCase().startsWith(prefix)) {
        matchedTool = tool;
        logger.warn('ja3-signal: known-malicious JA4 prefix', { ja4, tool });
        break;
      }
    }
  }

  const isKnownMalicious = matchedTool !== null;

  // Confidence:
  //   0.95 — exact JA3 match in blocklist (very high signal)
  //   0.75 — JA4 prefix match (strong but less specific)
  //   0.10 — JA3/JA4 present but not matched (unusual client, mild signal)
  let confidence: number;
  if (isKnownMalicious && ja3 && MALICIOUS_JA3[ja3.toLowerCase()]) {
    confidence = 0.95;
  } else if (isKnownMalicious) {
    confidence = 0.75;
  } else {
    confidence = 0.10; // non-browser fingerprint is worth a small bump
  }

  return { ja3Hash: ja3, ja4Hash: ja4, isKnownMalicious, matchedTool, confidence };
}

/** Known-malicious fingerprint count — for health check / logging */
export function getBlocklistSize(): { ja3: number; ja4Prefixes: number } {
  return { ja3: Object.keys(MALICIOUS_JA3).length, ja4Prefixes: Object.keys(MALICIOUS_JA4_PREFIXES).length };
}

/** Exposed for tests — allows adding test fingerprints */
export function _addFingerprintForTest(ja3Hash: string, tool: string): void {
  MALICIOUS_JA3[ja3Hash.toLowerCase()] = tool;
}

/** Exposed for tests — remove test fingerprints */
export function _removeFingerprintForTest(ja3Hash: string): void {
  delete MALICIOUS_JA3[ja3Hash.toLowerCase()];
}
