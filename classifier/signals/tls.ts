// TLS JA3/JA4 fingerprinting signal.
// In production, raw ClientHello bytes are captured via libpcap/tshark
// on the deception interface before traffic reaches the application layer.
// This module normalises the fingerprint and looks it up against known hashes.

export interface TLSSignal {
  ja3Hash: string | null;       // MD5 of (SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
  ja4Hash: string | null;       // JA4 fingerprint (next-gen, human-readable)
  knownTool: string | null;     // 'curl' | 'python-requests' | 'nuclei' | etc.
  isMaliciousHash: boolean;
  confidence: number;
}

// Sample known JA3 hashes (expand this database from ja3er.com / tls.peet.ws)
const KNOWN_JA3: Record<string, string> = {
  'e809e3a1a5a42d97bce3d67b3d75c5f1': 'curl/7.x',
  '6734f37431670b3ab4292b8f60f29984': 'python-requests',
  'b32309a26951912be7dba376398abc3b': 'go-net-http',
  '3b5074b1b5d032e5620bacd68dafb54b': 'nuclei',
  '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0': 'chrome-like',
};

// Hashes observed in known malicious scanning campaigns
const MALICIOUS_JA3_HASHES = new Set<string>([
  '3b5074b1b5d032e5620bacd68dafb54b', // nuclei
]);

export function analyzeTLS(ja3Hash: string | null, ja4Hash: string | null): TLSSignal {
  if (!ja3Hash && !ja4Hash) {
    return { ja3Hash: null, ja4Hash: null, knownTool: null, isMaliciousHash: false, confidence: 0 };
  }

  const knownTool = ja3Hash ? (KNOWN_JA3[ja3Hash] ?? null) : null;
  const isMaliciousHash = ja3Hash ? MALICIOUS_JA3_HASHES.has(ja3Hash) : false;

  let confidence = 0;
  if (knownTool && !knownTool.includes('chrome')) confidence += 0.4;
  if (isMaliciousHash) confidence += 0.6;

  return { ja3Hash, ja4Hash, knownTool, isMaliciousHash, confidence: Math.min(1, confidence) };
}
