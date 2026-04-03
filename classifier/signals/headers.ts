export interface HeaderSignal {
  userAgent: string | null;
  acceptLanguage: string | null;
  hasTypicalBrowserHeaders: boolean;
  isCurlOrScript: boolean;
  headerOrderHash: string;
  confidence: number;
}

// Known non-browser UA fragments
const SCRIPTED_UA_PATTERNS = [
  /curl\//i,
  /python-requests/i,
  /go-http-client/i,
  /okhttp/i,
  /java\//i,
  /nuclei/i,
  /masscan/i,
  /zgrab/i,
  /libwww-perl/i,
  /scrapy/i,
  /wget\//i,
];

const BROWSER_HEADERS = ['accept', 'accept-language', 'accept-encoding', 'sec-ch-ua'];

export function analyzeHeaders(headers: Record<string, string>): HeaderSignal {
  const ua = headers['user-agent'] ?? null;
  const acceptLanguage = headers['accept-language'] ?? null;

  const isCurlOrScript =
    ua === null || SCRIPTED_UA_PATTERNS.some((re) => re.test(ua));

  const hasTypicalBrowserHeaders = BROWSER_HEADERS.every(
    (h) => h in headers,
  );

  const headerOrderHash = Object.keys(headers).join(',');

  let confidence = 0;
  if (isCurlOrScript) confidence += 0.5;
  if (!hasTypicalBrowserHeaders) confidence += 0.3;

  return {
    userAgent: ua,
    acceptLanguage,
    hasTypicalBrowserHeaders,
    isCurlOrScript,
    headerOrderHash,
    confidence: Math.min(1, confidence),
  };
}
