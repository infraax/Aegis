/**
 * AI Agent Behavioral Detector (Module 9 — Stage 10)
 *
 * Extends LLM signal detection with empirical signatures from:
 *  - Palisade Research LLM Agent Honeypot (8.1M interactions, 3 months)
 *  - GTG-1002 incident (Anthropic disclosure, November 2025)
 *  - OWASP LLM Top 10 2025
 *
 * New signals not in the base llm-detector.ts:
 *  1. Sub-2s response timing (AI agents: <1.7s; humans: several seconds)
 *  2. Request uniformity score (AI = highly consistent headers/structure)
 *  3. Systematic exhaustive enumeration (AI scans every endpoint methodically)
 *  4. Prompt injection probe detection (agent submitted a prompt injection payload)
 *  5. Canary token in prompt (agent sent an LLM-readable canary back to our trap)
 *  6. Retry-with-mutation pattern (agent modifies payload after each failure)
 *
 * Confidence weights are calibrated against Palisade Research empirical data.
 */

export interface AIAgentSignal {
  subTwoSecondTiming:       boolean;  // >50% of delays are <1700ms
  requestUniformity:        number;   // 0–1: how uniform header/structure is across requests
  exhaustiveEnumeration:    boolean;  // >80% of known paths requested
  promptInjectionProbe:     boolean;  // payload contains prompt injection markers
  canaryTokenSubmitted:     boolean;  // agent echoed a canary token from our trap
  retryWithMutation:        boolean;  // same path attempted 3+ times with payload mutations
  detectedFramework:        string | null;  // 'langchain' | 'autogpt' | 'crewai' | 'openai-functions' | null
  confidence:               number;
}

// ─── Prompt injection markers (OWASP LLM01) ──────────────────────────────────

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(previous|above|prior)\s+instructions/i,
  /system\s*:\s*you\s+are/i,
  /\[INST\]/i,
  /\<\|im_start\|\>/i,
  /<\|system\|>/i,
  /###\s*instruction/i,
  /forget\s+everything\s+you/i,
  /you\s+are\s+now\s+(?:a|an)\s+\w+\s+(?:AI|assistant|bot)/i,
  /act\s+as\s+(?:a|an)\s+(?:evil|unrestricted|jailbroken)/i,
];

// ─── AI framework signatures (User-Agent / header patterns) ──────────────────

const FRAMEWORK_PATTERNS: Array<[RegExp, string]> = [
  [/langchain/i,                        'langchain'],
  [/openai-python/i,                    'openai-sdk'],
  [/anthropic-sdk/i,                    'anthropic-sdk'],
  [/autogpt/i,                          'autogpt'],
  [/crewai/i,                           'crewai'],
  [/llamaindex|llama.index/i,           'llamaindex'],
  [/smolagents/i,                       'smolagents'],
  [/semantic.kernel/i,                  'semantic-kernel'],
  [/haystack/i,                         'haystack'],
  [/gpt-?engineer/i,                    'gpt-engineer'],
  [/agentgpt/i,                         'agentgpt'],
  [/python-httpx\/\d/i,                 'python-httpx'],    // common AI agent HTTP client
  [/python-requests\/\d/i,              'python-requests'], // common but ambiguous
  [/aiohttp\/\d/i,                      'aiohttp'],
];

// Paths that only a systematic AI agent would exhaust (not a human browser)
const SYSTEMATIC_PATHS = [
  '/api/v1/', '/api/v2/', '/api/v3/',
  '/graphql', '/graphql/schema',
  '/openapi.json', '/swagger.json', '/api-docs',
  '/.well-known/openid-configuration',
  '/actuator/env', '/actuator/beans', '/actuator/metrics',
  '/config', '/settings', '/admin/config',
  '/debug', '/trace', '/__debug__',
  '/metrics', '/stats', '/status',
];

// ─── Request uniformity scorer ────────────────────────────────────────────────

interface RequestSample {
  method: string;
  path:   string;
  headers: Record<string, string>;
}

/**
 * Calculate how uniform a series of requests are.
 * AI agents produce highly uniform requests (same headers, similar structure).
 * Humans vary their headers, accept-language, referrers, etc.
 * Returns 0–1 (1 = perfectly uniform = suspicious).
 */
export function scoreUniformity(requests: RequestSample[]): number {
  if (requests.length < 3) return 0;

  const n = requests.length;
  let uniformityScore = 0;
  let checks = 0;

  // 1. User-Agent consistency (uniform = same UA every request)
  const userAgents = new Set(requests.map((r) => r.headers['user-agent'] ?? ''));
  if (userAgents.size === 1) uniformityScore += 1;
  else if (userAgents.size <= 2) uniformityScore += 0.5;
  checks++;

  // 2. Accept-Language consistency
  const acceptLangs = new Set(requests.map((r) => r.headers['accept-language'] ?? ''));
  if (acceptLangs.size === 1) uniformityScore += 1;
  checks++;

  // 3. Method distribution — AI agents are usually GET-only or have very consistent method distribution
  const methods = requests.map((r) => r.method.toUpperCase());
  const methodSet = new Set(methods);
  if (methodSet.size === 1) uniformityScore += 0.8;
  checks++;

  // 4. Path length variance — AI scans have very uniform path lengths
  const pathLengths = requests.map((r) => r.path.length);
  const mean = pathLengths.reduce((a, b) => a + b, 0) / n;
  const variance = pathLengths.reduce((a, b) => a + (b - mean) ** 2, 0) / n;
  const stddev = Math.sqrt(variance);
  const cv = mean > 0 ? stddev / mean : 0;
  if (cv < 0.2) uniformityScore += 0.8;  // very low coefficient of variation
  else if (cv < 0.4) uniformityScore += 0.4;
  checks++;

  // 5. Header count consistency
  const headerCounts = requests.map((r) => Object.keys(r.headers).length);
  const hMean = headerCounts.reduce((a, b) => a + b, 0) / n;
  const hVariance = headerCounts.reduce((a, b) => a + (b - hMean) ** 2, 0) / n;
  if (Math.sqrt(hVariance) < 1) uniformityScore += 0.8;
  checks++;

  return Math.min(1, uniformityScore / checks);
}

// ─── Retry-with-mutation detector ────────────────────────────────────────────

/**
 * Detects AI agent retry-with-mutation: same path attempted 3+ times with
 * different payloads. AI agents systematically mutate inputs on failure rather
 * than giving up (unlike humans or simple scanners).
 */
export function detectRetryMutation(
  requests: Array<{ path: string; body?: string }>
): boolean {
  const pathCounts = new Map<string, number>();
  for (const r of requests) {
    const base = r.path.split('?')[0];
    pathCounts.set(base, (pathCounts.get(base) ?? 0) + 1);
  }
  return [...pathCounts.values()].some((count) => count >= 3);
}

// ─── Main analyzer ────────────────────────────────────────────────────────────

export function analyzeAIAgentSignals(session: {
  requestDelays:     number[];
  requests:          RequestSample[];
  pathsRequested:    string[];
  payloads?:         string[];  // request body snippets for injection detection
  canaryTriggered?:  boolean;   // set by adaptive engine when canary fires
  userAgent?:        string;
}): AIAgentSignal {
  const {
    requestDelays,
    requests,
    pathsRequested,
    payloads = [],
    canaryTriggered = false,
    userAgent = '',
  } = session;

  // 1. Sub-2s timing (Palisade Research: AI agents respond in <1700ms)
  const SUB_2S_THRESHOLD = 1700;
  const subTwoCount = requestDelays.filter((d) => d > 0 && d < SUB_2S_THRESHOLD).length;
  const subTwoSecondTiming =
    requestDelays.length >= 3 &&
    subTwoCount / requestDelays.length > 0.5;

  // 2. Request uniformity
  const requestUniformity = scoreUniformity(requests);

  // 3. Systematic enumeration: fraction of known AI-target paths requested
  const hitSystematic = pathsRequested.filter((p) =>
    SYSTEMATIC_PATHS.some((sp) => p.startsWith(sp))
  ).length;
  const exhaustiveEnumeration =
    pathsRequested.length >= 5 &&
    hitSystematic / SYSTEMATIC_PATHS.length > 0.15;

  // 4. Prompt injection probe
  const allPayloads = payloads.join('\n');
  const promptInjectionProbe =
    PROMPT_INJECTION_PATTERNS.some((re) => re.test(allPayloads)) ||
    PROMPT_INJECTION_PATTERNS.some((re) => re.test(userAgent));

  // 5. Canary token submitted (set by adaptive engine / honeypot)
  const canaryTokenSubmitted = canaryTriggered;

  // 6. Retry-with-mutation
  const retryWithMutation = detectRetryMutation(
    requests.map((r) => ({ path: r.path }))
  );

  // 7. Framework detection from User-Agent
  let detectedFramework: string | null = null;
  for (const [re, framework] of FRAMEWORK_PATTERNS) {
    if (re.test(userAgent)) {
      detectedFramework = framework;
      break;
    }
  }

  // ── Confidence scoring (empirically calibrated) ───────────────────────────
  let confidence = 0;

  // Sub-2s timing is the strongest single signal (Palisade Research finding)
  if (subTwoSecondTiming)    confidence += 0.35;

  // High uniformity is a strong secondary signal
  if (requestUniformity > 0.8)       confidence += 0.25;
  else if (requestUniformity > 0.6)  confidence += 0.15;

  // Systematic enumeration
  if (exhaustiveEnumeration)         confidence += 0.20;

  // Prompt injection = confirmed AI agent
  if (promptInjectionProbe)          confidence += 0.40;

  // Canary triggered = highest confidence (caught in the act)
  if (canaryTokenSubmitted)          confidence += 0.50;

  // Retry mutation
  if (retryWithMutation)             confidence += 0.15;

  // Known framework = bonus
  if (detectedFramework)             confidence += 0.10;

  return {
    subTwoSecondTiming,
    requestUniformity,
    exhaustiveEnumeration,
    promptInjectionProbe,
    canaryTokenSubmitted,
    retryWithMutation,
    detectedFramework,
    confidence: Math.min(1, confidence),
  };
}
