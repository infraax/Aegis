// AI / LLM agent detection signal.
// LLM-driven agents exhibit characteristic behavioral tells that differ from
// both human browsers and traditional scripted scanners.

export interface LLMSignal {
  semantic404FollowUp: boolean;       // understood 404 content, requested related path
  documentationEnumeration: boolean;  // enumerated endpoints from /docs or /openapi
  errorMessageInterpretation: boolean;// acted on fake error semantics (e.g., probed DB port after "DB error")
  structuredCredentialTesting: boolean;
  contextRetention: boolean;          // references content from earlier in the session
  tokenRateTiming: boolean;           // response-processing delay in LLM range (800–8000ms)
  detectedFormat: string | null;      // 'openai' | 'langchain' | 'autogpt' | 'crewai' | null
  confidence: number;
}

const LLM_TIMING = { minMs: 800, maxMs: 8000 };

export function analyzeLLMSignals(session: {
  requestDelays: number[];            // ms between receiving response and next request
  paths: string[];
  responsesActedOn: Array<{ responseSnippet: string; followUpPath: string }>;
}): LLMSignal {
  // Token-rate timing: LLMs take 0.8–8s to process and generate next request
  const timingMatches = session.requestDelays.filter(
    (d) => d >= LLM_TIMING.minMs && d <= LLM_TIMING.maxMs,
  );
  const tokenRateTiming =
    timingMatches.length / Math.max(1, session.requestDelays.length) > 0.5;

  // Documentation enumeration
  const docPaths = ['/docs', '/swagger', '/openapi', '/api-docs', '/graphql'];
  const hitDocs = session.paths.some((p) => docPaths.some((d) => p.startsWith(d)));
  const documentationEnumeration = hitDocs && session.paths.length > 3;

  // Semantic 404 follow-up: after a 404, requested a path semantically related to the 404 body
  const semantic404FollowUp = session.responsesActedOn.some(
    (r) => r.responseSnippet.includes('not found') && r.followUpPath.length > 0,
  );

  // Error message interpretation: probed :5432 or /db after fake DB error in response
  const errorMessageInterpretation = session.responsesActedOn.some(
    (r) =>
      r.responseSnippet.toLowerCase().includes('database') &&
      (r.followUpPath.includes('5432') || r.followUpPath.includes('/db')),
  );

  const structuredCredentialTesting = session.paths.filter(
    (p) => p.includes('login') || p.includes('auth') || p.includes('token'),
  ).length > 2;

  // Context retention: path references an ID or name seen in an earlier response
  const contextRetention = false; // Requires response body diffing — implemented in adaptive engine

  let confidence = 0;
  if (tokenRateTiming) confidence += 0.35;
  if (documentationEnumeration) confidence += 0.25;
  if (semantic404FollowUp) confidence += 0.2;
  if (errorMessageInterpretation) confidence += 0.3;
  if (structuredCredentialTesting) confidence += 0.15;

  // Detect framework from User-Agent / header patterns (set externally)
  const detectedFormat: string | null = null;

  return {
    semantic404FollowUp,
    documentationEnumeration,
    errorMessageInterpretation,
    structuredCredentialTesting,
    contextRetention,
    tokenRateTiming,
    detectedFormat,
    confidence: Math.min(1, confidence),
  };
}
