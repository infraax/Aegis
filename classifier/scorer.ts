import type { TimingSignal } from './signals/timing.js';
import type { HeaderSignal } from './signals/headers.js';
import type { TLSSignal } from './signals/tls.js';
import type { BehavioralSignal } from './signals/behavioral.js';
import type { LLMSignal } from './signals/llm-detector.js';
import type { ToolMatch } from './signals/tool-sigs.js';

export type Tier = 1 | 2 | 3;

export interface SignalResult {
  name: string;
  score: number;
  weight: number;
}

export interface Classification {
  tier: Tier;
  confidence: number;
  signals: SignalResult[];
  toolIdentified: string | null;
  sessionId: string;
  timestamp: number;
}

// Tier thresholds — tune after observing real traffic
const TIER_THRESHOLDS = {
  scanner: 0.6,   // Tier 1
  aiAgent: 0.65,  // Tier 2
  targeted: 0.8,  // Tier 3 (escalate)
};

export function classify(input: {
  sessionId: string;
  timing: TimingSignal;
  headers: HeaderSignal;
  tls: TLSSignal;
  behavioral: BehavioralSignal;
  llm: LLMSignal;
  toolMatch: ToolMatch | null;
}): Classification {
  const { sessionId, timing, headers, tls, behavioral, llm, toolMatch } = input;

  const signals: SignalResult[] = [
    { name: 'timing',     score: timing.confidence,    weight: 0.20 },
    { name: 'headers',    score: headers.confidence,   weight: 0.10 },
    { name: 'tls',        score: tls.confidence,       weight: 0.15 },
    { name: 'behavioral', score: behavioral.confidence, weight: 0.20 },
    { name: 'llm',        score: llm.confidence,       weight: 0.35 },
  ];

  const weightedScore = signals.reduce((acc, s) => acc + s.score * s.weight, 0);
  const toolIdentified = toolMatch?.tool ?? llm.detectedFormat ?? null;

  // Determine tier
  let tier: Tier;
  let confidence: number;

  if (llm.confidence >= TIER_THRESHOLDS.aiAgent) {
    tier = 2;
    confidence = llm.confidence;
  } else if (weightedScore >= TIER_THRESHOLDS.scanner) {
    tier = 1;
    confidence = weightedScore;
  } else if (behavioral.depthFirstPattern && !timing.isMetronomic) {
    // Slow, methodical, human-like — possible Tier 3
    tier = 3;
    confidence = TIER_THRESHOLDS.targeted;
  } else {
    // Default: treat as scanner (safest assumption)
    tier = 1;
    confidence = weightedScore;
  }

  // Known tools bump confidence
  if (toolMatch) {
    confidence = Math.min(1, confidence + toolMatch.confidence * 0.2);
  }

  return {
    tier,
    confidence: Math.min(1, confidence),
    signals,
    toolIdentified,
    sessionId,
    timestamp: Date.now(),
  };
}
