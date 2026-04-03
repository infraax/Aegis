export interface TimingSignal {
  requestIntervals: number[];     // ms between successive requests
  coefficientOfVariation: number; // stddev / mean  (<0.1 over 5+ req = automated)
  requestsPerSecond: number;
  isMetronomic: boolean;          // exact or near-exact intervals
  confidence: number;             // 0–1
}

export function analyzeTimings(timestamps: number[]): TimingSignal {
  if (timestamps.length < 2) {
    return {
      requestIntervals: [],
      coefficientOfVariation: 1,
      requestsPerSecond: 0,
      isMetronomic: false,
      confidence: 0,
    };
  }

  const intervals: number[] = [];
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push(timestamps[i] - timestamps[i - 1]);
  }

  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance =
    intervals.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / intervals.length;
  const stddev = Math.sqrt(variance);
  const cv = mean > 0 ? stddev / mean : 1;

  const spanSeconds =
    (timestamps[timestamps.length - 1] - timestamps[0]) / 1000;
  const rps = spanSeconds > 0 ? timestamps.length / spanSeconds : 0;

  const isMetronomic = cv < 0.05 && intervals.length >= 4;

  let confidence = 0;
  if (rps > 10) confidence = Math.min(1, confidence + 0.5);
  if (cv < 0.1 && intervals.length >= 5) confidence = Math.min(1, confidence + 0.4);
  if (isMetronomic) confidence = Math.min(1, confidence + 0.3);

  return { requestIntervals: intervals, coefficientOfVariation: cv, requestsPerSecond: rps, isMetronomic, confidence };
}
