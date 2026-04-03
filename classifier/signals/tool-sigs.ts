// Known scanner / tool fingerprints.
// Confidence scores are conservative — false positives are expensive.

export interface ToolSignature {
  name: string;
  confidence: number;
  indicators: string[];
}

export interface ToolMatch {
  tool: string;
  confidence: number;
}

export const KNOWN_SIGNATURES: ToolSignature[] = [
  {
    name: 'nuclei',
    confidence: 0.95,
    indicators: ['Nuclei', 'projectdiscovery', 'X-Nuclei-Template'],
  },
  {
    name: 'masscan',
    confidence: 0.98,
    indicators: ['masscan'],
  },
  {
    name: 'metasploit',
    confidence: 0.90,
    indicators: ['Metasploit'],
  },
  {
    name: 'shodan-crawler',
    confidence: 0.85,
    indicators: ['Shodan.io', 'Shodan'],
  },
  {
    name: 'zgrab',
    confidence: 0.92,
    indicators: ['zgrab'],
  },
  {
    name: 'langchain-agent',
    confidence: 0.80,
    indicators: ['langchain', 'python-httpx', 'openai'],
  },
  {
    name: 'openai-browsing',
    confidence: 0.75,
    indicators: ['GPTBot', 'ChatGPT-User'],
  },
  {
    name: 'autogpt',
    confidence: 0.78,
    indicators: ['AutoGPT', 'auto-gpt'],
  },
  {
    name: 'crewai',
    confidence: 0.76,
    indicators: ['crewai', 'CrewAI'],
  },
];

export function matchToolSignature(
  userAgent: string,
  headers: Record<string, string>,
): ToolMatch | null {
  const haystack = [
    userAgent,
    ...Object.values(headers),
  ].join(' ').toLowerCase();

  for (const sig of KNOWN_SIGNATURES) {
    if (sig.indicators.some((ind) => haystack.includes(ind.toLowerCase()))) {
      return { tool: sig.name, confidence: sig.confidence };
    }
  }
  return null;
}
