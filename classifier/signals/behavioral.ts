// Behavioral pattern analysis — tracks request sequences within a session.

export interface BehavioralSignal {
  pathsRequested: string[];
  methodDistribution: Record<string, number>;
  hasRobotsFollowUp: boolean;        // requested /robots.txt then enumerated paths from it
  hasSitemapFollowUp: boolean;
  breadthFirstPattern: boolean;      // wide + shallow (scanner)
  depthFirstPattern: boolean;        // narrow + deep (targeted / agent)
  confidence: number;
}

export function analyzeBehavior(requests: Array<{ method: string; path: string }>): BehavioralSignal {
  const pathsRequested = requests.map((r) => r.path);
  const methodDistribution: Record<string, number> = {};

  for (const r of requests) {
    methodDistribution[r.method] = (methodDistribution[r.method] ?? 0) + 1;
  }

  const hasRobotsFollowUp =
    pathsRequested.includes('/robots.txt') && pathsRequested.length > 2;
  const hasSitemapFollowUp =
    pathsRequested.includes('/sitemap.xml') && pathsRequested.length > 2;

  // Breadth-first: many unique top-level paths, few revisits
  const topLevelPaths = pathsRequested.map((p) => '/' + p.split('/')[1]);
  const uniqueTopLevel = new Set(topLevelPaths).size;
  const breadthFirstPattern = uniqueTopLevel / Math.max(1, pathsRequested.length) > 0.7;

  // Depth-first: repeated prefix, increasing specificity
  const prefixGroups: Record<string, number> = {};
  for (const p of pathsRequested) {
    const prefix = p.split('/').slice(0, 2).join('/');
    prefixGroups[prefix] = (prefixGroups[prefix] ?? 0) + 1;
  }
  const maxGroup = Math.max(...Object.values(prefixGroups));
  const depthFirstPattern = maxGroup / Math.max(1, pathsRequested.length) > 0.6;

  let confidence = 0;
  if (breadthFirstPattern && requests.length > 10) confidence += 0.4;
  if (hasRobotsFollowUp || hasSitemapFollowUp) confidence += 0.2;

  return {
    pathsRequested,
    methodDistribution,
    hasRobotsFollowUp,
    hasSitemapFollowUp,
    breadthFirstPattern,
    depthFirstPattern,
    confidence: Math.min(1, confidence),
  };
}
