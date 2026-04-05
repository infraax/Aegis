/**
 * Maintainer Geography Enricher
 *
 * For packages where we can resolve a GitHub source repo, calls gitgeo
 * (via scripts/gitgeo_scan.py) to determine the geographic distribution of
 * recent committers.
 *
 * Integration pattern: Pattern C (subprocess bridge)
 *   - gitgeo stays in its own Python process
 *   - We own only this bridge + scripts/gitgeo_scan.py
 *   - Upgrade gitgeo independently: pip3 install --upgrade gitgeo
 *
 * What we flag:
 *   concentration_score > GEO_CONCENTRATION_THRESHOLD
 *   → A package where the majority of commits come from a single country.
 *   This is not proof of malice but is a supply chain risk signal worth
 *   human review — especially for packages in critical paths.
 *
 * Graceful degradation:
 *   - No GITHUB_TOKEN: rate limited but functional (60 req/hr)
 *   - gitgeo script missing: skipped, logged, pipeline continues
 *   - Network error: skipped, logged, pipeline continues
 *
 * Environment:
 *   GITHUB_TOKEN            — GitHub PAT for API calls (optional but recommended)
 *   GEO_CONCENTRATION_THRESHOLD — 0.0–1.0, default 0.75
 *   GEO_SCAN_TIMEOUT_MS     — per-repo timeout, default 30000
 */

import { spawn } from 'child_process';
import path from 'path';
import { logger } from '../shared/logger.js';

// CommonJS — __dirname is available directly
const SCRIPT_PATH = path.resolve(__dirname, '../scripts/gitgeo_scan.py');

const CONCENTRATION_THRESHOLD = parseFloat(
  process.env.GEO_CONCENTRATION_THRESHOLD ?? '0.75',
);
const TIMEOUT_MS = parseInt(process.env.GEO_SCAN_TIMEOUT_MS ?? '30000', 10);

// ─── Types ────────────────────────────────────────────────────────────────────

export interface GeoScanResult {
  repo: string;
  contributorsSampled: number;
  countryCounts: Record<string, number>;
  topCountry: string | null;
  topCountryPct: number;
  concentrationScore: number;   // 0.0–1.0 — fraction held by top country
  unknownPct: number;           // % of contributors with no location set
  flagged: boolean;             // true if concentration > threshold
  skipped: boolean;             // true if scan could not run
  error?: string;
}

// ─── Resolve GitHub repo slug from package metadata ──────────────────────────

/**
 * Best-effort extraction of a GitHub owner/repo slug from npm, PyPI, or
 * cargo package metadata.  Returns null if we can't find a GitHub URL.
 *
 * In production this would be enriched from the package manager's registry
 * API.  Here we parse whatever the SBOM collector stores in `location`.
 */
export function extractGithubRepo(location: string): string | null {
  if (!location) return null;
  // Match github.com/owner/repo (with or without https://, .git suffix, trailing paths)
  const match = location.match(
    /github\.com\/([a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+?)(?:\.git|\/|$)/,
  );
  return match ? match[1] : null;
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

/**
 * Run gitgeo_scan.py for a given GitHub repo slug.
 * Never rejects — errors are captured in result.error.
 */
export async function scanRepoGeo(repoSlug: string): Promise<GeoScanResult> {
  logger.debug('geo-enricher: scanning repo', { repo: repoSlug });

  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';

    const env: NodeJS.ProcessEnv = { ...process.env };
    if (process.env.GITHUB_TOKEN) {
      env.GITHUB_TOKEN = process.env.GITHUB_TOKEN;
    }

    const proc = spawn(
      'python3',
      [SCRIPT_PATH, repoSlug, '--max-contributors', '20'],
      { timeout: TIMEOUT_MS, env },
    );

    proc.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

    proc.on('error', (err) => {
      const notFound = err.message.includes('ENOENT') || err.message.includes('spawn');
      logger.warn('geo-enricher: script spawn error', {
        repo: repoSlug,
        err: err.message,
        hint: notFound ? 'Ensure scripts/gitgeo_scan.py exists and python3 is in PATH' : undefined,
      });
      resolve(makeSkipped(repoSlug, err.message));
    });

    proc.on('close', () => {
      if (!stdout.trim()) {
        logger.warn('geo-enricher: no output from gitgeo script', {
          repo: repoSlug,
          stderr: stderr.slice(0, 300),
        });
        resolve(makeSkipped(repoSlug, stderr.slice(0, 200) || 'no output'));
        return;
      }

      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(stdout.trim());
      } catch {
        logger.warn('geo-enricher: invalid JSON from gitgeo script', { repo: repoSlug });
        resolve(makeSkipped(repoSlug, 'invalid JSON output'));
        return;
      }

      if (parsed['error']) {
        logger.warn('geo-enricher: gitgeo reported error', { repo: repoSlug, error: parsed['error'] });
        resolve(makeSkipped(repoSlug, String(parsed['error'])));
        return;
      }

      const result: GeoScanResult = {
        repo: repoSlug,
        contributorsSampled: Number(parsed['contributors_sampled'] ?? 0),
        countryCounts: (parsed['country_counts'] as Record<string, number>) ?? {},
        topCountry: (parsed['top_country'] as string) ?? null,
        topCountryPct: Number(parsed['top_country_pct'] ?? 0),
        concentrationScore: Number(parsed['concentration_score'] ?? 0),
        unknownPct: Number(parsed['unknown_pct'] ?? 0),
        flagged: Number(parsed['concentration_score'] ?? 0) >= CONCENTRATION_THRESHOLD,
        skipped: false,
      };

      if (result.flagged) {
        logger.warn('geo-enricher: HIGH GEOGRAPHIC CONCENTRATION', {
          repo: repoSlug,
          topCountry: result.topCountry,
          topCountryPct: result.topCountryPct,
          concentrationScore: result.concentrationScore,
          threshold: CONCENTRATION_THRESHOLD,
        });
      } else {
        logger.info('geo-enricher: scan complete', {
          repo: repoSlug,
          topCountry: result.topCountry,
          concentrationScore: result.concentrationScore,
        });
      }

      resolve(result);
    });
  });
}

function makeSkipped(repo: string, error: string): GeoScanResult {
  return {
    repo,
    contributorsSampled: 0,
    countryCounts: {},
    topCountry: null,
    topCountryPct: 0,
    concentrationScore: 0,
    unknownPct: 0,
    flagged: false,
    skipped: true,
    error,
  };
}
