/**
 * SBOM Collector
 *
 * Collects software bill-of-materials from all mesh nodes via the
 * orchestrator MCP (read-only) and stores in a local SQLite database.
 * Diffs each run to detect new, changed, or removed packages.
 */

import Database from 'better-sqlite3';
import path from 'path';
import cron from 'node-cron';
import { logger } from '../shared/logger.js';

import { scanModelFiles, SCANNABLE_EXTENSIONS } from './model-scanner.js';
import { extractGithubRepo, scanRepoGeo } from './geo-enricher.js';
import { assessExposure } from './correlator.js';

const DB_PATH = process.env.SBOM_DB_PATH ?? '/opt/aegis/data/sbom.sqlite';
let db: Database.Database;

export interface Package {
  node: string;
  manager: 'npm' | 'pip' | 'dpkg' | 'docker' | 'cargo' | 'go';
  name: string;
  version: string;
  location: string;
  lastUpdated: number;
}

export function initDB(): void {
  db = new Database(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS packages (
      id                  INTEGER PRIMARY KEY AUTOINCREMENT,
      node                TEXT NOT NULL,
      manager             TEXT NOT NULL,
      name                TEXT NOT NULL,
      version             TEXT NOT NULL,
      location            TEXT,
      last_updated        INTEGER NOT NULL,
      maintainer_geo_json TEXT,          -- JSON: GeoScanResult, nullable until enriched
      geo_scanned_at      INTEGER        -- Unix ms of last geo enrichment run
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_pkg ON packages(node, manager, name);

    CREATE TABLE IF NOT EXISTS sbom_events (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      ts        INTEGER NOT NULL,
      node      TEXT NOT NULL,
      manager   TEXT NOT NULL,
      name      TEXT NOT NULL,
      old_ver   TEXT,
      new_ver   TEXT,
      event     TEXT NOT NULL  -- 'added' | 'changed' | 'removed'
    );

    CREATE TABLE IF NOT EXISTS model_scan_results (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      ts          INTEGER NOT NULL,
      node        TEXT NOT NULL,
      file_path   TEXT NOT NULL,
      safe        INTEGER NOT NULL,  -- 1 = safe, 0 = malicious
      findings    TEXT,              -- JSON array of fickling output lines
      duration_ms INTEGER
    );
  `);
  logger.info('SBOM database initialised', { path: DB_PATH });
}

export function upsertPackages(pkgs: Package[]): Array<{ pkg: Package; event: 'added' | 'changed' | 'removed' }> {
  const changes: Array<{ pkg: Package; event: 'added' | 'changed' | 'removed' }> = [];
  const now = Date.now();

  const getStmt = db.prepare('SELECT version FROM packages WHERE node=? AND manager=? AND name=?');
  const upsertStmt = db.prepare(
    `INSERT INTO packages(node,manager,name,version,location,last_updated)
     VALUES(?,?,?,?,?,?)
     ON CONFLICT(node,manager,name) DO UPDATE SET version=excluded.version,last_updated=excluded.last_updated`,
  );
  const eventStmt = db.prepare(
    `INSERT INTO sbom_events(ts,node,manager,name,old_ver,new_ver,event) VALUES(?,?,?,?,?,?,?)`,
  );

  const txn = db.transaction(() => {
    for (const pkg of pkgs) {
      const existing = getStmt.get(pkg.node, pkg.manager, pkg.name) as { version: string } | undefined;
      if (!existing) {
        changes.push({ pkg, event: 'added' });
        eventStmt.run(now, pkg.node, pkg.manager, pkg.name, null, pkg.version, 'added');
      } else if (existing.version !== pkg.version) {
        changes.push({ pkg, event: 'changed' });
        eventStmt.run(now, pkg.node, pkg.manager, pkg.name, existing.version, pkg.version, 'changed');
      }
      upsertStmt.run(pkg.node, pkg.manager, pkg.name, pkg.version, pkg.location, now);
    }
  });

  txn();
  return changes;
}

export function getAllPackages(): Package[] {
  return (db.prepare('SELECT node,manager,name,version,location,last_updated as lastUpdated FROM packages').all() as Package[]);
}

// Schedule full SBOM collection every 6 hours
export function startScheduler(collectFn: () => Promise<Package[]>): void {
  const intervalMinutes = parseInt(process.env.CVE_POLL_INTERVAL_MINUTES ?? '360', 10);
  const cronExpr = `0 */${Math.floor(intervalMinutes / 60)} * * *`;

  cron.schedule(cronExpr, async () => {
    logger.info('SBOM collection run starting');
    try {
      const pkgs = await collectFn();
      const changes = upsertPackages(pkgs);
      logger.info('SBOM collection complete', { total: pkgs.length, changes: changes.length });

      // ── Stage 2A: Scan newly discovered model files with fickling ──────────
      const modelPaths = pkgs
        .filter((p) => {
          const ext = p.location?.split('.').pop();
          return ext && SCANNABLE_EXTENSIONS.has(`.${ext}`);
        })
        .map((p) => p.location)
        .filter((loc): loc is string => Boolean(loc));

      if (modelPaths.length > 0) {
        logger.info('SBOM: running fickling model scan', { count: modelPaths.length });
        const scanResults = await scanModelFiles(modelPaths);

        // Persist results and trigger exposure alerts for malicious files
        const insertScan = db.prepare(
          `INSERT INTO model_scan_results(ts,node,file_path,safe,findings,duration_ms)
           VALUES(?,?,?,?,?,?)`,
        );
        for (const r of scanResults) {
          if (r.skipped) continue;
          const pkg = pkgs.find((p) => p.location === r.filePath);
          insertScan.run(
            Date.now(),
            pkg?.node ?? 'unknown',
            r.filePath,
            r.safe ? 1 : 0,
            JSON.stringify(r.findings),
            r.durationMs,
          );

          if (!r.safe && pkg) {
            // Build a synthetic advisory and route through the existing exposure pipeline
            await assessExposure(pkg, {
              id: `FICKLING-${Date.now()}`,
              summary: `Malicious pickle bytecode detected in ${r.filePath}`,
              published: new Date().toISOString(),
              modified: new Date().toISOString(),
              aliases: [],
              severity: [{ type: 'CVSS_V3', score: '10.0' }],
              affected: [{
                package: { name: pkg.name, ecosystem: pkg.manager },
                versions: [pkg.version],
                ranges: [],
              }],
            });
          }
        }
      }

      // ── Stage 2B: Geo-enrich newly added packages ─────────────────────────
      const newPkgs = changes
        .filter((c) => c.event === 'added')
        .map((c) => c.pkg);

      for (const pkg of newPkgs) {
        const repoSlug = extractGithubRepo(pkg.location ?? '');
        if (!repoSlug) continue;

        // Run async — does not block the scheduler tick
        scanRepoGeo(repoSlug).then((geoResult) => {
          db.prepare(
            `UPDATE packages SET maintainer_geo_json=?, geo_scanned_at=?
             WHERE node=? AND manager=? AND name=?`,
          ).run(JSON.stringify(geoResult), Date.now(), pkg.node, pkg.manager, pkg.name);

          if (geoResult.flagged) {
            logger.warn('SBOM: geo-concentration flag on new package', {
              package: pkg.name,
              repo: repoSlug,
              topCountry: geoResult.topCountry,
              concentrationScore: geoResult.concentrationScore,
            });
          }
        }).catch((err) => logger.error('SBOM: geo enrichment failed', { pkg: pkg.name, err }));
      }

    } catch (err) {
      logger.error('SBOM collection failed', { err });
    }
  });
}
