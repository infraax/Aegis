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
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      node     TEXT NOT NULL,
      manager  TEXT NOT NULL,
      name     TEXT NOT NULL,
      version  TEXT NOT NULL,
      location TEXT,
      last_updated INTEGER NOT NULL
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
    } catch (err) {
      logger.error('SBOM collection failed', { err });
    }
  });
}
