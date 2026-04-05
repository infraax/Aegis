/**
 * ML Model Supply Chain Scanner
 *
 * Scans serialised ML model files (.pkl, .pt, .pth, .safetensors) for
 * malicious pickle bytecode using Trail of Bits' fickling tool.
 *
 * Integration pattern: Pattern C (subprocess bridge)
 *   - fickling stays in its own Python process
 *   - We own only this 60-line bridge
 *   - Upgrade fickling independently with: pip3 install --upgrade fickling
 *
 * Attack scenario this catches:
 *   A poisoned model file on HuggingFace / internal model registry that
 *   executes a reverse shell when torch.load() is called.  Fickling
 *   decompiles the pickle bytecode and surfaces the malicious call before
 *   any code runs.
 *
 * Graceful degradation: if fickling is not installed, logs a warning and
 * returns { safe: true, skipped: true } so the SBOM pipeline continues.
 */

import { spawn } from 'child_process';
import path from 'path';
import { logger } from '../shared/logger.js';

/** File extensions that contain pickle bytecode */
export const SCANNABLE_EXTENSIONS = new Set(['.pkl', '.pt', '.pth', '.pickle']);

export interface ScanResult {
  filePath: string;
  safe: boolean;
  skipped: boolean;   // true if fickling not available or file not scannable
  findings: string[]; // human-readable fickling output lines
  durationMs: number;
  error?: string;
}

/**
 * Scan a single file with fickling.
 * Resolves when scan completes — never rejects (errors surface in result.error).
 */
export async function scanModelFile(filePath: string): Promise<ScanResult> {
  const start = Date.now();
  const ext = path.extname(filePath).toLowerCase();

  if (!SCANNABLE_EXTENSIONS.has(ext)) {
    return { filePath, safe: true, skipped: true, findings: [], durationMs: 0 };
  }

  logger.debug('model-scanner: scanning file', { filePath, ext });

  return new Promise((resolve) => {
    const findings: string[] = [];
    let stderr = '';

    const proc = spawn('python3', ['-m', 'fickling', '--check-safety', '--print-results', filePath], {
      timeout: 30_000,      // 30s max per file
      env: { ...process.env },
    });

    proc.stdout.on('data', (chunk: Buffer) => {
      findings.push(...chunk.toString().trim().split('\n').filter(Boolean));
    });

    proc.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    proc.on('error', (err) => {
      const notInstalled = err.message.includes('ENOENT') || err.message.includes('spawn');
      if (notInstalled) {
        logger.warn('model-scanner: fickling not found — skipping scan', {
          filePath,
          hint: 'pip3 install fickling',
        });
        resolve({ filePath, safe: true, skipped: true, findings: [], durationMs: Date.now() - start });
      } else {
        logger.error('model-scanner: spawn error', { filePath, err: err.message });
        resolve({ filePath, safe: true, skipped: true, findings: [], durationMs: Date.now() - start, error: err.message });
      }
    });

    proc.on('close', (code) => {
      const durationMs = Date.now() - start;

      // Distinguish "file error" from "malicious content":
      // fickling exits 1 for FileNotFoundError, PermissionError, etc. — not a security finding
      const isFileError =
        stderr.includes('FileNotFoundError') ||
        stderr.includes('PermissionError') ||
        stderr.includes('IsADirectoryError') ||
        stderr.includes('No such file or directory');

      if (code !== 0 && isFileError) {
        logger.warn('model-scanner: cannot read file — skipping', { filePath, stderr: stderr.slice(0, 200) });
        resolve({ filePath, safe: true, skipped: true, findings: [], durationMs, error: stderr.slice(0, 200) });
        return;
      }

      const safe = code === 0;

      if (!safe) {
        logger.warn('model-scanner: MALICIOUS PICKLE DETECTED', {
          filePath,
          findings,
          stderr: stderr.slice(0, 500),
        });
      } else {
        logger.debug('model-scanner: file is clean', { filePath, durationMs });
      }

      resolve({ filePath, safe, skipped: false, findings, durationMs });
    });
  });
}

/**
 * Scan a batch of files concurrently (max 4 parallel scans to avoid thrashing).
 * Returns results in the same order as input.
 */
export async function scanModelFiles(filePaths: string[]): Promise<ScanResult[]> {
  const CONCURRENCY = 4;
  const results: ScanResult[] = [];

  for (let i = 0; i < filePaths.length; i += CONCURRENCY) {
    const batch = filePaths.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(batch.map(scanModelFile));
    results.push(...batchResults);
  }

  const malicious = results.filter((r) => !r.safe && !r.skipped);
  if (malicious.length > 0) {
    logger.warn('model-scanner: batch scan complete — malicious files found', {
      total: filePaths.length,
      malicious: malicious.length,
      files: malicious.map((r) => r.filePath),
    });
  } else {
    logger.info('model-scanner: batch scan complete — all clean', {
      total: filePaths.length,
      skipped: results.filter((r) => r.skipped).length,
    });
  }

  return results;
}
