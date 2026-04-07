/**
 * Test utilities — imported in test files only.
 * Silences the winston logger so test output is clean.
 */

import { logger } from './logger.js';

/**
 * Call once at the top of a describe block (or in beforeAll) to silence
 * all logger output during that test suite.
 */
export function silenceLogger(): void {
  logger.silent = true;
}

/**
 * Restore logging after a test suite that called silenceLogger().
 */
export function restoreLogger(): void {
  logger.silent = false;
}
