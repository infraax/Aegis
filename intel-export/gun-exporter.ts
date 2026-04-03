/**
 * GUN Intelligence Exporter
 *
 * One-way push: ThinkPad → Pi5 GUN relay.
 * The ThinkPad NEVER reads from GUN. Data only flows outward.
 *
 * GUN is used here as a lightweight real-time sync layer that the PWA
 * dashboard subscribes to. It requires no persistent server state on the
 * ThinkPad side — just a peer connection.
 */

// GUN's CommonJS package doesn't have great TS types; we use require() here.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const Gun = require('gun');
import { logger } from '../shared/logger.js';

const GUN_RELAY = process.env.GUN_RELAY_URL ?? 'ws://10.99.0.1:8765/gun';

let gun: ReturnType<typeof Gun> | null = null;
let connected = false;

function getGun() {
  if (!gun) {
    gun = Gun({ peers: [GUN_RELAY], localStorage: false, radisk: false });
    gun.on('hi', () => { connected = true; logger.info('GUN relay connected', { relay: GUN_RELAY }); });
    gun.on('bye', () => { connected = false; logger.warn('GUN relay disconnected'); });
  }
  return gun;
}

export async function exportEvent(
  namespace: string,
  data: Record<string, unknown>,
): Promise<void> {
  try {
    const g = getGun();
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('GUN put timeout')), 5_000);
      g.get(namespace).put({ ...data, _aegis_ts: Date.now() }, (ack: { err?: string }) => {
        clearTimeout(timeout);
        if (ack.err) reject(new Error(ack.err));
        else resolve();
      });
    });
  } catch (err) {
    // Non-fatal — log and continue. Events can be buffered locally if needed.
    logger.warn('GUN export failed', { namespace, err });
  }
}

export function isConnected(): boolean {
  return connected;
}
