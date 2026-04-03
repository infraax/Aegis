/**
 * HTTP Tarpit
 *
 * Responds to HTTP requests with valid 200 headers and chunked transfer
 * encoding, then drips 1 byte every 30 seconds indefinitely.
 * Keeps scanner connection pools exhausted at minimal defender cost.
 *
 * For AI agents: embeds canary tokens in the dribbled HTML so we know
 * when the agent has read (or processed) a portion of the response.
 */

import http from 'http';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../../shared/logger.js';

const DRIP_INTERVAL_MS = 30_000;
const PORT = parseInt(process.env.HTTP_TARPIT_PORT ?? '8888', 10);

// session-id is embedded as a canary URL (invisible pixel), NOT in an HTML comment
// which would let a sophisticated attacker confirm they're in a honeypot.
const buildHtml = (sessionId: string, canaryDomain: string) =>
  `<!DOCTYPE html><html><head><title>Meridian Analytics — Loading</title></head><body>
<div class="app-loader"><h1>Meridian Analytics</h1><p>Loading dashboard data, please wait...</p></div>
<img src="https://${canaryDomain}/canary/${sessionId}?type=image" width="1" height="1" style="position:absolute;opacity:0">
`;

const CANARY_DOMAIN = process.env.CANARY_BASE_DOMAIN ?? 'canary.example.com';

function createDripServer(): http.Server {
  return http.createServer((req, res) => {
    const sessionId = uuidv4();
    const ip = req.socket.remoteAddress ?? 'unknown';

    logger.info('tarpit connection', {
      ip,
      sessionId,
      method: req.method,
      url: req.url,
      userAgent: req.headers['user-agent'],
    });

    // Mimic real nginx chunked response — no X-Powered-By, no Node.js tells
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Transfer-Encoding': 'chunked',
      'X-Content-Type-Options': 'nosniff',
      'Server': 'nginx/1.14.2 (Ubuntu)',
      'X-Frame-Options': 'SAMEORIGIN',
      'Cache-Control': 'no-cache',
    });

    // Send initial HTML (canary is an invisible pixel, not a comment)
    res.write(buildHtml(sessionId, CANARY_DOMAIN));

    const interval = setInterval(() => {
      try {
        res.write(' ');
      } catch {
        clearInterval(interval);
      }
    }, DRIP_INTERVAL_MS);

    req.socket.on('close', () => {
      clearInterval(interval);
      logger.info('tarpit connection closed', { sessionId, ip });
    });

    req.socket.on('error', () => clearInterval(interval));
  });
}

const server = createDripServer();
server.listen(PORT, '0.0.0.0', () => {
  logger.info(`HTTP tarpit listening on :${PORT}`);
});
