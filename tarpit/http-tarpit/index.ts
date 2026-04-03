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

const HTML_HEADER = `<!DOCTYPE html><html><head><title>Loading...</title></head><body>
<!-- session-id: `;
const HTML_MID = ` -->
<p>Please wait while we load your content...</p>
`;

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

    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Transfer-Encoding': 'chunked',
      'X-Content-Type-Options': 'nosniff',
      'Server': 'nginx/1.14.2',
    });

    // Send initial HTML with canary token
    res.write(HTML_HEADER + sessionId + HTML_MID);

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
