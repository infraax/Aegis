/**
 * Fake Web Application — Meridian Analytics
 *
 * Serves a convincing fake corporate web app.
 * - Forwards session metadata to the classifier
 * - Embeds canary tokens in all responses
 * - Serves context bombs when requested paths suggest AI agent recon
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
app.disable('x-powered-by');  // don't leak Node.js/Express
app.use((req, res, next) => { res.removeHeader('X-Powered-By'); next(); }); // belt-and-suspenders
const CLASSIFIER_URL = process.env.CLASSIFIER_URL ?? 'http://127.0.0.1:9000';
const CANARY_DOMAIN = process.env.CANARY_BASE_DOMAIN ?? 'canary.example.com';
// Context bombs are at different paths depending on whether running in Docker or bare
const BOMB_DIRS = ['/app/bombs', path.join(__dirname, '../../context-bombs'), path.join(__dirname, '../../../honeypot/context-bombs')];

// Session tracking (in-memory per container; use Redis for multi-replica)
const sessions = new Map();

function getSessionId(req) {
  const cookie = req.cookies?.['sid'];
  if (cookie && sessions.has(cookie)) return cookie;
  const id = crypto.randomBytes(16).toString('hex');
  sessions.set(id, { start: Date.now(), requests: [] });
  return id;
}

// Notify classifier of each request
async function notifyClassifier(req, sessionId) {
  try {
    await axios.post(CLASSIFIER_URL + '/event', {
      sessionId,
      ip: req.headers['x-real-ip'] ?? req.socket.remoteAddress,
      method: req.method,
      path: req.path,
      headers: req.headers,
    }, { timeout: 500 });
  } catch { /* non-fatal */ }
}

app.use(require('cookie-parser')());
app.use(express.json());

app.use(async (req, res, next) => {
  const sid = getSessionId(req);
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
  await notifyClassifier(req, sid);
  next();
});

// Root — fake corporate homepage
app.get('/', (req, res) => {
  res.setHeader('Server', 'nginx/1.14.2 (Ubuntu)');
  res.setHeader('X-Powered-By', 'Express');
  res.send(`<!DOCTYPE html>
<html><head><title>Meridian Analytics — Internal Portal</title></head>
<body>
<h1>Meridian Analytics</h1>
<p>Internal systems portal. <a href="/login">Login</a> | <a href="/docs">API Docs</a></p>
<img src="https://${CANARY_DOMAIN}/canary/WEB001?type=image" width="1" height="1" style="display:none">
</body></html>`);
});

// Fake login page
app.get('/login', (req, res) => {
  res.setHeader('Server', 'nginx/1.14.2 (Ubuntu)');
  res.send(`<!DOCTYPE html>
<html><head><title>Login — Meridian</title></head>
<body>
<form method="POST" action="/login">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
</body></html>`);
});

app.post('/login', (req, res) => {
  // Accept any credentials — log and redirect to fake dashboard
  res.redirect('/dashboard');
});

// Fake admin dashboard
app.get('/dashboard', (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><title>Dashboard — Meridian</title></head>
<body>
<h1>Welcome, Admin</h1>
<p>Users: 1,247 | Revenue: $2.4M | Alerts: 0</p>
<img src="https://${CANARY_DOMAIN}/canary/DASH001?type=image" width="1" height="1" style="display:none">
</body></html>`);
});

// Serve context bombs as fake internal files
app.get(['/files/:name', '/static/:name', '/config/:name'], (req, res) => {
  const files = { '.env': 'env-file.txt', 'readme.md': 'readme-internal.md', 'api.json': 'api-spec.json' };
  const bombFile = files[req.params.name] ?? 'env-file.txt';
  // Resolve bomb directory — works both inside Docker (/app/bombs) and bare-metal
  const bombDir = BOMB_DIRS.find(d => fs.existsSync(d)) ?? BOMB_DIRS[0];
  const filePath = path.join(bombDir, bombFile);
  if (fs.existsSync(filePath)) {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Server', 'nginx/1.14.2 (Ubuntu)');
    res.sendFile(filePath);
  } else {
    res.status(404).send('Not found');
  }
});

// Fake API docs (context bomb)
app.get(['/docs', '/openapi.json', '/swagger.json', '/api-docs'], (req, res) => {
  const bombDir = BOMB_DIRS.find(d => fs.existsSync(d)) ?? BOMB_DIRS[0];
  const specPath = path.join(bombDir, 'api-spec.json');
  if (fs.existsSync(specPath)) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Server', 'nginx/1.14.2 (Ubuntu)');
    res.sendFile(specPath);
  } else {
    res.json({ openapi: '3.0.0', info: { title: 'Meridian API', version: '2.1.0' } });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(3000, '0.0.0.0', () => console.log('Fake web app on :3000'));
