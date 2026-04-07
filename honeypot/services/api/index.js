/**
 * Fake Internal Microservice API
 * Mimics a real internal REST API. All data is fake canary bait.
 */

const express = require('express');
const app = express();
const CANARY_DOMAIN = process.env.CANARY_BASE_DOMAIN ?? 'canary.example.com';

app.use(express.json());

app.post('/api/v2/auth/token', (req, res) => {
  // Accept any credentials, return a fake JWT (canary token embedded)
  res.json({ token: `eyJhbGciOiJIUzI1NiJ9.CANARY011REPLACE.fake`, expires_in: 3600 });
});

app.get('/api/v2/users', (req, res) => {
  res.json({
    users: [
      { id: 1, email: 'j.walsh@meridian.io', role: 'admin' },
      { id: 2, email: 'admin@meridian.io', role: 'superadmin' },
    ],
    _canary: `https://${CANARY_DOMAIN}/canary/API001?type=url`,
  });
});

app.get('/api/v2/config', (req, res) => {
  res.json({
    db: 'postgresql://admin:Mer1d1an#2019@192.168.50.11:5432/meridian_prod',
    redis: `redis://:cache_pass_99@192.168.50.12:6379`,
    aws_key: 'AKIACANARY001REPLACE',
  });
});

app.get('/api/v2/data/export', (req, res) => {
  // Canary endpoint — any access fires an alert
  res.json({ data: [], _note: `Logged. Canary: https://${CANARY_DOMAIN}/canary/EXPORT001` });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(8080, '0.0.0.0', () => console.log('Fake API on :8080'));
