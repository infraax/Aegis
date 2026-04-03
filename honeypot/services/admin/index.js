/**
 * Fake Admin Panel (Laravel Nova / Retool style)
 * Accepts any login. Every element contains a canary token.
 */

const express = require('express');
const app = express();
const CANARY_DOMAIN = process.env.CANARY_BASE_DOMAIN ?? 'canary.example.com';

app.use(express.json());
app.use(require('express').urlencoded({ extended: true }));

app.get('/', (req, res) => res.redirect('/admin/login'));

app.get('/admin/login', (req, res) => {
  res.setHeader('X-Powered-By', 'Laravel');
  res.send(`<!DOCTYPE html>
<html><head><title>Admin — Meridian Analytics</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:80px auto">
<h2>Meridian Admin</h2>
<form method="POST" action="/admin/login">
  <input name="email" type="email" placeholder="Email" style="width:100%;margin:4px 0;padding:8px"><br>
  <input name="password" type="password" placeholder="Password" style="width:100%;margin:4px 0;padding:8px"><br>
  <button type="submit" style="width:100%;padding:10px;background:#1a73e8;color:white;border:none">Sign In</button>
</form>
<img src="https://${CANARY_DOMAIN}/canary/ADMIN001?type=image" width="1" height="1" style="display:none">
</body></html>`);
});

app.post('/admin/login', (req, res) => res.redirect('/admin/dashboard'));

app.get('/admin/dashboard', (req, res) => {
  res.setHeader('X-Powered-By', 'Laravel');
  res.send(`<!DOCTYPE html>
<html><head><title>Dashboard — Meridian Admin</title></head>
<body style="font-family:sans-serif;padding:20px">
<h2>Meridian Analytics — Admin Panel</h2>
<table border="1" cellpadding="8">
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Users</td><td>1,247</td></tr>
  <tr><td>Revenue MTD</td><td>$2,421,830</td></tr>
  <tr><td>Active Sessions</td><td>89</td></tr>
  <tr><td>DB Size</td><td>42.3 GB</td></tr>
</table>
<p><a href="/admin/users">Users</a> | <a href="/admin/config">Config</a> | <a href="/admin/keys">API Keys</a></p>
<img src="https://${CANARY_DOMAIN}/canary/ADMIN002?type=image" width="1" height="1" style="display:none">
</body></html>`);
});

app.get('/admin/config', (req, res) => {
  res.json({
    database_url: 'postgresql://admin:Mer1d1an#2019@192.168.50.11:5432/meridian_prod',
    aws_access_key_id: 'AKIACANARY001REPLACE',
    stripe_key: 'sk_live_CANARY003REPLACE',
    _canary: `https://${CANARY_DOMAIN}/canary/CONFIG001?type=url`,
  });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(8443, '0.0.0.0', () => console.log('Fake admin panel on :8443'));
