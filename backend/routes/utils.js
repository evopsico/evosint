const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { encodeText, decodeText, generatePassword } = require('../utils/crypto');
const { ok, fail } = require('../utils/validate');

/** Implements the Utility Tools the README promised but v1 never shipped. */

// POST /api/utils/encode { text, type: base64|hex|binary|morse|url }
router.post('/encode', (req, res) => {
  const { text = '', type = 'base64' } = req.body || {};
  if (typeof text !== 'string' || !text) return fail(res, 400, 'Body { text, type } required');
  if (text.length > 50000) return fail(res, 413, 'Text too large (max 50k chars)');
  const t = String(type).toLowerCase();
  try {
    if (t === 'url') return ok(res, { type: t, input: text, output: encodeURIComponent(text) });
    return ok(res, { type: t, input: text, output: encodeText(text, t) });
  } catch (e) { return fail(res, 400, e.message); }
});

// POST /api/utils/decode { text, type }
router.post('/decode', (req, res) => {
  const { text = '', type = 'base64' } = req.body || {};
  if (typeof text !== 'string' || !text) return fail(res, 400, 'Body { text, type } required');
  const t = String(type).toLowerCase();
  try {
    if (t === 'url') return ok(res, { type: t, input: text, output: decodeURIComponent(text) });
    return ok(res, { type: t, input: text, output: decodeText(text, t) });
  } catch (e) { return fail(res, 400, `Decode failed: ${e.message}`); }
});

// GET /api/utils/password?length=20&symbols=1&numbers=1&upper=1 — CSPRNG (v1 used Math.random)
router.get('/password', (req, res) => {
  const length = Math.min(Math.max(parseInt(req.query.length, 10) || 20, 8), 128);
  const symbols = req.query.symbols !== '0';
  const numbers = req.query.numbers !== '0';
  const upper = req.query.upper !== '0';
  let pool = 'abcdefghijklmnopqrstuvwxyz';
  if (upper) pool += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (numbers) pool += '0123456789';
  if (symbols) pool += '!@#$%^&*()-_=+[]{};:,.<>?';
  let password = '';
  for (let i = 0; i < length; i++) password += pool[crypto.randomInt(pool.length)];
  const entropy = Math.round(length * Math.log2(pool.length));
  return ok(res, {
    password,
    length,
    entropy_bits: entropy,
    strength: entropy < 60 ? 'weak' : entropy < 90 ? 'fair' : entropy < 120 ? 'strong' : 'excellent',
  });
});



// POST /api/utils/jwt { token } — decode + flag weak algs (none/HS256 confusion, exp check)
router.post('/jwt', (req, res) => {
  const { token = '' } = req.body || {};
  if (typeof token !== 'string' || token.split('.').length < 2) return fail(res, 400, 'Valid JWT required in body { token }');
  try {
    const [h, p, s] = token.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    const findings = [];
    if (String(header.alg || '').toLowerCase() === 'none') findings.push({ level: 'critical', msg: 'alg=none — token accepts unauthenticated forgery' });
    if (String(header.alg || '').toUpperCase() === 'HS256' && payload.kid) findings.push({ level: 'info', msg: 'kid header present — check for key-confusion/directory traversal' });
    if (payload.exp && payload.exp < now) findings.push({ level: 'warn', msg: 'token is EXPIRED' });
    if (!payload.exp) findings.push({ level: 'warn', msg: 'no exp claim — token never expires' });
    const sensitive = ['password', 'secret', 'ssn', 'credit'].filter((k) => JSON.stringify(payload).toLowerCase().includes(k));
    if (sensitive.length) findings.push({ level: 'warn', msg: `payload may contain sensitive keys: ${sensitive.join(', ')}` });
    return ok(res, { header, payload, signature_present: !!s, expired: payload.exp ? payload.exp < now : null, findings });
  } catch (e) { return fail(res, 400, `JWT decode failed: ${e.message}`); }
});

// GET /api/utils/timestamp?value=... — unix/iso/human conversions
router.get('/timestamp', (req, res) => {
  const v = String(req.query.value ?? '').trim();
  const now = new Date();
  if (!v) {
    const unix = Math.floor(now.getTime() / 1000);
    return ok(res, { unix, unix_ms: now.getTime(), iso: now.toISOString(), utc: now.toUTCString() });
  }
  let d = null;
  if (/^-?\d{10}$/.test(v)) d = new Date(Number(v) * 1000);
  else if (/^-?\d{13}$/.test(v)) d = new Date(Number(v));
  else if (!Number.isNaN(Date.parse(v))) d = new Date(Date.parse(v));
  if (!d || Number.isNaN(d.getTime())) return fail(res, 400, 'Unrecognized timestamp (unix seconds/ms, ISO, or date string)');
  return ok(res, { unix: Math.floor(d.getTime() / 1000), unix_ms: d.getTime(), iso: d.toISOString(), utc: d.toUTCString() });
});

// POST /api/utils/url { url } — parameter/structure analysis
router.post('/url', (req, res) => {
  const { url = '' } = req.body || {};
  try {
    const u = new URL(String(url));
    const params = [...u.searchParams.entries()].map(([k, val]) => ({ key: k, value: val }));
    return ok(res, {
      protocol: u.protocol, hostname: u.hostname, port: u.port || null, pathname: u.pathname,
      params, param_count: params.length,
      suspicious_params: params.filter((p) => /token|key|pass|secret|auth|session|redirect|url|next|debug|admin/i.test(p.key)).map((p) => p.key),
      has_fragment: !!u.hash, is_ip_host: /^[0-9.]+$/.test(u.hostname) || u.hostname.includes(':'),
    });
  } catch { return fail(res, 400, 'Invalid URL (include protocol, e.g. https://example.com/?a=1)'); }
});

module.exports = router;
