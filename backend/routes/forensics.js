const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { ok, fail } = require('../utils/validate');

// Forensics / parsing utilities — mostly local, no keys.

// POST /api/forensics/email-header { raw } — parse Received chain, auth results, delays
router.post('/email-header', (req, res) => {
  const raw = String(req.body?.raw || '');
  if (!raw || raw.length > 100000) return fail(res, 400, 'Body { raw } with full message headers required (max 100k)');
  const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/);
  const headers = {};
  for (const line of unfolded) {
    const i = line.indexOf(':');
    if (i > 0) {
      const k = line.slice(0, i).trim().toLowerCase();
      (headers[k] = headers[k] || []).push(line.slice(i + 1).trim());
    }
  }
  const received = (headers.received || []).map((r) => {
    const from = (r.match(/from\s+([^\s;]+)/i) || [])[1] || null;
    const by = (r.match(/by\s+([^\s;]+)/i) || [])[1] || null;
    const ip = (r.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/) || [])[1] || null;
    const date = (r.match(/;\s*(.+)$/) || [])[1] || null;
    return { from, by, ip, date };
  });
  const auth = (headers['authentication-results'] || []).join(' ');
  const dkim = /dkim=(pass|fail|none)/i.exec(auth)?.[1] || 'unknown';
  const spf = /spf=(pass|fail|softfail|neutral|none)/i.exec(auth)?.[1] || 'unknown';
  const dmarc = /dmarc=(pass|fail|none)/i.exec(auth)?.[1] || 'unknown';
  const spoofRisk = (spf === 'fail' || dkim === 'fail' || dmarc === 'fail') ? 'HIGH — auth failed, likely spoofed'
    : (spf === 'pass' || dkim === 'pass') ? 'low — auth passed' : 'unknown — no auth headers present';
  return ok(res, {
    from: headers.from?.[0] || null, to: headers.to?.[0] || null, subject: headers.subject?.[0] || null,
    date: headers.date?.[0] || null, message_id: headers['message-id']?.[0] || null,
    return_path: headers['return-path']?.[0] || null, reply_to: headers['reply-to']?.[0] || null,
    hops: received.length, received_chain: received,
    auth: { dkim, spf, dmarc }, spoof_risk: spoofRisk,
    red_flags: [
      headers.from?.[0] && headers['return-path']?.[0] && !headers['return-path'][0].includes((headers.from[0].match(/@([\w.-]+)/) || [])[1] || '\0') ? 'Return-Path domain differs from From domain' : null,
      headers['reply-to']?.[0] && headers.from?.[0] && headers['reply-to'][0] !== headers.from[0] ? 'Reply-To differs from From' : null,
      received.length === 0 ? 'No Received headers at all (hand-crafted?)' : null,
    ].filter(Boolean),
  });
});

// POST /api/forensics/iban { iban } — mod-97 validation + country/bank split
router.post('/iban', (req, res) => {
  const iban = String(req.body?.iban || '').replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return fail(res, 400, 'IBAN format invalid');
  const rearr = iban.slice(4) + iban.slice(0, 4);
  const numeric = rearr.split('').map((c) => (/\d/.test(c) ? c : (c.charCodeAt(0) - 55).toString())).join('');
  let rem = 0;
  for (const ch of numeric) rem = (rem * 10 + Number(ch)) % 97;
  return ok(res, { iban, valid: rem === 1, country: iban.slice(0, 2), check_digits: iban.slice(2, 4), bban: iban.slice(4) });
});

// POST /api/forensics/card { number } — Luhn check + brand guess (never store full PANs)
router.post('/card', (req, res) => {
  const digits = String(req.body?.number || '').replace(/\D/g, '');
  if (digits.length < 12 || digits.length > 19) return fail(res, 400, 'Card number must be 12–19 digits');
  let sum = 0, dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  const brand = /^4/.test(digits) ? 'Visa' : /^(5[1-5]|2[2-7])/.test(digits) ? 'Mastercard' : /^3[47]/.test(digits) ? 'Amex' : /^6/.test(digits) ? 'Discover' : 'unknown';
  return ok(res, { valid_luhn: sum % 10 === 0, brand, masked: `${digits.slice(0, 4)} •••• •••• ${digits.slice(-4)}`, length: digits.length });
});

// POST /api/forensics/hash-id { hash } — identify likely algorithms from shape
router.post('/hash-id', (req, res) => {
  const h = String(req.body?.hash || '').trim();
  if (!h) return fail(res, 400, 'Body { hash } required');
  const cands = [];
  const hex = /^[a-fA-F0-9]+$/.test(h), b64 = /^[A-Za-z0-9+/=]+$/.test(h) && h.length % 4 === 0;
  const hexLens = { 32: ['MD5', 'MD4', 'NTLM'], 40: ['SHA-1', 'RIPEMD-160'], 56: ['SHA-224'], 64: ['SHA-256', 'SHA3-256', 'BLAKE2s-256'], 96: ['SHA-384', 'SHA3-384'], 128: ['SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Whirlpool'] };
  if (hex && hexLens[h.length]) cands.push(...hexLens[h.length].map((a) => ({ algo: a, confidence: 'high', why: `${h.length} hex chars` })));
  if (/^\$2[aby]\$\d{2}\$.{53}$/.test(h)) cands.push({ algo: 'bcrypt', confidence: 'certain', why: 'bcrypt modular format' });
  if (/^\$argon2(id|i|d)\$/.test(h)) cands.push({ algo: 'argon2', confidence: 'certain', why: 'argon2 modular format' });
  if (/^\$6\$/.test(h)) cands.push({ algo: 'sha512crypt', confidence: 'certain', why: '$6$ prefix' });
  if (/^\$5\$/.test(h)) cands.push({ algo: 'sha256crypt', confidence: 'certain', why: '$5$ prefix' });
  if (/^\$1\$/.test(h)) cands.push({ algo: 'md5crypt', confidence: 'certain', why: '$1$ prefix' });
  if (b64 && !hex && [24, 28, 44, 88].includes(h.replace(/=+$/, '').length * 6 / 8 | 0)) cands.push({ algo: 'base64-encoded digest (decode first)', confidence: 'low', why: 'valid base64 shape' });
  if (!cands.length) cands.push({ algo: 'unknown', confidence: 'none', why: 'no known signature matched' });
  return ok(res, { input_length: h.length, hex, candidates: cands });
});

// GET /api/forensics/vin/:vin — NHTSA decode (free, no key)
router.get('/vin/:vin', async (req, res) => {
  const vin = String(req.params.vin || '').trim().toUpperCase();
  if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(vin)) return fail(res, 400, 'VIN must be 17 chars (no I, O, Q)');
  try {
    const { data, cached } = await getOrSet(`vin:${vin}`, 86400 * 30, async () => {
      const r = await http.get(`https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVin/${vin}?format=json`, { timeout: 12000 });
      const rows = (r.data?.Results || []).filter((x) => x.Value && x.Value !== 'Not Applicable');
      return Object.fromEntries(rows.slice(0, 30).map((x) => [x.Variable, x.Value]));
    });
    return ok(res, data, { cached, source: 'nhtsa' });
  } catch (e) { return fail(res, 502, 'VIN decode failed'); }
});

// GET /api/forensics/mac/:mac — vendor lookup (macvendors, keyless)
router.get('/mac/:mac', async (req, res) => {
  const mac = String(req.params.mac || '').trim();
  if (!/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(mac) && !/^[0-9A-Fa-f]{12}$/.test(mac)) return fail(res, 400, 'MAC like AA:BB:CC:DD:EE:FF required');
  try {
    const { data, cached } = await getOrSet(`mac:${mac.toLowerCase()}`, 86400 * 30, async () => {
      const r = await http.get(`https://api.macvendors.com/${encodeURIComponent(mac)}`, { timeout: 10000 });
      if (r.status === 404) return { vendor: null, note: 'OUI not in database' };
      return { vendor: String(r.data || '').slice(0, 200), oui: mac.slice(0, 8).toUpperCase() };
    });
    return ok(res, data, { cached, source: 'macvendors' });
  } catch (e) { return fail(res, 502, 'MAC lookup failed'); }
});

module.exports = router;
