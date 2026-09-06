const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidEmail, ok, fail } = require('../utils/validate');

const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'yopmail.com', 'throwawaymail.com', 'fakeinbox.com', 'getnada.com', 'trashmail.com', 'sharklasers.com', 'grr.la', 'dispostable.com', 'temp-mail.org', 'mohmal.com', 'emailondeck.com', 'maildrop.cc', '20minutemail.com', 'mintemail.com', 'mytrashmail.com']);
const ROLE_PREFIX = new Set(['admin', 'administrator', 'support', 'info', 'contact', 'help', 'sales', 'abuse', 'postmaster', 'webmaster', 'billing', 'noreply', 'no-reply', 'security', 'hr', 'jobs', 'careers', 'press', 'media']);

// GET /api/verify/email/:email — deliverability signals: syntax, MX, disposable, role, gravatar
router.get('/email/:email', async (req, res) => {
  const email = String(req.params.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return fail(res, 400, 'Invalid email format');
  const [local, domain] = email.split('@');
  try {
    const { data, cached } = await getOrSet(`verify:${email}`, 86400, async () => {
      const mx = await http.get(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`, { timeout: 8000 });
      const records = (mx.data?.Answer || []).map((a) => a.data);
      const hash = crypto.createHash('md5').update(email).digest('hex');
      let gravatar = false;
      try {
        const g = await http.get(`https://en.gravatar.com/${hash}.json`, { timeout: 8000 });
        gravatar = g.status === 200 && !!g.data?.entry;
      } catch { /* no profile */ }
      const score = [records.length > 0, !DISPOSABLE.has(domain), !ROLE_PREFIX.has(local), gravatar].filter(Boolean).length;
      return {
        email, valid_syntax: true, domain,
        mx_records: records, mx_found: records.length > 0,
        disposable: DISPOSABLE.has(domain), role_account: ROLE_PREFIX.has(local),
        free_provider: ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'proton.me', 'protonmail.com', 'aol.com', 'gmx.com', 'yandex.com'].includes(domain),
        gravatar_profile: gravatar,
        deliverability: score >= 4 ? 'likely' : score >= 2 ? 'uncertain' : 'unlikely',
        score: `${score}/4`,
      };
    });
    return ok(res, data, { cached });
  } catch (e) { return fail(res, 502, 'Verification failed'); }
});

// POST /api/verify/password { password } — HIBP Pwned Passwords k-anonymity (nothing sensitive leaves: only 5-char prefix)
router.post('/password', async (req, res) => {
  const pw = String(req.body?.password || '');
  if (!pw || pw.length > 200) return fail(res, 400, 'Body { password } required');
  const sha1 = crypto.createHash('sha1').update(pw).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5), suffix = sha1.slice(5);
  try {
    const r = await http.get(`https://api.pwnedpasswords.com/range/${prefix}`, { timeout: 10000 });
    const line = String(r.data || '').split('\n').find((l) => l.split(':')[0] === suffix);
    const count = line ? parseInt(line.split(':')[1], 10) : 0;
    return ok(res, {
      pwned: count > 0, count,
      verdict: count > 1000 ? 'heavily exposed — never use' : count > 0 ? 'seen in breaches — change it' : 'not seen in Pwned Passwords',
      checks: { length: pw.length, has_upper: /[A-Z]/.test(pw), has_lower: /[a-z]/.test(pw), has_digit: /\d/.test(pw), has_symbol: /[^A-Za-z0-9]/.test(pw) },
    }, { source: 'haveibeenpwned (k-anonymity)' });
  } catch (e) { return fail(res, 502, 'Pwned-passwords check failed'); }
});

module.exports = router;
