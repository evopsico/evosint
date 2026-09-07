const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const store = require('../utils/store');
const { ok, fail, oneLine } = require('../utils/validate');
const { base32Encode, totpVerify, newBackupCodes, sha256hex } = require('../utils/crypto');

const router = express.Router();

const TIERS = {
  guest: { label: 'Guest', quota: 2 },
  user: { label: 'User', quota: 50 },
  super: { label: 'Super', quota: Infinity },
};
const EXEMPT = [/^\/auth(\/|$)/, /^\/health\/?$/, /^\/lab\/limits\/?$/, /^\/username\/catalog\/list\/?$/, /^\/kitty(\/|$)/];

// Express 4 does not catch rejected async handlers (the connection just hangs
// until the platform kills it). Every async route below runs inside `ah()` so
// store/network failures always become a 500 JSON instead of a hung socket.
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------- password hashing (scrypt, stdlib only) ----------
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, dk) => {
      if (err) return reject(err);
      resolve({ salt, hash: dk.toString('hex') });
    });
  });
}
function verifyPassword(password, rec) {
  return new Promise((resolve) => {
    if (!rec || !rec.salt || !rec.hash) return resolve(false);
    crypto.scrypt(password, rec.salt, 64, (err, dk) => {
      if (err) return resolve(false);
      try {
        resolve(crypto.timingSafeEqual(Buffer.from(dk.toString('hex'), 'hex'), Buffer.from(rec.hash, 'hex')));
      } catch { resolve(false); }
    });
  });
}

// ---------- session tokens (HMAC-signed, 30 days) ----------
async function signToken(uid) {
  const payload = Buffer.from(JSON.stringify({ uid, iat: Date.now(), exp: Date.now() + 30 * 864e5 })).toString('base64url');
  const sig = crypto.createHmac('sha256', await store.getSecret()).update('v1.' + payload).digest('hex');
  return `v1.${payload}.${sig}`;
}
async function readToken(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3 || parts[0] !== 'v1') return null;
    const sig = crypto.createHmac('sha256', await store.getSecret()).update(parts[0] + '.' + parts[1]).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(parts[2], 'hex'))) return null;
    const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!p.uid || p.exp < Date.now()) return null;
    return p;
  } catch { return null; }
}

// ---------- seed owner account on first boot ----------
async function ensureSeed() {
  const users = await store.loadUsers();
  if (Object.values(users).some((u) => u.username.toLowerCase() === 'evo')) return;
  if (Object.keys(users).length > 0) return; // never auto-seed into a non-empty db
  const pass = await hashPassword(process.env.EVO_ADMIN_PASS || 'aA12345678@');
  const id = crypto.randomBytes(8).toString('hex');
  users[id] = {
    id, username: process.env.EVO_ADMIN_USER || 'evo', pass,
    tier: 'super', left: Infinity, dob: null, created: new Date().toISOString(),
  };
  await store.saveUsers(users);
  console.log(`✓ seeded super account '${users[id].username}' (change password in Account panel)`);
}

// ---------- identity resolution ----------
function clientIp(req) {
  // With TRUST_PROXY set, Express validates X-Forwarded-For per hop count.
  // Without it, the header is client-controlled (spoofable) and must be ignored,
  // otherwise anyone could mint unlimited guest buckets by forging IPs.
  if (process.env.TRUST_PROXY) return req.ip || 'unknown';
  return req.socket?.remoteAddress || 'unknown';
}
async function resolveIdentity(req) {
  // 1) API key (infinite searches)
  const keyRaw = req.headers['x-api-key'] || req.query.key || req.query.api_key;
  if (keyRaw) {
    const digest = crypto.createHash('sha256').update(String(keyRaw)).digest('hex');
    const keys = await store.loadKeys();
    const k = keys.find((x) => x.hash === digest);
    if (!k) return { kind: 'key', valid: false };
    const users = await store.loadUsers();
    k.last_used = new Date().toISOString();
    await store.saveKeys(keys);
    return { kind: 'key', valid: true, keyId: k.id, userId: k.userId, username: users[k.userId]?.username || '?', tier: 'super', infinite: true, left: Infinity };
  }
  // 2) session token
  const auth = String(req.headers.authorization || '');
  const m = /^Bearer\s+(.+)$/.exec(auth);
  if (m) {
    const p = await readToken(m[1].trim());
    if (!p) return { kind: 'token', valid: false };
    const users = await store.loadUsers();
    const u = users[p.uid];
    if (!u) return { kind: 'token', valid: false };
    return { kind: 'user', valid: true, userId: u.id, username: u.username, tier: u.tier, infinite: u.tier === 'super', left: u.tier === 'super' ? Infinity : u.left };
  }
  // 3) guest bucket by IP
  const ip = clientIp(req);
  const guests = await store.loadGuests();
  if (!guests[ip]) { guests[ip] = { left: TIERS.guest.quota, seen: new Date().toISOString() }; await store.saveGuests(guests); }
  return { kind: 'guest', valid: true, username: 'Guest', tier: 'guest', infinite: false, left: guests[ip].left, ip };
}
async function persistLeft(ident, left) {
  if (ident.kind === 'user') {
    const users = await store.loadUsers();
    if (users[ident.userId]) { users[ident.userId].left = left; await store.saveUsers(users); }
  } else if (ident.kind === 'guest') {
    const guests = await store.loadGuests();
    if (guests[ident.ip]) { guests[ident.ip].left = left; await store.saveGuests(guests); }
  }
}

// ---------- quota middleware (counts scans; skips exempt paths) ----------
async function quotaMiddleware(req, res, next) {
  try {
    if (EXEMPT.some((re) => re.test(req.path))) return next();
    const ident = await resolveIdentity(req);
    if ((ident.kind === 'key' || ident.kind === 'token') && ident.valid === false) {
      return fail(res, 401, ident.kind === 'key' ? 'Invalid API key' : 'Invalid or expired session — log in again');
    }
    req.ident = ident;
    if (!ident.infinite) {
      if (!(ident.left > 0)) {
        return res.status(402).json({
          success: false, code: 'QUOTA_EXHAUSTED', tier: ident.tier, searches_left: 0,
          error: ident.kind === 'guest'
            ? 'Guest scans used up (2 lifetime). Sign up free for 50 scans, or log in.'
            : 'Scan quota used up (50 lifetime). Log in as a super user or use an API key for unlimited.',
          timestamp: new Date().toISOString(),
        });
      }
      const after = ident.left - 1; // charge upfront (awaited: no double-spend races)…
      await persistLeft(ident, after);
      res.setHeader('X-Searches-Left', String(after));
      res.on('finish', () => { if (res.statusCode >= 500) persistLeft(ident, after + 1).catch(() => {}); }); // …refund on server failure
    } else {
      res.setHeader('X-Searches-Left', 'infinite');
    }
    res.setHeader('X-Tier', ident.tier);
    next();
  } catch (e) { next(e); }
}

// ---------- validation ----------
function validUsername(u) { return typeof u === 'string' && /^[a-zA-Z0-9._-]{3,24}$/.test(u.trim()); }
function validDob(d) {
  if (typeof d !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(d)) return null;
  const dt = new Date(d + 'T00:00:00Z');
  if (Number.isNaN(dt.getTime())) return null;
  const now = new Date();
  if (dt > now || dt.getUTCFullYear() < 1900) return null;
  let age = now.getUTCFullYear() - dt.getUTCFullYear();
  const m = now.getUTCMonth() - dt.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < dt.getUTCDate())) age--;
  if (age < 13) return null;
  return d;
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 40, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { success: false, error: 'Too many auth attempts — try again in 15 minutes' },
});
// Login gets its own much tighter bucket: passwords must not be guessable at 40/15min.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { success: false, error: 'Too many login attempts — try again in 15 minutes' },
});
router.use(authLimiter);

// POST /api/auth/signup { username, password, repeat, dob }
router.post('/signup', ah(async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const repeat = String(req.body?.repeat ?? req.body?.repeatPassword ?? '');
  const dob = validDob(req.body?.dob);
  if (!validUsername(username)) return fail(res, 400, 'Username: 3–24 chars, letters/numbers/._- only');
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) return fail(res, 400, 'Password must be 8–200 characters');
  if (password.toLowerCase() === username.toLowerCase()) return fail(res, 400, 'Password must differ from username');
  if (repeat !== undefined && repeat !== '' && repeat !== password) return fail(res, 400, 'Passwords do not match');
  if (req.body?.dob !== undefined && !dob) return fail(res, 400, 'Date of birth invalid (YYYY-MM-DD, age 13+, not future)');
  const cf = await verifyTurnstile(req.body?.cf_token, req.ip);
  if (!cf.skipped && !cf.ok) return fail(res, 400, 'Captcha check failed — please retry');
  const users = await store.loadUsers();
  if (Object.values(users).some((u) => u.username.toLowerCase() === username.toLowerCase())) {
    return fail(res, 409, 'Username is taken');
  }
  const pass = await hashPassword(password);
  const id = crypto.randomBytes(8).toString('hex');
  // First-super recovery: if the database somehow has no super user left
  // (deleted seed, fresh restore), the next signup claims super instead of
  // bricking admin access forever. Logged loudly; normal signups unaffected.
  let tier = 'user';
  let left = TIERS.user.quota;
  if (!Object.values(users).some((u) => u.tier === 'super')) {
    tier = 'super';
    left = Infinity;
    console.warn(`(!) no super user exists — granting super to '${username}' (first-super recovery)`);
  }
  users[id] = { id, username, pass, tier, left, dob: dob || null, created: new Date().toISOString() };
  await store.saveUsers(users);
  return ok(res, { token: await signToken(id), username, tier, searches_left: tier === 'super' ? 'infinite' : left });
}));

// POST /api/auth/login { username, password }
// NOTE: unknown usernames still pay one full scrypt (DUMMY_PASS) so timing
// alone can never reveal whether an account exists. Error text is identical
// for both cases for the same reason.
const DUMMY_PASS = { salt: '0'.repeat(32), hash: '0'.repeat(128) };
router.post('/login', loginLimiter, ah(async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) return fail(res, 401, 'Invalid username or password');
  const cfLogin = await verifyTurnstile(req.body?.cf_token, req.ip);
  if (!cfLogin.skipped && !cfLogin.ok) return fail(res, 400, 'Captcha check failed — please retry');
  // Overlong input still pays one scrypt so even length can't be timed.
  if (password.length > 200) { await verifyPassword(password.slice(0, 64), DUMMY_PASS); return fail(res, 401, 'Invalid username or password'); }
  const users = await store.loadUsers();
  const u = Object.values(users).find((x) => x.username.toLowerCase() === username.toLowerCase());
  // Exactly one scrypt on every path — equal cost for known/unknown/malformed accounts.
  const okPass = await verifyPassword(password, u && u.pass ? u.pass : DUMMY_PASS);
  if (!u || !okPass) {
    return fail(res, 401, 'Invalid username or password');
  }
  // TOTP second factor: password alone only earns a 5-minute pre-token.
  if (u.totp && u.totp.enabled) {
    return ok(res, { totp_required: true, tmp: await preToken(u.id), username: u.username });
  }
  return ok(res, {
    token: await signToken(u.id), username: u.username, tier: u.tier,
    searches_left: u.tier === 'super' ? 'infinite' : u.left,
  });
}));

// GET /api/auth/me — who am I + quota (works logged out → guest bucket)
router.get('/me', ah(async (req, res) => {
  const ident = await resolveIdentity(req);
  if ((ident.kind === 'key' || ident.kind === 'token') && ident.valid === false) {
    return ok(res, { logged_in: false, username: 'Guest', tier: 'guest', searches_left: 0, invalid_credential: true });
  }
  let totpEnabled = false;
  if ((ident.kind === 'user' || ident.kind === 'key') && ident.userId) {
    try {
      const users = await store.loadUsers();
      const me = users[ident.userId];
      totpEnabled = !!(me && me.totp && me.totp.enabled);
    } catch { /* flag stays false rather than failing the whole call */ }
  }
  return ok(res, {
    logged_in: ident.kind !== 'guest',
    username: ident.username, tier: ident.tier,
    searches_left: ident.infinite ? 'infinite' : ident.left,
    kind: ident.kind,
    totp_enabled: totpEnabled,
  });
}));

// POST /api/auth/password { current, next } — change own password
router.post('/password', ah(async (req, res) => {
  const auth = String(req.headers.authorization || '');
  const m = /^Bearer\s+(.+)$/.exec(auth);
  const p = m && await readToken(m[1].trim());
  if (!p) return fail(res, 401, 'Log in first');
  const users = await store.loadUsers();
  const u = users[p.uid];
  if (!u) return fail(res, 401, 'Log in first');
  const next = String(req.body?.next || '');
  if (!(await verifyPassword(String(req.body?.current || ''), u.pass))) return fail(res, 401, 'Current password is wrong');
  if (next.length < 8 || next.length > 200) return fail(res, 400, 'New password must be 8–200 characters');
  u.pass = await hashPassword(next);
  await store.saveUsers(users);
  return ok(res, { changed: true });
}));

async function requireUser(req, res, next) {
  try {
    const auth = String(req.headers.authorization || '');
    const m = /^Bearer\s+(.+)$/.exec(auth);
    const p = m && await readToken(m[1].trim());
    const users = await store.loadUsers();
    const u = p && users[p.uid];
    if (!u) return fail(res, 401, 'Log in first');
    req.user = u;
    next();
  } catch (e) { next(e); }
}
function requireSuper(req, res, next) {
  requireUser(req, res, (err) => {
    if (err) return next(err);
    if (!req.user || req.user.tier !== 'super') return fail(res, 403, 'Super users only');
    next();
  });
}

// GET /api/auth/keys — list my keys (super only; keys are infinite)
router.get('/keys', requireSuper, ah(async (req, res) => {
  const mine = (await store.loadKeys()).filter((k) => k.userId === req.user.id)
    .map((k) => ({ id: k.id, label: k.label, prefix: k.prefix, created: k.created, last_used: k.last_used || null }));
  return ok(res, mine, { count: mine.length });
}));

// POST /api/auth/keys { label } — mint an infinite key (super only, full key shown ONCE)
router.post('/keys', requireSuper, ah(async (req, res) => {
  const label = oneLine(req.body?.label || 'default', 60) || 'default';
  const raw = 'evk_' + crypto.randomBytes(24).toString('hex');
  const keys = await store.loadKeys();
  const rec = {
    id: crypto.randomBytes(8).toString('hex'), userId: req.user.id, label,
    hash: crypto.createHash('sha256').update(raw).digest('hex'),
    prefix: raw.slice(0, 12) + '…', created: new Date().toISOString(), last_used: null,
  };
  keys.push(rec);
  await store.saveKeys(keys);
  return ok(res, { id: rec.id, label, key: raw, note: 'Copy it now — the full key is never shown again. Keys grant infinite searches.' });
}));

// DELETE /api/auth/keys/:id — revoke (super only)
router.delete('/keys/:id', requireSuper, ah(async (req, res) => {
  const keys = await store.loadKeys();
  const i = keys.findIndex((k) => k.id === req.params.id && k.userId === req.user.id);
  if (i < 0) return fail(res, 404, 'Key not found');
  keys.splice(i, 1);
  await store.saveKeys(keys);
  return ok(res, { revoked: true });
}));

// ---------- short-lived TOTP pre-tokens (5 min, single purpose) ----------
async function preToken(uid) {
  const payload = Buffer.from(JSON.stringify({ uid, purpose: 'totp', exp: Date.now() + 5 * 60 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', await store.getSecret()).update('pre.' + payload).digest('hex');
  return `pre.${payload}.${sig}`;
}
async function readPreToken(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3 || parts[0] !== 'pre') return null;
    const sig = crypto.createHmac('sha256', await store.getSecret()).update(parts[0] + '.' + parts[1]).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(parts[2], 'hex'))) return null;
    const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (p.purpose !== 'totp' || !p.uid || p.exp < Date.now()) return null;
    return p;
  } catch { return null; }
}

// ---------- Cloudflare Turnstile (optional bot wall) ----------
// Inactive unless TURNSTILE_SECRET is set — zero behavior change otherwise.
async function verifyTurnstile(token, ip) {
  if (!process.env.TURNSTILE_SECRET) return { skipped: true };
  if (!token) return { ok: false };
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: process.env.TURNSTILE_SECRET, response: String(token), remoteip: ip || '' }),
      signal: AbortSignal.timeout(10000),
    });
    const j = await r.json().catch(() => ({}));
    return { ok: j.success === true };
  } catch { return { ok: false }; }
}

// GET /api/auth/config — public knobs the UI needs (site key is public by design)
router.get('/config', (req, res) => {
  return ok(res, { turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
});

// POST /api/auth/totp/setup — mint a fresh secret (stays disabled until verified)
router.post('/totp/setup', requireUser, async (req, res) => {
  const secret = base32Encode(crypto.randomBytes(20));
  const users = await store.loadUsers();
  const u = users[req.user.id];
  if (!u) return fail(res, 401, 'Log in first');
  u.totp = { secret, enabled: false, backup: [], created: new Date().toISOString() };
  await store.saveUsers(users);
  const label = encodeURIComponent(`Evosint:${u.username}`);
  return ok(res, {
    secret,
    uri: `otpauth://totp/${label}?secret=${secret}&issuer=Evosint&digits=6&period=30`,
    note: 'Add the key to any authenticator app, then confirm with a 6-digit code.',
  });
});

// POST /api/auth/totp/enable { code } — verify + activate, backup codes shown ONCE
router.post('/totp/enable', requireUser, async (req, res) => {
  const users = await store.loadUsers();
  const u = users[req.user.id];
  if (!u || !u.totp || !u.totp.secret) return fail(res, 400, 'Run setup first');
  if (!totpVerify(u.totp.secret, req.body?.code)) return fail(res, 400, 'Wrong code — check the clock and retry');
  const codes = newBackupCodes();
  u.totp.enabled = true;
  u.totp.backup = codes.map(sha256hex);
  u.totp.enabled_at = new Date().toISOString();
  await store.saveUsers(users);
  return ok(res, { enabled: true, backup_codes: codes, note: 'Save these — each works once if you lose the app.' });
});

// POST /api/auth/totp/disable { password }
router.post('/totp/disable', requireUser, async (req, res) => {
  const users = await store.loadUsers();
  const u = users[req.user.id];
  if (!u) return fail(res, 401, 'Log in first');
  if (!(await verifyPassword(String(req.body?.password || ''), u.pass))) return fail(res, 401, 'Current password is wrong');
  u.totp = null;
  await store.saveUsers(users);
  return ok(res, { disabled: true });
});

// POST /api/auth/totp/verify { tmp, code? , backup_code? } — finish a TOTP login
router.post('/totp/verify', loginLimiter, async (req, res) => {
  const pre = await readPreToken(req.body?.tmp);
  if (!pre) return fail(res, 401, 'Login session expired — start over');
  const users = await store.loadUsers();
  const u = users[pre.uid];
  if (!u || !u.totp || !u.totp.enabled) return fail(res, 401, 'Two-factor is not enabled here');
  const code = String(req.body?.code || '').replace(/\D/g, '');
  const backup = String(req.body?.backup_code || '').trim().toUpperCase();
  if (code && totpVerify(u.totp.secret, code)) {
    return ok(res, { token: await signToken(u.id), username: u.username, tier: u.tier, searches_left: u.tier === 'super' ? 'infinite' : u.left });
  }
  if (backup) {
    const digest = sha256hex(backup);
    const i = (u.totp.backup || []).indexOf(digest);
    if (i >= 0) {
      u.totp.backup.splice(i, 1); // single use — burn it
      await store.saveUsers(users);
      return ok(res, { token: await signToken(u.id), username: u.username, tier: u.tier, searches_left: u.tier === 'super' ? 'infinite' : u.left, backup_remaining: u.totp.backup.length });
    }
  }
  return fail(res, 401, 'Wrong code');
});

// GET /api/auth/backup — full export for the super user (hashes only, never raw keys)
router.get('/backup', requireSuper, async (req, res) => {
  const [users, keys, guests] = await Promise.all([store.loadUsers(), store.loadKeys(), store.loadGuests()]);
  return ok(res, { exported_at: new Date().toISOString(), version: 1, users, keys, guests });
});

// POST /api/auth/restore { data } — super-only full replace (shape-checked)
router.post('/backup/restore', requireSuper, async (req, res) => {
  const d = req.body?.data;
  if (!d || typeof d !== 'object' || d.version !== 1 || !d.users || typeof d.users !== 'object' || !Array.isArray(d.keys) || !d.guests || typeof d.guests !== 'object') {
    return fail(res, 400, 'Invalid backup (need {version:1, users:{}, keys:[], guests:{}})');
  }
  for (const u of Object.values(d.users)) {
    if (!u || typeof u.username !== 'string' || !u.pass || !u.pass.salt || !u.pass.hash || !['user', 'super'].includes(u.tier)) {
      return fail(res, 400, 'Backup users are malformed — refusing to import');
    }
  }
  await store.saveUsers(d.users);
  await store.saveKeys(d.keys);
  await store.saveGuests(d.guests);
  return ok(res, { restored: true, users: Object.keys(d.users).length, keys: d.keys.length });
});

module.exports = { router, quotaMiddleware, resolveIdentity, persistLeft, ensureSeed, TIERS };
