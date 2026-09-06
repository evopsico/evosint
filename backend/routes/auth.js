const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const store = require('../utils/store');
const { ok, fail, oneLine } = require('../utils/validate');

const router = express.Router();

const TIERS = {
  guest: { label: 'Guest', quota: 2 },
  user: { label: 'User', quota: 50 },
  super: { label: 'Super', quota: Infinity },
};
const EXEMPT = [/^\/auth(\/|$)/, /^\/health\/?$/, /^\/lab\/limits\/?$/, /^\/username\/catalog\/list\/?$/];

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
router.post('/signup', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const repeat = String(req.body?.repeat ?? req.body?.repeatPassword ?? '');
  const dob = validDob(req.body?.dob);
  if (!validUsername(username)) return fail(res, 400, 'Username: 3–24 chars, letters/numbers/._- only');
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) return fail(res, 400, 'Password must be 8–200 characters');
  if (password.toLowerCase() === username.toLowerCase()) return fail(res, 400, 'Password must differ from username');
  if (repeat !== undefined && repeat !== '' && repeat !== password) return fail(res, 400, 'Passwords do not match');
  if (req.body?.dob !== undefined && !dob) return fail(res, 400, 'Date of birth invalid (YYYY-MM-DD, age 13+, not future)');
  const users = await store.loadUsers();
  if (Object.values(users).some((u) => u.username.toLowerCase() === username.toLowerCase())) {
    return fail(res, 409, 'Username is taken');
  }
  const pass = await hashPassword(password);
  const id = crypto.randomBytes(8).toString('hex');
  users[id] = { id, username, pass, tier: 'user', left: TIERS.user.quota, dob: dob || null, created: new Date().toISOString() };
  await store.saveUsers(users);
  return ok(res, { token: await signToken(id), username, tier: 'user', searches_left: TIERS.user.quota });
});

// POST /api/auth/login { username, password }
// NOTE: unknown usernames still pay one full scrypt (DUMMY_PASS) so timing
// alone can never reveal whether an account exists. Error text is identical
// for both cases for the same reason.
const DUMMY_PASS = { salt: '0'.repeat(32), hash: '0'.repeat(128) };
router.post('/login', loginLimiter, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) return fail(res, 401, 'Invalid username or password');
  // Overlong input still pays one scrypt so even length can't be timed.
  if (password.length > 200) { await verifyPassword(password.slice(0, 64), DUMMY_PASS); return fail(res, 401, 'Invalid username or password'); }
  const users = await store.loadUsers();
  const u = Object.values(users).find((x) => x.username.toLowerCase() === username.toLowerCase());
  // Exactly one scrypt on every path — equal cost for known/unknown/malformed accounts.
  const okPass = await verifyPassword(password, u && u.pass ? u.pass : DUMMY_PASS);
  if (!u || !okPass) {
    return fail(res, 401, 'Invalid username or password');
  }
  return ok(res, {
    token: await signToken(u.id), username: u.username, tier: u.tier,
    searches_left: u.tier === 'super' ? 'infinite' : u.left,
  });
});

// GET /api/auth/me — who am I + quota (works logged out → guest bucket)
router.get('/me', async (req, res) => {
  const ident = await resolveIdentity(req);
  if ((ident.kind === 'key' || ident.kind === 'token') && ident.valid === false) {
    return ok(res, { logged_in: false, username: 'Guest', tier: 'guest', searches_left: 0, invalid_credential: true });
  }
  return ok(res, {
    logged_in: ident.kind !== 'guest',
    username: ident.username, tier: ident.tier,
    searches_left: ident.infinite ? 'infinite' : ident.left,
    kind: ident.kind,
  });
});

// POST /api/auth/password { current, next } — change own password
router.post('/password', async (req, res) => {
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
});

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
router.get('/keys', requireSuper, async (req, res) => {
  const mine = (await store.loadKeys()).filter((k) => k.userId === req.user.id)
    .map((k) => ({ id: k.id, label: k.label, prefix: k.prefix, created: k.created, last_used: k.last_used || null }));
  return ok(res, mine, { count: mine.length });
});

// POST /api/auth/keys { label } — mint an infinite key (super only, full key shown ONCE)
router.post('/keys', requireSuper, async (req, res) => {
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
});

// DELETE /api/auth/keys/:id — revoke (super only)
router.delete('/keys/:id', requireSuper, async (req, res) => {
  const keys = await store.loadKeys();
  const i = keys.findIndex((k) => k.id === req.params.id && k.userId === req.user.id);
  if (i < 0) return fail(res, 404, 'Key not found');
  keys.splice(i, 1);
  await store.saveKeys(keys);
  return ok(res, { revoked: true });
});

module.exports = { router, quotaMiddleware, resolveIdentity, ensureSeed, TIERS };
