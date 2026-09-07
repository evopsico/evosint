const express = require('express');
const rateLimit = require('express-rate-limit');
const store = require('../utils/store');
const { ok, fail } = require('../utils/validate');
const { resolveIdentity, persistLeft, verifyTurnstile } = require('./auth');

const router = express.Router();

// ---- Kitty clicker: 1,000 taps = +20 scans. Clicks never cost scans
// (exempted from quota in auth.js EXEMPT). Counting is server-side so the
// award can't be forged by editing client state; a daily award cap bounds
// scripted farming while leaving humans plenty of room.
//
// ANTI-AUTOCLICKER: every tap carries timing + pointer evidence [dt_ms, x, y]
// (keyboard taps send null coords). A rhythm-forensics engine scores batches
// for metronome regularity, fixed-point tapping, impossible rates and forged
// timestamps; suspects must pass a fair-play challenge (Turnstile when
// configured, cooldown otherwise) before awards release. Taps always COUNT
// (the counter never visibly resets); only the PAYOUT can be held.
const PER = Math.max(10, parseInt(process.env.KITTY_PER, 10) || 1000);
const REWARD = 20;
const MAX_AWARDS_PER_DAY = 10;
const TAP_CAP = 60;
const CH_AT = 30;   // suspicion → 10-minute hold + challenge
const LOCK_AT = 70; // sustained botting → 60-minute hold + challenge
const BUCKET_CAP = 20;        // batch-arrival token bucket (per identity)
const BUCKET_REFILL_MS = 1000;

// Outer IP guard; the per-identity token bucket below governs arrival pace.
const kittyLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 400, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { success: false, error: 'Kitty is dizzy — slow down a little' },
});
router.use(kittyLimiter);

const dayUTC = () => new Date().toISOString().slice(0, 10);
const turnstileArmed = () => !!(process.env.TURNSTILE_SECRET && process.env.TURNSTILE_SITE_KEY);

function quotaHeaders(res, ident, left) {
  res.setHeader('X-Searches-Left', ident.infinite ? 'infinite' : String(left));
  res.setHeader('X-Tier', ident.tier);
}

async function identOr401(req, res) {
  const ident = await resolveIdentity(req);
  if ((ident.kind === 'key' || ident.kind === 'token') && ident.valid === false) {
    fail(res, 401, ident.kind === 'key' ? 'Invalid API key' : 'Invalid or expired session — log in again');
    return null;
  }
  return ident;
}

function stateOf(ident, st, now) {
  const committed = (st.awards || 0) + (st.held || 0);
  return {
    clicks: st.c, per: PER, reward: REWARD, to_next: Math.max(0, PER - st.c),
    awards_today: st.awards, awards_left_today: Math.max(0, MAX_AWARDS_PER_DAY - committed),
    daily_cap: MAX_AWARDS_PER_DAY,
    scans_left: ident.infinite ? 'infinite' : ident.left, tier: ident.tier,
    note: ident.infinite ? 'Infinite plan — clicks count for glory' : '',
    challenged: now < (st.until || 0), cooldown_ms: Math.max(0, (st.until || 0) - now),
    held: st.held || 0, turnstile: turnstileArmed(),
  };
}

function kittyBucket(K, ident) {
  // API-key holders share their owner's user bucket; guests use the IP bucket.
  const key = ident.kind === 'guest' ? 'g' : 'u';
  const idk = ident.kind === 'guest' ? ident.ip : ident.userId;
  const bucket = key === 'u' ? (K.u = K.u || {}) : (K.g = K.g || {});
  return [bucket, idk];
}

function freshEntry(today) {
  return { c: 0, day: today, awards: 0, score: 0, until: 0, held: 0, ts: [], upd: Date.now(), tok: BUCKET_CAP, lastRefill: Date.now() };
}

function scoreDecay(st, now) {
  const h = (now - (st.upd || now)) / 36e5;
  if (h > 0) st.score = Math.max(0, (st.score || 0) - h * 3);
  st.upd = now;
}

function refillBucket(st, now) {
  st.tok = Math.min(BUCKET_CAP, (st.tok ?? BUCKET_CAP) + (now - (st.lastRefill || now)) / BUCKET_REFILL_MS);
  st.lastRefill = now;
}

// Sanitize one batch: [[dt_ms, x, y|null], ...] → valid taps (chronological).
function validTaps(taps) {
  if (!Array.isArray(taps) || taps.length < 1 || taps.length > TAP_CAP) return null;
  const out = [];
  for (const t of taps) {
    if (!Array.isArray(t) || t.length < 1) continue;
    let dt = Number(t[0]);
    if (!Number.isFinite(dt)) continue;
    dt = Math.max(0, Math.min(10000, Math.round(dt)));
    let x = t[1], y = t[2];
    if (x === null || x === undefined || y === null || y === undefined) { x = null; y = null; }
    else {
      x = Number(x); y = Number(y);
      if (!Number.isFinite(x) || !Number.isFinite(y)) continue;
      x = Math.round(x); y = Math.round(y);
      if (x < -100 || x > 1000 || y < -100 || y > 1000) continue;
    }
    out.push({ dt, x, y });
  }
  return out;
}

function meanStd(a) {
  if (!a.length) return { mean: 0, std: 0 };
  const mean = a.reduce((s, v) => s + v, 0) / a.length;
  return { mean, std: Math.sqrt(a.reduce((s, v) => s + (v - mean) * (v - mean), 0) / a.length) };
}

// Rhythm forensics. Returns suspicion points for this batch (0 = clean human).
function forensics(valid, st, now) {
  let pts = 0;
  const ptr = valid.filter((t) => t.x !== null);       // pointer taps (movement signals apply)
  const iv = valid.slice(1).map((t) => t.dt);          // skip inter-batch gap
  const piv = ptr.slice(1).map((t) => t.dt);
  const ps = meanStd(piv);
  // S1 metronome: superhuman regularity at speed (OS key-repeat excluded: null coords).
  if (piv.length >= 7 && ps.mean < 500 && ps.std < 4) pts += 10;
  // S2 fixed point: same pixel, fast, repeatedly — fingers jitter, scripts don't.
  if (ptr.length >= 5 && ps.mean < 300) {
    const same = ptr.every((t) => t.x === ptr[0].x && t.y === ptr[0].y);
    if (same) pts += 8;
  }
  // S3 impossible single intervals (generous: humans bottom out ~40ms; needs
  // two strikes so one touch-bounce glitch never counts).
  if (iv.filter((v) => v < 18).length >= 2) pts += 12;
  // S4 claimed burst rate over this batch's own span (floor: short human
  // double-tap bursts must not trip it).
  const span = iv.reduce((a, b) => a + b, 0);
  if (valid.length >= 15 && span > 0 && valid.length / (span / 1000) > 30) pts += 10;
  // S5 forged timestamps: claims more tapping than wall-clock allows. Tolerance
  // covers legit flush batching (~2s spans); machine-arrival bots always trip.
  if (st.lastSeen && span > now - st.lastSeen + 5000) pts += 15;
  // S6 sustained rate over reconstructed tap times (30s window). st.ts already
  // includes this batch — never add it twice. Cap 2000 keeps memory bounded
  // while leaving headroom above the threshold (400/30 could never fire).
  const recent = (st.ts || []).filter((t) => t > now - 30000).length;
  if (recent / 30 > 14) pts += 6;
  // S7 keyboard-only machine gun (above any OS repeat rate).
  const kbd = valid.filter((t) => t.x === null);
  if (kbd.length >= 10) {
    const ks = meanStd(kbd.slice(1).map((t) => t.dt));
    if (ks.mean < 25) pts += 10;
  }
  return pts;
}

function tripwire(st, now) {
  if ((st.score || 0) >= LOCK_AT) st.until = Math.max(st.until || 0, now + 3600e3);
  else if ((st.score || 0) >= CH_AT && (st.until || 0) - now < 5 * 60e3) st.until = now + 600e3;
}

async function payEarned(st, ident, earnable, earned) {
  // Infinite plans stack milestones for glory but need no scans; writing
  // Infinity into the quota store would corrupt it (Infinity → null in JSON).
  if (earned > 0 && earnable) {
    const after = ident.left + earned * REWARD;
    await persistLeft(ident, after);
    ident.left = after;
  }
  return earnable ? earned * REWARD : 0;
}

// Release held awards after a passed challenge (or expired cooldown).
async function releaseHold(st, ident) {
  const earnable = !ident.infinite;
  const rel = Math.min(st.held || 0, Math.max(0, MAX_AWARDS_PER_DAY - st.awards));
  if (rel > 0) {
    st.awards += rel;
    if (earnable) {
      const after = ident.left + rel * REWARD;
      await persistLeft(ident, after);
      ident.left = after;
    }
  }
  st.held = 0;
  return earnable ? rel * REWARD : 0;
}

// GET /api/kitty/state — counter + balance + challenge status (free, like /auth/me)
router.get('/state', async (req, res) => {
  try {
    const ident = await identOr401(req, res);
    if (!ident) return;
    const now = Date.now();
    const K = await store.loadKitty();
    const [bucket, idk] = kittyBucket(K, ident);
    const today = dayUTC();
    let st = bucket[idk];
    if (!st || st.day !== today) { st = bucket[idk] = freshEntry(today); await store.saveKitty(K); }
    else { scoreDecay(st, now); }
    if (now >= (st.until || 0) && (st.held || 0) > 0) { await releaseHold(st, ident); await store.saveKitty(K); }
    quotaHeaders(res, ident, ident.left);
    return ok(res, stateOf(ident, st, now), { source: 'kitty' });
  } catch (e) { return fail(res, 500, 'Kitty state failed'); }
});

// POST /api/kitty/click { taps: [[dt_ms, x, y|null], ...], cf_token? }
router.post('/click', async (req, res) => {
  try {
    const ident = await identOr401(req, res);
    if (!ident) return;
    const valid = validTaps(req.body?.taps);
    if (!valid || !valid.length) {
      const legacy = req.body?.n !== undefined;
      return fail(res, 400, legacy ? 'Kitty client too old — refresh the page' : 'Body { taps: [[dt_ms, x, y], …] × up to 60 } required');
    }
    const now = Date.now();
    const earnable = !ident.infinite;
    const K = await store.loadKitty();
    const [bucket, idk] = kittyBucket(K, ident);
    const today = dayUTC();
    let st = bucket[idk];
    if (!st || st.day !== today) st = bucket[idk] = freshEntry(today);
    scoreDecay(st, now);
    // Arrival throttle (token bucket): legit flushes land ~1 per 2s; floods 429.
    refillBucket(st, now);
    if (st.tok < 1) {
      await store.saveKitty(K);
      quotaHeaders(res, ident, ident.left);
      return fail(res, 429, 'Too many taps at once — kitty is catching its breath');
    }
    st.tok -= 1;
    // Reconstruct tap times (anchored at now) for sustained-rate analysis.
    let t = now;
    const times = [];
    for (let i = valid.length - 1; i >= 0; i--) { t -= valid[i].dt; times.unshift(t); }
    st.ts = [...(st.ts || []), ...times].filter((x) => x > now - 120000).slice(-2000);
    st.score = (st.score || 0) + forensics(valid, st, now);
    st.lastSeen = now;
    tripwire(st, now);
    // Challenge clearing: a fresh Turnstile token, or an expired cooldown.
    let released = 0;
    const cf = req.body?.cf_token;
    if (cf && turnstileArmed()) {
      try {
        const v = await verifyTurnstile(String(cf), req.ip);
        if (v.ok) { st.until = 0; st.score = Math.min(st.score || 0, 10); released = await releaseHold(st, ident); }
      } catch {}
    }
    if (now >= (st.until || 0) && (st.held || 0) > 0) released += await releaseHold(st, ident);
    const challenged = now < (st.until || 0);
    let earned = 0, added = 0;
    // Held awards reserve cap space so a held payout can never overflow the day.
    const capacity = () => MAX_AWARDS_PER_DAY - st.awards - (st.held || 0);
    if (capacity() > 0) {
      st.c += valid.length;
      while (st.c >= PER && capacity() > 0) { st.c -= PER; earned += 1; if (!challenged) st.awards += 1; }
      if (earned > 0) {
        if (challenged) st.held = (st.held || 0) + earned; // held, released on verify
        else added = await payEarned(st, ident, earnable, earned);
      }
      await store.saveKitty(K);
    }
    quotaHeaders(res, ident, ident.left);
    return ok(res, { ...stateOf(ident, st, now), earned, scans_added: added, released, capped: capacity() <= 0 }, { source: 'kitty' });
  } catch (e) { return fail(res, 500, 'Kitty click failed'); }
});

// POST /api/kitty/verify { cf_token } — pass the fair-play challenge early
router.post('/verify', async (req, res) => {
  try {
    const ident = await identOr401(req, res);
    if (!ident) return;
    const now = Date.now();
    const K = await store.loadKitty();
    const [bucket, idk] = kittyBucket(K, ident);
    const today = dayUTC();
    let st = bucket[idk];
    if (!st || st.day !== today) { st = bucket[idk] = freshEntry(today); }
    scoreDecay(st, now);
    let cleared = now >= (st.until || 0);
    let released = 0;
    if (!cleared && turnstileArmed() && req.body?.cf_token) {
      try {
        const v = await verifyTurnstile(String(req.body.cf_token), req.ip);
        if (v.ok) { st.until = 0; st.score = Math.min(st.score || 0, 10); cleared = true; }
      } catch {}
    }
    if (cleared && (st.held || 0) > 0) released = await releaseHold(st, ident);
    await store.saveKitty(K);
    quotaHeaders(res, ident, ident.left);
    return ok(res, { ...stateOf(ident, st, now), cleared, released }, { source: 'kitty' });
  } catch (e) { return fail(res, 500, 'Kitty verify failed'); }
});

module.exports = router;
