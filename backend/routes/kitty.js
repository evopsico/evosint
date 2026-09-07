const express = require('express');
const rateLimit = require('express-rate-limit');
const store = require('../utils/store');
const { ok, fail } = require('../utils/validate');
const { resolveIdentity, persistLeft } = require('./auth');

const router = express.Router();

// ---- Kitty clicker: 1,000 clicks = +20 scans. Clicks never cost scans
// (exempted from quota in auth.js EXEMPT). Counting is server-side so the
// award can't be forged by editing client state; a daily award cap bounds
// scripted farming while leaving humans plenty of room.
const PER = 1000;
const REWARD = 20;
const MAX_AWARDS_PER_DAY = 10;

// Flushes arrive batched (~1 per 2s per tab), so this is generous to humans
// and still useless for floods (flooding only burns the daily award cap).
const kittyLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 200, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { success: false, error: 'Kitty is dizzy — slow down a little' },
});
router.use(kittyLimiter);

const dayUTC = () => new Date().toISOString().slice(0, 10);

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

function stateOf(ident, st) {
  return {
    clicks: st.c, per: PER, reward: REWARD, to_next: Math.max(0, PER - st.c),
    awards_today: st.awards, awards_left_today: Math.max(0, MAX_AWARDS_PER_DAY - st.awards),
    daily_cap: MAX_AWARDS_PER_DAY,
    scans_left: ident.infinite ? 'infinite' : ident.left, tier: ident.tier,
  };
}

// GET /api/kitty/state — counter + balance for first paint (free, like /auth/me)
router.get('/state', async (req, res) => {
  try {
    const ident = await identOr401(req, res);
    if (!ident) return;
    if (ident.infinite) {
      quotaHeaders(res, ident);
      return ok(res, { clicks: 0, per: PER, reward: REWARD, to_next: PER, awards_today: 0, awards_left_today: MAX_AWARDS_PER_DAY, daily_cap: MAX_AWARDS_PER_DAY, scans_left: 'infinite', tier: ident.tier, note: 'Infinite plan — kitty is just for fun' });
    }
    const K = await store.loadKitty();
    const bucket = ident.kind === 'user' ? (K.u = K.u || {}) : (K.g = K.g || {});
    const idk = ident.kind === 'user' ? ident.userId : ident.ip;
    const today = dayUTC();
    let st = bucket[idk];
    if (!st || st.day !== today) st = bucket[idk] = { c: 0, day: today, awards: 0 };
    quotaHeaders(res, ident, ident.left);
    return ok(res, stateOf(ident, st), { source: 'kitty' });
  } catch (e) { return fail(res, 500, 'Kitty state failed'); }
});

// POST /api/kitty/click { n } — add a batch of clicks, pay out full thousands
router.post('/click', async (req, res) => {
  try {
    const ident = await identOr401(req, res);
    if (!ident) return;
    const n = Math.floor(Number(req.body?.n));
    if (!Number.isFinite(n) || n < 1 || n > 200) return fail(res, 400, 'Body { n } with 1–200 clicks required');
    if (ident.infinite) {
      quotaHeaders(res, ident);
      return ok(res, { clicks: 0, per: PER, reward: REWARD, to_next: PER, awards_today: 0, awards_left_today: MAX_AWARDS_PER_DAY, daily_cap: MAX_AWARDS_PER_DAY, earned: 0, scans_added: 0, scans_left: 'infinite', tier: ident.tier, note: 'Infinite plan — kitty is just for fun' });
    }
    const K = await store.loadKitty();
    const bucket = ident.kind === 'user' ? (K.u = K.u || {}) : (K.g = K.g || {});
    const idk = ident.kind === 'user' ? ident.userId : ident.ip;
    const today = dayUTC();
    let st = bucket[idk];
    if (!st || st.day !== today) st = bucket[idk] = { c: 0, day: today, awards: 0 };
    let earned = 0;
    if (st.awards < MAX_AWARDS_PER_DAY) {
      st.c += n;
      while (st.c >= PER && st.awards < MAX_AWARDS_PER_DAY) { st.c -= PER; st.awards += 1; earned += 1; }
      if (earned > 0) {
        const after = ident.left + earned * REWARD;
        await persistLeft(ident, after);
        ident.left = after;
      }
      await store.saveKitty(K);
    }
    quotaHeaders(res, ident, ident.left);
    return ok(res, { ...stateOf(ident, st), earned, scans_added: earned * REWARD, capped: st.awards >= MAX_AWARDS_PER_DAY }, { source: 'kitty' });
  } catch (e) { return fail(res, 500, 'Kitty click failed'); }
});

module.exports = router;
