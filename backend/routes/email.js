const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidEmail, ok, fail, axiosError } = require('../utils/validate');

/**
 * GET /api/email/:email — breach check.
 * v1 flaw fixed: sent fake 'no-key-public' HIBP key so EVERY request 401'd.
 * Now: HIBP when HIBP_API_KEY is set, otherwise free XposedOrNot fallback.
 */
router.get('/:email', async (req, res) => {
  const email = String(req.params.email || '').trim();
  if (!isValidEmail(email)) return fail(res, 400, 'Invalid email format');

  try {
    const { data, cached } = await getOrSet(`email:${email.toLowerCase()}`, 3600, async () => {
      const hibpKey = process.env.HIBP_API_KEY;
      if (hibpKey) {
        const r = await http.get(
          `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
          { headers: { 'User-Agent': 'Evosint', 'hibp-api-key': hibpKey }, timeout: 10000 }
        );
        if (r.status === 404) return { breached: false, count: 0, breaches: [], source: 'haveibeenpwned' };
        if (r.status === 200) {
          const breaches = Array.isArray(r.data) ? r.data : [];
          return { breached: true, count: breaches.length, breaches, source: 'haveibeenpwned' };
        }
        if (r.status === 401) throw Object.assign(new Error('HIBP API key invalid — check server HIBP_API_KEY'), { status: 500 });
        if (r.status === 429) throw Object.assign(new Error('HIBP rate limit — retry after a minute'), { status: 502 });
        throw Object.assign(new Error(`HIBP returned HTTP ${r.status}`), { status: 502 });
      }
      // Free fallback: XposedOrNot (no key needed)
      const r = await http.get(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, { timeout: 10000 });
      if (r.status === 200 && r.data) {
        const breaches = r.data.breaches || [];
        return {
          breached: breaches.length > 0,
          count: breaches.length,
          breaches: breaches.map((b) => (typeof b === 'string' ? { Name: b } : b)),
          source: 'xposedornot (free fallback — set HIBP_API_KEY for full HIBP data)',
        };
      }
      if (r.status === 404) return { breached: false, count: 0, breaches: [], source: 'xposedornot' };
      throw Object.assign(new Error('Breach lookup failed on all providers'), { status: 502 });
    });
    return ok(res, data, { cached, breached: data.breached, count: data.count });
  } catch (error) {
    if (error.status) return fail(res, error.status, error.message);
    // HIBP-style 404-in-axiosError means "not breached"
    if (error.response && error.response.status === 404) {
      return ok(res, { breached: false, count: 0, breaches: [] }, { breached: false, count: 0 });
    }
    return axiosError(res, error);
  }
});

module.exports = router;
