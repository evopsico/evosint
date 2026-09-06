const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { PLATFORMS, NOT_FOUND_MARKERS } = require('../utils/platforms');
const { isValidUsername, ok, fail } = require('../utils/validate');

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

async function probe(platform, username) {
  const target = platform.url(username);
  const profile = target;
  try {
    const r = await http.get(target, {
      timeout: 7000,
      headers: platform.kind === 'api'
        ? { 'User-Agent': 'Evosint/2.0', Accept: 'application/json, text/html;q=0.9, */*;q=0.8' }
        : { 'User-Agent': BROWSER_UA, Accept: 'text/html,application/xhtml+xml' },
    });
    const body = typeof r.data === 'string' ? r.data : (r.data ? JSON.stringify(r.data) : '');
    if (platform.found) {
      const found = !!platform.found(r, body);
      return { name: platform.name, domain: platform.domain, label: platform.label, found, status_code: r.status, url: profile, method: 'api' };
    }
    if (r.status === 404) return { name: platform.name, domain: platform.domain, label: platform.label, found: false, status_code: 404, url: profile, method: 'page' };
    if (r.status !== 200) return { name: platform.name, domain: platform.domain, label: platform.label, found: false, status_code: r.status, url: profile, method: 'page', note: 'inconclusive status' };
    const lower = body.toLowerCase().slice(0, 80000);
    const looksMissing = NOT_FOUND_MARKERS.some((m) => lower.includes(m));
    return {
      name: platform.name, domain: platform.domain, label: platform.label,
      found: !looksMissing, status_code: 200, url: profile, method: 'page',
      ...(looksMissing ? {} : { note: 'page probe — confirm manually' }),
    };
  } catch (e) {
    return { name: platform.name, domain: platform.domain, label: platform.label, found: false, status_code: e.response?.status ?? null, url: profile, method: platform.kind, error: String(e.message || e).slice(0, 200) };
  }
}

/** GET /api/username/catalog — module list (name/domain/label) for the Modules grid. */
router.get('/catalog/list', (req, res) => {
  return ok(res, PLATFORMS.map((p) => ({ name: p.name, domain: p.domain, label: p.label, kind: p.kind })), { count: PLATFORMS.length });
});

/** GET /api/username/:username — ~170 platforms, data-driven catalog. */
router.get('/:username', async (req, res) => {
  const username = String(req.params.username || '').trim();
  if (!isValidUsername(username)) return fail(res, 400, 'Invalid username (1–39 chars: letters, numbers, . _ -)');
  const only = String(req.query.label || '').toLowerCase();
  const list = only ? PLATFORMS.filter((p) => p.label.toLowerCase() === only) : PLATFORMS;
  if (only && !list.length) return fail(res, 400, 'Unknown label filter');
  try {
    const { data, cached } = await getOrSet(`username:${username.toLowerCase()}:${only || 'all'}`, 1800, async () => {
      const results = await Promise.all(list.map((p) => probe(p, username)));
      const found = results.filter((r) => r.found).length;
      return { results, summary: { total_platforms: results.length, found_count: found, not_found_count: results.length - found } };
    });
    return ok(res, data.results, { summary: data.summary, cached });
  } catch (e) {
    return fail(res, 500, e.message || 'Username check failed');
  }
});

module.exports = router;
