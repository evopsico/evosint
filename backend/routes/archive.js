const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidDomain, normalizeDomain, ok, fail } = require('../utils/validate');

// GET /api/archive/wayback/:domain?limit=20 — Wayback CDX snapshot list (free, no key)
router.get('/wayback/:domain', async (req, res) => {
  const raw = String(req.params.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Invalid domain');
  const domain = normalizeDomain(raw);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
  try {
    const { data, cached } = await getOrSet(`wb:${domain}:${limit}`, 86400, async () => {
      // Full wildcard query first (rich), exact-URL fallback (fast, always works).
      const full = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&limit=${limit}&collapse=urlkey&fl=timestamp,original,statuscode,mimetype&filter=statuscode:200`;
      try {
        const r = await http.get(full, { timeout: 28000 });
        if (r.status === 200 && Array.isArray(r.data) && r.data.length > 1) {
          const [, ...rows] = r.data;
          return { domain, snapshots: rows.map((row) => ({ timestamp: row[0], url: row[1], status: row[2], type: row[3], replay: `https://web.archive.org/web/${row[0]}id_/${row[1]}` })).slice(0, limit), source: 'cdx-wildcard' };
        }
      } catch { /* fall through */ }
      const r = await http.get(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=${limit}&fl=timestamp,original,statuscode&filter=statuscode:200`, { timeout: 20000 });
      if (r.status !== 200 || !Array.isArray(r.data)) throw Object.assign(new Error('Wayback CDX unreachable'), { status: 502 });
      const [, ...rows] = r.data;
      return { domain, snapshots: rows.map((row) => ({ timestamp: row[0], url: row[1], status: row[2], replay: `https://web.archive.org/web/${row[0]}id_/${row[1]}` })).slice(0, limit), source: 'cdx-exact' };
    });
    return ok(res, data.snapshots, { cached, source: `web.archive.org (${data.source})`, domain: data.domain, count: data.snapshots.length });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Wayback lookup failed'); }
});

// GET /api/archive/available?url= — closest archived snapshot (free)
router.get('/available', async (req, res) => {
  const url = String(req.query.url || '').trim();
  if (!/^https?:\/\/.+\..+/.test(url)) return fail(res, 400, 'Query ?url=https://… required');
  try {
    const r = await http.get(`https://archive.org/wayback/available?url=${encodeURIComponent(url)}`, { timeout: 12000 });
    const snap = r.data?.archived_snapshots?.closest;
    return ok(res, snap ? { available: true, ...snap } : { available: false, note: 'No snapshot found' }, { source: 'web.archive.org' });
  } catch (e) { return fail(res, 502, 'Availability check failed'); }
});

// GET /api/archive/urlscan?q=domain:example.com — urlscan.io search (free, no key)
router.get('/urlscan', async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (!q || q.length > 200) return fail(res, 400, 'Query ?q= required (e.g. domain:example.com)');
  try {
    const { data, cached } = await getOrSet(`urlscan:${q.toLowerCase()}`, 3600, async () => {
      const r = await http.get(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=20`, { timeout: 15000 });
      if (r.status !== 200) throw Object.assign(new Error('urlscan.io error'), { status: 502 });
      return (r.data?.results || []).map((x) => ({ scan: x.task?.url, page_url: x.page?.url, domain: x.page?.domain, ip: x.page?.ip, country: x.page?.country, time: x.task?.time, result: x.result }));
    });
    return ok(res, data, { cached, source: 'urlscan.io', count: data.length });
  } catch (e) { return fail(res, e.status || 502, e.message || 'urlscan search failed'); }
});

// POST /api/archive/meta { url } — page metadata / OG-tag extractor (SSRF-guarded)
router.post('/meta', async (req, res) => {
  let u;
  try {
    u = new URL(String(req.body?.url || ''));
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s)');
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.)/.test(u.hostname) || u.hostname === '::1') throw new Error('Private/internal targets blocked');
  } catch (e) { return fail(res, 400, `Invalid URL: ${e.message}`); }
  try {
    const r = await http.get(u.toString(), { timeout: 12000, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0' } });
    const html = typeof r.data === 'string' ? r.data.slice(0, 300000) : '';
    const pick = (re) => (html.match(re) || [])[1]?.trim().slice(0, 500) || null;
    const og = {};
    for (const m of html.matchAll(/<meta[^>]+property=["']og:([^"']+)["'][^>]+content=["']([^"']*)["']/gi)) og[m[1]] = m[2].slice(0, 500);
    return ok(res, {
      url: u.toString(), status: r.status,
      title: pick(/<title[^>]*>([^<]*)<\/title>/i),
      description: pick(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i),
      canonical: pick(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i),
      generator: r.headers?.['x-powered-by'] || pick(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*)["']/i),
      og, links_found: (html.match(/<a\s[^>]*href=/gi) || []).length,
    }, { source: 'page-meta' });
  } catch (e) { return fail(res, 502, `Fetch failed: ${e.message}`); }
});

module.exports = router;
