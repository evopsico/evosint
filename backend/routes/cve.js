const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { ok, fail } = require('../utils/validate');

/**
 * GET /api/cve/:software — NVD 2.0 (primary) with CIRCL + OSV fallbacks.
 * v1 flaw fixed: only used dead cve.circl.lu /api/search/ endpoint, unbounded payload.
 */
router.get('/:software', async (req, res) => {
  const q = String(req.params.software || '').trim();
  if (!q || q.length > 100) return fail(res, 400, 'Software name is required (max 100 chars)');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9 .+_:-]{0,99}$/.test(q)) return fail(res, 400, 'Invalid software query');

  try {
    const { data, cached } = await getOrSet(`cve:${q.toLowerCase()}`, 3600, async () => {
      // 1) NVD 2.0 — official, no key at low volume
      try {
        const r = await http.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(q)}&resultsPerPage=20`, {
          timeout: 12000, headers: { 'User-Agent': 'Evosint/2.0' },
        });
        if (r.status === 200 && r.data?.vulnerabilities) {
          const items = r.data.vulnerabilities.slice(0, 20).map((v) => {
            const c = v.cve || {};
            const metrics = c.metrics?.cvssMetricV31?.[0] || c.metrics?.cvssMetricV30?.[0] || c.metrics?.cvssMetricV2?.[0];
            return {
              id: c.id, published: c.published, lastModified: c.lastModified,
              descriptions: (c.descriptions || []).filter((d) => d.lang === 'en').slice(0, 2).map((d) => d.value),
              severity: metrics?.cvssData?.baseSeverity || metrics?.baseSeverity || 'UNKNOWN',
              score: metrics?.cvssData?.baseScore ?? metrics?.baseScore ?? null,
              references: (c.references || []).slice(0, 5).map((x) => x.url),
            };
          });
          return { source: 'nvd', totalResults: r.data.totalResults ?? items.length, items };
        }
      } catch { /* fall through */ }
      // 2) CIRCL (new path)
      try {
        const r = await http.get(`https://cve.circl.lu/api/cve/${encodeURIComponent(q.toUpperCase())}`, { timeout: 10000 });
        if (r.status === 200 && r.data) return { source: 'circl', totalResults: 1, items: [r.data].flat().slice(0, 20) };
      } catch { /* fall through */ }
      // 3) OSV — package-oriented, best-effort keyword echo
      const r = await http.post('https://api.osv.dev/v1/query', { package: { name: q } }, { timeout: 10000 });
      if (r.status === 200) return { source: 'osv', totalResults: (r.data?.vulns || []).length, items: (r.data?.vulns || []).slice(0, 20) };
      throw Object.assign(new Error('All CVE providers failed'), { status: 502 });
    });
    return ok(res, data.items, { source: data.source, totalResults: data.totalResults, cached });
  } catch (e) {
    if (e.status) return fail(res, e.status, e.message);
    return fail(res, 502, 'CVE lookup failed');
  }
});

module.exports = router;
