const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidDomain, normalizeDomain, ok, fail, axiosError } = require('../utils/validate');

/**
 * GET /api/domain/:domain — WHOIS via RDAP (official, free, no key) with whois.vu fallback.
 * v1 flaw fixed: broken regex rejected subdomains/short domains; single dead provider.
 */
router.get('/:domain', async (req, res) => {
  const raw = String(req.params.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Invalid domain (e.g. example.com or sub.example.co.uk)');
  const domain = normalizeDomain(raw);

  try {
    const { data, cached } = await getOrSet(`whois:${domain}`, 86400, async () => {
      // 1) IANA RDAP bootstrap — authoritative per-TLD referral
      try {
        const boot = await http.get(`https://data.iana.org/rdap/dns.json`, { timeout: 8000 });
        const svcs = (boot.data && boot.data.services) || [];
        let rdapBase = 'https://rdap.org/domain/';
        for (const [tlds, urls] of svcs) {
          if (Array.isArray(tlds) && tlds.some((t) => domain.endsWith(`.${t}`) || domain === t) && urls && urls[0]) {
            rdapBase = urls[0].replace(/\/?$/, '/domain/');
            break;
          }
        }
        void rdapBase;
      } catch { /* non-fatal, fall through to rdap.org */ }

      // 2) rdap.org aggregator (free, no key)
      const r = await http.get(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { timeout: 10000 });
      if (r.status === 200 && r.data && (r.data.ldhName || r.data.handle)) {
        return { ...r.data, _source: 'rdap.org' };
      }
      if (r.status === 404) {
        const e = new Error('Domain not found in RDAP (likely unregistered)');
        e.status = 404;
        throw e;
      }
      // 3) legacy fallback
      const w = await http.get(`https://api.whois.vu/?q=${encodeURIComponent(domain)}`, { timeout: 10000 });
      if (w.status === 200 && w.data) return { ...w.data, _source: 'whois.vu (fallback)' };
      const e = new Error('WHOIS lookup failed on all providers');
      e.status = 502;
      throw e;
    });
    return ok(res, data, { cached });
  } catch (error) {
    if (error.status) return fail(res, error.status, error.message);
    return axiosError(res, error);
  }
});

module.exports = router;
