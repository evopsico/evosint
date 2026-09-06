const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidDomain, normalizeDomain, ok, fail, clientError } = require('../utils/validate');

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV', 'PTR'];

/**
 * GET /api/dns/:domain[?type=A] — parallel DNS-over-HTTPS via dns.google.
 * v1 flaws fixed: sequential requests (slow), broken domain regex, only 6 types.
 */
router.get('/:domain', async (req, res) => {
  const raw = String(req.params.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Invalid domain');
  const domain = normalizeDomain(raw);
  const only = String(req.query.type || '').toUpperCase();
  const types = only ? (RECORD_TYPES.includes(only) ? [only] : null) : RECORD_TYPES;
  if (!types) return fail(res, 400, `Invalid type. Use one of: ${RECORD_TYPES.join(', ')}`);

  try {
    const { data, cached } = await getOrSet(`dns:${domain}:${types.join(',')}`, 600, async () => {
      const out = {};
      await Promise.all(types.map(async (type) => {
        try {
          const r = await http.get(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, { timeout: 6000 });
          out[type] = {
            status: r.data.Status,
            answer: r.data.Answer || [],
            authority: r.data.Authority || [],
            dnssec: r.data.AD === true,
          };
        } catch {
          out[type] = { status: null, answer: [], authority: [], dnssec: false, error: 'lookup failed' };
        }
      }));
      return out;
    });
    return ok(res, data, { cached, domain });
  } catch (error) {
    return fail(res, 500, clientError(error, 'DNS lookup failed'));
  }
});

module.exports = router;
