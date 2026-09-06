const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { ok, fail } = require('../utils/validate');

// Company lookup via Wikidata + Wikipedia (free, keyless) + logo shortcut.

// GET /api/company/:name — resolve + summary + identifiers
router.get('/:name', async (req, res) => {
  const name = String(req.params.name || '').trim();
  if (!name || name.length > 120) return fail(res, 400, 'Company name required');
  try {
    const { data, cached } = await getOrSet(`co:${name.toLowerCase()}`, 86400 * 7, async () => {
      const search = await http.get(`https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(name)}&language=en&format=json&limit=5&origin=*`, { timeout: 12000 });
      const cands = (search.data?.search || []).map((e) => ({ id: e.id, label: e.label, description: e.description || null }));
      if (!cands.length) return { found: false, candidates: [], note: 'No Wikidata entity matched' };
      const top = cands[0];
      const ent = await http.get(`https://www.wikidata.org/wiki/Special:EntityData/${top.id}.json`, { timeout: 12000 });
      const E = ent.data?.entities?.[top.id] || {};
      const claims = E.claims || {};
      const val = (p) => claims[p]?.[0]?.mainsnak?.datavalue?.value || null;
      const website = val('P856') || null;
      const inception = val('P571')?.time || null;
      const industryId = val('P452')?.id || null;
      let summary = null, wikiUrl = null;
      try {
        const sitelink = E.sitelinks?.enwiki?.title;
        if (sitelink) {
          wikiUrl = `https://en.wikipedia.org/wiki/${encodeURIComponent(sitelink.replace(/ /g, '_'))}`;
          const sum = await http.get(`https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(sitelink)}`, { timeout: 10000 });
          summary = sum.data?.extract?.slice(0, 1200) || null;
        }
      } catch { /* summary optional */ }
      const domainGuess = website ? website.replace(/^https?:\/\//, '').split('/')[0] : null;
      return {
        found: true, entity: top.id, label: E.labels?.en?.value || top.label, description: E.descriptions?.en?.value || top.description,
        inception, industry_entity: industryId, website, domain: domainGuess,
        logo: domainGuess ? `https://logo.clearbit.com/${domainGuess}` : null,
        wikipedia: wikiUrl, summary, candidates: cands.slice(1),
      };
    });
    return ok(res, data, { cached, source: 'wikidata+wikipedia' });
  } catch (e) { return fail(res, 502, 'Company lookup failed'); }
});

module.exports = router;
