const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidIP, isValidDomain, normalizeDomain, ok, fail } = require('../utils/validate');

// ---- Threat Intel hub: all keyless, all cached ----

// POST /api/threat/ioc { value } — ThreatFox (abuse.ch, no key)
router.post('/ioc', async (req, res) => {
  const value = String(req.body?.value || '').trim();
  if (!value || value.length > 300) return fail(res, 400, 'Body { value } with an IP/domain/URL/hash required');
  try {
    const { data, cached } = await getOrSet(`threatfox:${value.toLowerCase()}`, 3600, async () => {
      const r = await http.post('https://threatfox-api.abuse.ch/api/v1/', { query: 'search_ioc', search_term: value }, { timeout: 12000 });
      if (r.status === 200 && r.data?.query_status === 'ok') {
        return { found: true, count: (r.data.data || []).length, iocs: r.data.data.slice(0, 20).map((d) => ({
          ioc: d.ioc, threat_type: d.threat_type, malware: d.malware_printable, confidence: d.confidence_level,
          first_seen: d.first_seen, last_seen: d.last_seen, reference: (d.reference || '').slice(0, 300),
        })) };
      }
      return { found: false, count: 0, iocs: [], note: 'Not in ThreatFox' };
    });
    return ok(res, data, { cached, source: 'threatfox' });
  } catch (e) { return fail(res, 502, 'ThreatFox lookup failed'); }
});

// GET /api/threat/host/:domain — URLhaus host reputation (no key)
router.get('/host/:domain', async (req, res) => {
  const raw = String(req.params.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Invalid domain');
  const domain = normalizeDomain(raw);
  try {
    const { data, cached } = await getOrSet(`urlhaus:${domain}`, 3600, async () => {
      const r = await http.post('https://urlhaus-api.abuse.ch/v1/host/', new URLSearchParams({ host: domain }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 12000 });
      if (r.status === 200 && r.data?.query_status === 'ok') {
        return { listed: true, url_count: r.data.url_count ?? (r.data.urls || []).length,
          firstseen: r.data.firstseen || null, urls: (r.data.urls || []).slice(0, 20).map((u) => ({ url: u.url, threat: u.threat, tags: u.tags, date: u.date_added })) };
      }
      return { listed: false, url_count: 0, urls: [], note: 'Not in URLhaus' };
    });
    return ok(res, data, { cached, source: 'urlhaus' });
  } catch (e) { return fail(res, 502, 'URLhaus lookup failed'); }
});

// GET /api/threat/feodo/:ip — Feodo (Emotet/Dridex/TrickBot C2) blocklist check
router.get('/feodo/:ip', async (req, res) => {
  const ip = String(req.params.ip || '').trim();
  if (!isValidIP(ip)) return fail(res, 400, 'IPv4/IPv6 required');
  try {
    const { data, cached } = await getOrSet('feodo:list', 21600, async () => {
      const r = await http.get('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { timeout: 15000 });
      if (r.status !== 200 || !Array.isArray(r.data)) throw Object.assign(new Error('Feodo feed unreachable'), { status: 502 });
      return r.data.map((d) => ({ ip: d.ip_address, malware: d.malware, first_seen: d.first_seen_utc, last_online: d.last_online }));
    });
    const hit = data.find((d) => d.ip === ip);
    return ok(res, hit ? { listed: true, ...hit } : { listed: false, note: 'Not in Feodo Tracker' }, { cached, source: 'feodotracker' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Feodo check failed'); }
});

// GET /api/threat/kev?q= — CISA Known Exploited Vulnerabilities search (free JSON catalog)
router.get('/kev', async (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  try {
    const { data, cached } = await getOrSet('kev:catalog', 86400, async () => {
      const r = await http.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 20000 });
      if (r.status !== 200 || !r.data?.vulnerabilities) throw Object.assign(new Error('KEV catalog unreachable'), { status: 502 });
      return r.data.vulnerabilities.map((v) => ({ cve: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, date_added: v.dateAdded, due_date: v.dueDate, ransomware: v.knownRansomwareCampaignUse, notes: (v.shortDescription || '').slice(0, 300) }));
    });
    const items = q ? data.filter((v) => `${v.cve} ${v.vendor} ${v.product} ${v.name}`.toLowerCase().includes(q)).slice(0, 30) : data.slice(0, 30);
    return ok(res, items, { cached, source: 'cisa-kev', total_catalog: data.length, shown: items.length });
  } catch (e) { return fail(res, e.status || 502, e.message || 'KEV lookup failed'); }
});

// GET /api/threat/ransomware?q= — ransomware-linked IOCs (ThreatFox tag) + CISA KEV ransomware-use CVEs.
// (ransomware.live sits behind bot protection; these two sources are keyless and verifiable.)
router.get('/ransomware', async (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  try {
    const { data, cached } = await getOrSet('rw:feed', 21600, async () => {
      const [tf, kev] = await Promise.all([
        http.post('https://threatfox-api.abuse.ch/api/v1/', { query: 'get_taginfo', tag: 'ransomware' }, { timeout: 15000 }).catch(() => null),
        http.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 20000 }).catch(() => null),
      ]);
      const iocs = (tf?.data?.query_status === 'ok' ? (tf.data.data || []) : []).slice(0, 50).map((d) => ({
        kind: 'ioc', ioc: d.ioc, malware: d.malware_printable, confidence: d.confidence_level,
        first_seen: d.first_seen, reference: (d.reference || '').slice(0, 200),
      }));
      const cves = ((kev?.data?.vulnerabilities) || []).filter((v) => v.knownRansomwareCampaignUse === 'Known').slice(0, 50).map((v) => ({
        kind: 'cve', cve: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, date_added: v.dateAdded,
      }));
      if (!iocs.length && !cves.length) throw Object.assign(new Error('Ransomware feeds unreachable'), { status: 502 });
      return [...iocs, ...cves];
    });
    const items = q ? data.filter((v) => JSON.stringify(v).toLowerCase().includes(q)).slice(0, 30) : data.slice(0, 30);
    return ok(res, items, { cached, source: 'threatfox-tag + cisa-kev', shown: items.length });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Ransomware search failed'); }
});

// GET /api/threat/internetdb/:ip — Shodan InternetDB (FREE, no key)
router.get('/internetdb/:ip', async (req, res) => {
  const ip = String(req.params.ip || '').trim();
  if (!isValidIP(ip)) return fail(res, 400, 'IP required');
  try {
    const { data, cached } = await getOrSet(`inetdb:${ip}`, 86400, async () => {
      const r = await http.get(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { timeout: 12000 });
      if (r.status === 404) return { found: false, note: 'No InternetDB record (host may be quiet or filtered)' };
      if (r.status !== 200) throw Object.assign(new Error('InternetDB error'), { status: 502 });
      return { found: true, ...r.data };
    });
    return ok(res, data, { cached, source: 'shodan-internetdb' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'InternetDB lookup failed'); }
});

// GET /api/threat/greynoise/:ip — GreyNoise community: scanner noise or real threat?
router.get('/greynoise/:ip', async (req, res) => {
  const ip = String(req.params.ip || '').trim();
  if (!isValidIP(ip)) return fail(res, 400, 'IPv4/IPv6 required');
  try {
    const { data, cached } = await getOrSet(`gn:${ip}`, 86400, async () => {
      const r = await http.get(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, { timeout: 12000 });
      if (r.status === 404) {
        const msg = r.data && r.data.message ? String(r.data.message) : '';
        return { observed: false, ip, note: msg || 'Not observed' };
      }
      if (r.status !== 200) { const e = new Error('GreyNoise error'); e.status = 502; throw e; }
      const d = r.data || {};
      return { observed: true, ip, noise: !!d.noise, riot: !!d.riot,
        classification: d.classification || null, name: d.name || null,
        link: d.link || null, last_seen: d.last_seen || null, message: d.message || null };
    });
    return ok(res, data, { cached, source: 'greynoise-community' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'GreyNoise lookup failed'); }
});

module.exports = router;
