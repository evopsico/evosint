const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidIP, ok, fail } = require('../utils/validate');

// BGP / routing hub via RIPEstat (free, keyless, reliable).

const RIPE = 'https://stat.ripe.net/data';

// GET /api/bgp/asn/:asn — announced prefixes + registry info
router.get('/asn/:asn', async (req, res) => {
  const asn = String(req.params.asn || '').trim().replace(/^as/i, '');
  if (!/^\d{1,10}$/.test(asn)) return fail(res, 400, 'ASN required (e.g. 15169 or AS15169)');
  try {
    const { data, cached } = await getOrSet(`asn:${asn}`, 86400, async () => {
      const [pfx, whois] = await Promise.all([
        http.get(`${RIPE}/announced-prefixes/data.json?resource=AS${asn}`, { timeout: 15000 }),
        http.get(`${RIPE}/whois/data.json?resource=AS${asn}`, { timeout: 15000 }),
      ]);
      if (pfx.data?.status !== 'ok') throw Object.assign(new Error('ASN not found'), { status: 404 });
      const prefixes = (pfx.data?.data?.prefixes || []).map((p) => ({ prefix: p.prefix, timelines: p.timelines }));
      const records = whois.data?.data?.records || [];
      const descr = records.flatMap((r) => r.filter((x) => x.key === 'descr' || x.key === 'org-name').map((x) => x.value)).slice(0, 3);
      return { asn: Number(asn), description: descr, prefix_count: prefixes.length, prefixes: prefixes.slice(0, 100), whois_records: records.length };
    });
    return ok(res, data, { cached, source: 'ripe-stat' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'ASN lookup failed'); }
});

// NOTE: prefix contains a slash, so a regex route is used (Express won't match :param across /).
// GET /api/bgp/prefix/8.8.8.0/24
router.get(/^\/prefix\/(.+)$/, async (req, res) => {
  const cidr = String(req.params[0] || '').trim();
  if (!/^[\d.:a-fA-F]+\/\d{1,3}$/.test(cidr)) return fail(res, 400, 'CIDR required (e.g. 8.8.8.0/24)');
  try {
    const { data, cached } = await getOrSet(`pfx:${cidr}`, 86400, async () => {
      const [info, whois] = await Promise.all([
        http.get(`${RIPE}/network-info/data.json?resource=${encodeURIComponent(cidr)}`, { timeout: 15000 }),
        http.get(`${RIPE}/whois/data.json?resource=${encodeURIComponent(cidr)}`, { timeout: 15000 }),
      ]);
      if (info.data?.status !== 'ok') throw Object.assign(new Error('Prefix not found'), { status: 404 });
      return { prefix: cidr, asns: info.data?.data?.asns || [], ...info.data?.data, whois_records: (whois.data?.data?.records || []).length };
    });
    return ok(res, data, { cached, source: 'ripe-stat' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Prefix lookup failed'); }
});

// GET /api/bgp/ip/:ip — announcing ASN + reverse DNS + registry
router.get('/ip/:ip', async (req, res) => {
  const ip = String(req.params.ip || '').trim();
  if (!isValidIP(ip)) return fail(res, 400, 'IP required');
  try {
    const { data, cached } = await getOrSet(`bgpip:${ip}`, 86400, async () => {
      const [info, ptr] = await Promise.all([
        http.get(`${RIPE}/network-info/data.json?resource=${encodeURIComponent(ip)}`, { timeout: 15000 }),
        http.get(`${RIPE}/reverse-dns-ip/data.json?resource=${encodeURIComponent(ip)}`, { timeout: 15000 }).catch(() => null),
      ]);
      if (info.data?.status !== 'ok') throw Object.assign(new Error('No BGP data for IP'), { status: 404 });
      return { ip, asns: info.data?.data?.asns || [], prefix: info.data?.data?.prefix || null, reverse_dns: ptr?.data?.data?.result || null };
    });
    return ok(res, data, { cached, source: 'ripe-stat' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'BGP IP lookup failed'); }
});

// GET /api/bgp/ptr/:ip — reverse DNS via DNS-over-HTTPS
router.get('/ptr/:ip', async (req, res) => {
  const ip = String(req.params.ip || '').trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return fail(res, 400, 'IPv4 required');
  try {
    const rev = `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
    const r = await http.get(`https://dns.google/resolve?name=${rev}&type=PTR`, { timeout: 8000 });
    const names = (r.data?.Answer || []).map((a) => a.data);
    return ok(res, { ip, ptr: names, found: names.length > 0 }, { source: 'dns.google' });
  } catch (e) { return fail(res, 502, 'PTR lookup failed'); }
});

module.exports = router;
