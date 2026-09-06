const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { ok, fail } = require('../utils/validate');

// Geo hub — all keyless.

// GET /api/geo/code?address= — Nominatim forward geocode (OSM, 1 req/s etiquette + cache)
router.get('/code', async (req, res) => {
  const address = String(req.query.address || '').trim();
  if (!address || address.length > 300) return fail(res, 400, 'Query ?address= required');
  try {
    const { data, cached } = await getOrSet(`geo:${address.toLowerCase()}`, 86400 * 7, async () => {
      const r = await http.get(`https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(address)}&format=json&limit=5&addressdetails=1`, {
        timeout: 12000, headers: { 'User-Agent': 'Evosint/2.0 (authorized-use)' },
      });
      if (r.status !== 200 || !Array.isArray(r.data)) throw Object.assign(new Error('Geocoder unreachable'), { status: 502 });
      return r.data.map((d) => ({ name: d.display_name, lat: d.lat, lon: d.lon, type: d.type, class: d.class, importance: d.importance, map: `https://www.openstreetmap.org/?mlat=${d.lat}&mlon=${d.lon}#map=14/${d.lat}/${d.lon}` }));
    });
    return ok(res, data, { cached, source: 'nominatim/osm', count: data.length });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Geocoding failed'); }
});

// GET /api/geo/reverse?lat=..&lon=.. — Nominatim reverse geocode
router.get('/reverse', async (req, res) => {
  const lat = Number(req.query.lat), lon = Number(req.query.lon);
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) {
    return fail(res, 400, 'Query ?lat=&lon= required (valid ranges)');
  }
  try {
    const { data, cached } = await getOrSet(`revgeo:${lat},${lon}`, 86400 * 7, async () => {
      const r = await http.get(`https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=json&addressdetails=1`, {
        timeout: 12000, headers: { 'User-Agent': 'Evosint/2.0 (authorized-use)' },
      });
      if (r.status !== 200) throw Object.assign(new Error('Reverse geocoder unreachable'), { status: 502 });
      return { name: r.data?.display_name || null, address: r.data?.address || {}, map: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=14/${lat}/${lon}` };
    });
    return ok(res, data, { cached, source: 'nominatim/osm' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Reverse geocoding failed'); }
});

// GET /api/geo/postal/:country/:code — zippopotam.us worldwide postal lookup
router.get('/postal/:country/:code', async (req, res) => {
  const country = String(req.params.country || '').toLowerCase();
  const code = String(req.params.code || '').trim();
  if (!/^[a-z]{2}$/.test(country) || !/^[\w\- ]{2,12}$/.test(code)) return fail(res, 400, 'Use /postal/:cc/:code (e.g. /postal/us/90210)');
  try {
    const { data, cached } = await getOrSet(`postal:${country}:${code}`, 86400 * 30, async () => {
      const r = await http.get(`https://api.zippopotam.us/${country}/${encodeURIComponent(code)}`, { timeout: 10000 });
      if (r.status === 404) throw Object.assign(new Error('Postal code not found'), { status: 404 });
      if (r.status !== 200) throw Object.assign(new Error('Postal lookup failed'), { status: 502 });
      return r.data;
    });
    return ok(res, data, { cached, source: 'zippopotam' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Postal lookup failed'); }
});

// GET /api/geo/uk/:postcode — postcodes.io UK lookup (constituency, NHS, crime area…)
router.get('/uk/:postcode', async (req, res) => {
  const pc = String(req.params.postcode || '').trim();
  if (!pc) return fail(res, 400, 'UK postcode required');
  try {
    const { data, cached } = await getOrSet(`ukpc:${pc.toLowerCase()}`, 86400 * 30, async () => {
      const r = await http.get(`https://api.postcodes.io/postcodes/${encodeURIComponent(pc)}`, { timeout: 10000 });
      if (r.status === 404) throw Object.assign(new Error('Postcode not found'), { status: 404 });
      if (r.status !== 200) throw Object.assign(new Error('Postcode lookup failed'), { status: 502 });
      return r.data?.result;
    });
    return ok(res, data, { cached, source: 'postcodes.io' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Postcode lookup failed'); }
});

module.exports = router;
