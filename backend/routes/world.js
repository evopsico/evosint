const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { ok, fail, oneLine } = require('../utils/validate');

// ---- World hub: the whole planet, keyless sources only ----
//   Open-Meteo (geo + weather, no key, generous) · GDELT DOC 2.1 (global news
//   wire, no key, 1 req / 5s per IP) · Feodo C2 blocklist + CISA KEV downloads.
// NOTE: the abuse.ch *APIs* (ThreatFox/URLhaus/MalwareBazaar) now return 401
// without an Auth-Key, so live-attack telemetry uses the keyless *downloads*.
// Every endpoint is cached; place/attacks cost 1 scan like any other card.

const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const WMO = {
  0: 'Clear sky', 1: 'Mainly clear', 2: 'Partly cloudy', 3: 'Overcast',
  45: 'Fog', 48: 'Icy fog', 51: 'Light drizzle', 53: 'Drizzle', 55: 'Heavy drizzle',
  56: 'Freezing drizzle', 57: 'Freezing drizzle', 61: 'Light rain', 63: 'Rain', 65: 'Heavy rain',
  66: 'Freezing rain', 67: 'Freezing rain', 71: 'Light snow', 73: 'Snow', 75: 'Heavy snow',
  77: 'Snow grains', 80: 'Light showers', 81: 'Showers', 82: 'Violent showers',
  85: 'Snow showers', 86: 'Snow showers', 95: 'Thunderstorm', 96: 'Storm + hail', 99: 'Storm + hail',
};
const wxLabel = (c) => WMO[c] || 'Unknown';

function decodeEnt(s) {
  return String(s || '')
    .replace(/&(amp|lt|gt|quot|#39|#x27);/g, (m, e) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#x27': "'" }[e] || m))
    .replace(/&#(\d+);/g, (_, n) => { try { return String.fromCharCode(Number(n)); } catch { return ''; } })
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => { try { return String.fromCharCode(parseInt(h, 16)); } catch { return ''; } });
}
const MON = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06', Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' };
function tagOf(block, tag) {
  const m = block.match(new RegExp('<' + tag + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + tag + '>'));
  return m ? decodeEnt(m[1]).trim() : '';
}
// Google News RSS: keyless, no throttle observed, fresh global headlines.
function parseRss(xml) {
  const items = [...String(xml || '').matchAll(/<item>([\s\S]*?)<\/item>/g)].slice(0, 40);
  return items.map((m) => {
    const link = tagOf(m[1], 'link'), title = tagOf(m[1], 'title');
    if (!link || !title) return null;
    const pd = tagOf(m[1], 'pubDate');
    const dm = pd.match(/(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})/);
    return {
      title: oneLine(title, 140), url: link.slice(0, 500),
      date: dm ? dm[3] + MON[dm[2]] + String(dm[1]).padStart(2, '0') : '',
      domain: oneLine(tagOf(m[1], 'source'), 60), image: null,
    };
  }).filter(Boolean).slice(0, 12);
}
const rssUrl = (q) => `https://news.google.com/rss/search?q=${encodeURIComponent(q)}&hl=en&gl=US&ceid=US:en`;
const gdeltUrl = (q) => `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&mode=artlist&maxrecords=12&format=json&sort=datedesc`;
function gdeltArticles(a) { /* GDELT fallback shape → same article shape */
  return (Array.isArray(a) ? a : [])
    .filter((x) => x && x.url && x.title)
    .slice(0, 12)
    .map((x) => ({
      title: oneLine(x.title, 140), url: String(x.url).slice(0, 500),
      date: (x.seendate || '').slice(0, 8), domain: oneLine(x.domain || '', 60),
      image: String(x.socialimage || '').slice(0, 500) || null,
    }));
}

// GET /api/world/geo?q=Berlin — place search (pick one → /place)
router.get('/geo', ah(async (req, res) => {
  const q = oneLine(req.query.q || '', 80).trim();
  if (q.length < 2) return fail(res, 400, '?q= needs 2+ characters (city, region, or country)');
  try {
    const { data, cached } = await getOrSet(`world:geo:${q.toLowerCase()}`, 86400, async () => {
      const r = await http.get(`https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(q)}&count=6&language=en&format=json`, { timeout: 12000 });
      if (r.status !== 200 || !Array.isArray(r.data?.results)) throw Object.assign(new Error('Geocoding unreachable'), { status: 502 });
      return r.data.results.map((g) => ({
        name: oneLine(g.name || q, 80), country: oneLine(g.country || '', 80), admin1: oneLine(g.admin1 || '', 80),
        lat: g.latitude, lon: g.longitude, cc: g.country_code || '', timezone: g.timezone || '',
      }));
    });
    return ok(res, data, { cached, source: 'open-meteo-geocoding' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Geocoding failed'); }
}));

// GET /api/world/reverse?lat=&lon= — coords → place name (BigDataCloud, no key)
router.get('/reverse', ah(async (req, res) => {
  const lat = Number(req.query.lat), lon = Number(req.query.lon);
  if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) return fail(res, 400, 'Valid ?lat= (-90..90) and ?lon= (-180..180) required');
  try {
    const { data, cached } = await getOrSet(`world:rev:${lat.toFixed(2)}:${lon.toFixed(2)}`, 2592000, async () => {
      const r = await http.get(`https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lon}&localityLanguage=en`, { timeout: 12000 });
      if (r.status !== 200 || typeof r.data !== 'object') throw Object.assign(new Error('Reverse-geocode unreachable'), { status: 502 });
      const d = r.data || {};
      const name = oneLine(d.city || d.locality || '', 80);
      const sub = oneLine(d.principalSubdivision || '', 80);
      const country = oneLine(d.countryName || '', 80);
      const ocean = !name && !sub && !country;
      return { ocean, name: ocean ? '' : (name || sub || country), sub: ocean ? '' : sub, country: ocean ? '' : country, cc: d.countryCode || '' };
    });
    return ok(res, data, { cached, source: 'bigdatacloud' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Reverse-geocode failed'); }
}));

// Shared place-bundle builder (weather everywhere; news wire needs a name).
async function buildPlace(lat, lon, name, country) {
  const quoted = /\s/.test(name) ? `"${name}"` : name;
  const newsQ = country ? `${quoted} ${country}` : quoted;
  const confQ = `${quoted} (war OR conflict OR airstrike OR missile OR bombing OR ceasefire OR troops OR offensive)`;
  const wxP = http.get(`https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current=temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m,wind_direction_10m,pressure_msl&daily=temperature_2m_max,temperature_2m_min,precipitation_probability_max,weather_code&timezone=auto&forecast_days=3`, { timeout: 12000 });
  let newsR = { status: 'rejected' }, confR = { status: 'rejected' };
  if (name) {
    const newsP = http.get(rssUrl(newsQ), { timeout: 15000 });
    const confP = http.get(rssUrl(confQ), { timeout: 15000 });
    [newsR, confR] = await Promise.allSettled([newsP, confP]);
  }
  const wx = await wxP.then((v) => ({ status: 'fulfilled', value: v }), (e) => ({ status: 'rejected', reason: e }));
  let news = [], newsSrc = name ? 'failed' : 'skipped', conflict = [], confSrc = name ? 'failed' : 'skipped';
  if (newsR.status === 'fulfilled' && newsR.value.status === 200) { news = parseRss(newsR.value.data); if (news.length) newsSrc = 'gnews-rss'; }
  if (confR.status === 'fulfilled' && confR.value.status === 200) { conflict = parseRss(confR.value.data); if (conflict.length) confSrc = 'gnews-rss'; }
  // Fallback lane: GDELT (throttled to ~1 req / 5s per IP — serialized, news first).
  async function gdelt(q) {
    try {
      const r = await http.get(gdeltUrl(q), { timeout: 15000 });
      if (r.status === 200 && Array.isArray(r.data?.articles)) return gdeltArticles(r.data.articles);
    } catch {}
    return [];
  }
  if (name && !news.length) { news = await gdelt(newsQ); if (news.length) newsSrc = 'gdelt'; await new Promise((r) => setTimeout(r, 6000)); }
  if (name && !conflict.length) { conflict = await gdelt(confQ); if (conflict.length) confSrc = 'gdelt'; }
  const out = { place: { name: name || `Open ocean ${lat.toFixed(1)}, ${lon.toFixed(1)}`, country, lat, lon }, weather: null, news, conflict, sources: { news: newsSrc, conflict: confSrc } };
  if (wx.status === 'fulfilled' && wx.value.status === 200 && wx.value.data?.current) {
    const c = wx.value.data.current, d = wx.value.data.daily || {};
    out.weather = {
      temp: c.temperature_2m, feels: c.apparent_temperature, humidity: c.relative_humidity_2m,
      wind: c.wind_speed_10m, wind_dir: c.wind_direction_10m, pressure: c.pressure_msl,
      code: c.weather_code, label: wxLabel(c.weather_code), units: wx.value.data.current_units || {},
      timezone: wx.value.data.timezone || '', utc_offset_seconds: wx.value.data.utc_offset_seconds ?? 0,
      server_now_ms: Date.now(),
      daily: (d.time || []).slice(0, 3).map((t, i) => ({
        date: t, tmax: d.temperature_2m_max?.[i] ?? null, tmin: d.temperature_2m_min?.[i] ?? null,
        code: d.weather_code?.[i], label: wxLabel(d.weather_code?.[i]), precip: d.precipitation_probability_max?.[i] ?? null,
      })),
    };
    out.sources.weather = 'ok';
  } else out.sources.weather = 'failed';
  if (!out.weather && !out.news.length && !out.conflict.length) throw Object.assign(new Error('All world sources unreachable'), { status: 502 });
  return out;
}

// GET /api/world/place?lat=&lon=&name=[&country=] — weather + clock + local news + conflict wire
router.get('/place', ah(async (req, res) => {
  const lat = Number(req.query.lat), lon = Number(req.query.lon);
  const name = oneLine(req.query.name || '', 80).trim();
  const country = oneLine(req.query.country || '', 80).trim();
  if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) return fail(res, 400, 'Valid ?lat= (-90..90) and ?lon= (-180..180) required');
  if (name.length < 2) return fail(res, 400, '?name= (from /geo) required for the news wire');
  try {
    const key = `world:place:${lat.toFixed(2)}:${lon.toFixed(2)}:${name.toLowerCase()}:${country.toLowerCase()}`;
    const { data, cached } = await getOrSet(key, 1800, () => buildPlace(lat, lon, name, country));
    return ok(res, data, { cached, source: 'open-meteo + gnews-rss (+gdelt fallback)' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'World lookup failed'); }
}));

// GET /api/world/pick?lat=&lon= — globe tap → reverse-geocode + full bundle in ONE scan
router.get('/pick', ah(async (req, res) => {
  const lat = Number(req.query.lat), lon = Number(req.query.lon);
  if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) return fail(res, 400, 'Valid ?lat= (-90..90) and ?lon= (-180..180) required');
  const la = Math.round(lat * 100) / 100, lo = Math.round(lon * 100) / 100;
  try {
    const { data, cached } = await getOrSet(`world:pick:${la.toFixed(2)}:${lo.toFixed(2)}`, 1800, async () => {
      let rev = { ocean: true, name: '', sub: '', country: '' };
      try {
        const r = await http.get(`https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${la}&longitude=${lo}&localityLanguage=en`, { timeout: 12000 });
        if (r.status === 200 && typeof r.data === 'object') {
          const d = r.data || {};
          const name = oneLine(d.city || d.locality || '', 80);
          const sub = oneLine(d.principalSubdivision || '', 80);
          const country = oneLine(d.countryName || '', 80);
          rev = { ocean: !name && !sub && !country, name: name || sub || country, sub, country };
        }
      } catch {}
      const bundle = await buildPlace(la, lo, rev.ocean ? '' : rev.name, rev.ocean ? '' : rev.country);
      return { ...bundle, tapped: { lat: la, lon: lo }, ocean: rev.ocean, resolved: rev.ocean ? null : { name: rev.name, sub: rev.sub, country: rev.country } };
    });
    return ok(res, data, { cached, source: 'bigdatacloud + open-meteo + gnews-rss' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Globe pick failed'); }
}));

// GET /api/world/attacks — live botnet C2s (Feodo) + freshly-exploited CVEs (KEV)
router.get('/attacks', ah(async (req, res) => {
  try {
    const { data, cached } = await getOrSet('world:attacks', 900, async () => {
      const [feodo, kev] = await Promise.allSettled([
        http.get('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { timeout: 15000 }),
        http.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 20000 }),
      ]);
      const c2 = (feodo.status === 'fulfilled' && feodo.value.status === 200 && Array.isArray(feodo.value.data) ? feodo.value.data : [])
        .slice(0, 25).map((d) => ({ ip: d.ip_address, malware: d.malware || '?', first_seen: d.first_seen_utc || null, last_online: d.last_online || null }));
      const vulns = (kev.status === 'fulfilled' && kev.value.status === 200 && Array.isArray(kev.value.data?.vulnerabilities) ? kev.value.data.vulnerabilities : [])
        .slice().sort((a, b) => String(b.dateAdded || '').localeCompare(String(a.dateAdded || ''))).slice(0, 15)
        .map((v) => ({ cve: v.cveID, vendor: v.vendorProject, product: v.product, name: (v.vulnerabilityName || '').slice(0, 120), date_added: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === 'Known' }));
      if (!c2.length && !vulns.length) throw Object.assign(new Error('Attack feeds unreachable'), { status: 502 });
      const fam = {};
      c2.forEach((d) => { fam[d.malware] = (fam[d.malware] || 0) + 1; });
      const families = Object.entries(fam).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name, count }));
      const max = families.length ? families[0].count : 1;
      return {
        window: 'live pull', c2_count: c2.length,
        families: families.map((f) => ({ ...f, share: Math.round((f.count / max) * 100) })),
        c2, kev_fresh: vulns,
        sources: { feodo: c2.length ? 'ok' : 'failed', kev: vulns.length ? 'ok' : 'failed' },
      };
    });
    return ok(res, data, { cached, source: 'feodo + cisa-kev' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Attack feed failed'); }
}));

module.exports = router;
