const express = require('express');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidEmail, ok, fail } = require('../utils/validate');

// BREACHER — multi-source breach lookup + unified Exposure Index (0-100).
// Sources: HIBP (key), XposedOrNot, HudsonRock infostealers, LeakCheck,
// EmailRep (key), HIBP pastes (key). Scored like an exposure meter:
//   Low <25 · Moderate 25-49 · High 50-74 · Critical ≥75.

// POST /api/breacher { email }
router.post('/', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return fail(res, 400, 'Body { email } with a valid address required');
  try {
    const { data, cached } = await getOrSet(`breacher:${email}`, 3600, async () => runBreacher(email));
    return ok(res, data, { cached });
  } catch (e) { return fail(res, 502, e.message || 'Breacher failed'); }
});

async function runBreacher(email) {
  const sources = {}; // name -> {status, ...}
  const settle = async (name, fn) => {
    try { sources[name] = { status: 'ok', ...(await fn()) }; }
    catch (e) { sources[name] = { status: e.status === 404 ? 'clean' : 'error', error: e.status === 404 ? undefined : String(e.message).slice(0, 160) }; }
  };

  await Promise.all([
    // 1) HaveIBeenPwned breaches (key required)
    settle('hibp', async () => {
      if (!process.env.HIBP_API_KEY) { const e = new Error('skipped — set HIBP_API_KEY'); e.status = 999; throw e; }
      const r = await http.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
        { headers: { 'hibp-api-key': process.env.HIBP_API_KEY }, timeout: 12000 });
      if (r.status === 404) return { breaches: [] };
      if (r.status !== 200) throw new Error(`HIBP HTTP ${r.status}`);
      return { breaches: (Array.isArray(r.data) ? r.data : []).map((b) => ({ name: b.Name, domain: b.Domain, date: b.BreachDate, pwn: b.PwnCount, verified: !!b.IsVerified, sensitive: !!b.IsSensitive, spam: !!b.IsSpamList, classes: b.DataClasses || [] })) };
    }),
    // 2) HIBP pastes (key required)
    settle('hibp_pastes', async () => {
      if (!process.env.HIBP_API_KEY) { const e = new Error('skipped — set HIBP_API_KEY'); e.status = 999; throw e; }
      const r = await http.get(`https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(email)}`,
        { headers: { 'hibp-api-key': process.env.HIBP_API_KEY }, timeout: 12000 });
      if (r.status === 404) return { pastes: [] };
      if (r.status !== 200) throw new Error(`HIBP HTTP ${r.status}`);
      return { pastes: (Array.isArray(r.data) ? r.data : []).map((p) => ({ source: p.Source, title: p.Title, date: p.Date, email_count: p.EmailCount })) };
    }),
    // 3) XposedOrNot (keyless)
    settle('xposedornot', async () => {
      const r = await http.get(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, { timeout: 12000 });
      if (r.status === 404) return { breaches: [] };
      const list = r.data?.breaches || [];
      return { breaches: list.map((b) => (typeof b === 'string' ? { name: b } : { name: b.breach || b.Name, date: b.breachDate, classes: b.xposed_data ? String(b.xposed_data).split(';') : [] })) };
    }),
    // 4) HudsonRock infostealers (keyless)
    settle('hudsonrock', async () => {
      const r = await http.get(`https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(email)}`, { timeout: 15000 });
      const stealers = r.data?.stealers || [];
      return { computers: stealers.length, total_user_services: r.data?.total_user_services ?? stealers.reduce((a, s) => a + (s.total_user_services || 0), 0),
        incidents: stealers.slice(0, 10).map((s) => ({ date: (s.date_compromised || '').slice(0, 10), os: s.operating_system || null, antiviruses: s.antiviruses || [], services: s.total_user_services ?? null })) };
    }),
    // 5) LeakCheck public (keyless, slow)
    settle('leakcheck', async () => {
      const r = await http.get(`https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`, { timeout: 25000 });
      if (!r.data?.success) throw new Error('LeakCheck error');
      return { found: r.data.found ?? 0, fields: r.data.fields || [], sources: (r.data.sources || []).slice(0, 60).map((s) => ({ name: s.name, date: s.date || null })) };
    }),
    // 6) EmailRep (key required — unauthenticated API is disabled)
    settle('emailrep', async () => {
      if (!process.env.EMAILREP_KEY) { const e = new Error('skipped — set EMAILREP_KEY'); e.status = 999; throw e; }
      const r = await http.get(`https://emailrep.io/${encodeURIComponent(email)}`, { headers: { Key: process.env.EMAILREP_KEY }, timeout: 12000 });
      if (r.status !== 200 || r.data?.status === 'fail') throw new Error(r.data?.reason || 'EmailRep error');
      return { reputation: r.data.reputation, suspicious: !!r.data.suspicious, credentials_leaked: !!r.data.details?.credentials_leaked, data_breach: !!r.data.details?.data_breach, last_seen: r.data.details?.last_seen || null, profiles: r.data.details?.profiles || [] };
    }),
    // 7) ProxyNova ComB (keyless combo-dump search - passwords masked, never stored raw)
    settle('proxynova', async () => {
      const r = await http.get('https://api.proxynova.com/comb?query=' + encodeURIComponent(email), { timeout: 15000 });
      if (typeof r.data?.count !== 'number') throw new Error('ProxyNova error');
      const masked = (r.data.lines || []).slice(0, 10).map((line) => {
        const s2 = String(line), i = s2.indexOf(':');
        return i > 0 ? s2.slice(0, i) + ':PW(' + s2.slice(i + 1).length + ')' : 'PW(?)';
      });
      return { count: r.data.count, masked_sample: masked };
    }),
  ]);

  for (const [k, v] of Object.entries(sources)) if (v.error && v.error.startsWith('skipped')) v.status = 'skipped';

  // ---- unify breaches across HIBP / XON / LeakCheck ----
  const seen = new Map(); // norm name -> {name, dates:Set, sources:Set, ...extra}
  const add = (name, date, source, extra = {}) => {
    if (!name) return;
    const key = String(name).toLowerCase().replace(/[\s_.-]+/g, '');
    if (!seen.has(key)) seen.set(key, { name: String(name), dates: new Set(), sources: new Set(), ...extra });
    const e = seen.get(key);
    if (date) e.dates.add(String(date).slice(0, 10));
    e.sources.add(source);
    Object.assign(e, extra);
  };
  (sources.hibp?.breaches || []).forEach((b) => add(b.name, b.date, 'HIBP', { verified: b.verified, sensitive: b.sensitive, pwn: b.pwn }));
  (sources.xposedornot?.breaches || []).forEach((b) => add(b.name, b.date, 'XposedOrNot'));
  (sources.leakcheck?.sources || []).forEach((s) => add(s.name, s.date, 'LeakCheck'));
  const unified = [...seen.values()].map((e) => ({ name: e.name, dates: [...e.dates].sort(), sources: [...e.sources], ...(e.verified !== undefined ? { verified: e.verified, sensitive: e.sensitive } : {}) }))
    .sort((a, b) => (b.sources.length - a.sources.length) || (b.dates[0] || '').localeCompare(a.dates[0] || ''));

  const classes = new Set();
  (sources.hibp?.breaches || []).forEach((b) => (b.classes || []).forEach((c) => classes.add(c)));
  (sources.xposedornot?.breaches || []).forEach((b) => (b.classes || []).forEach((c) => classes.add(c)));
  (sources.leakcheck?.fields || []).forEach((c) => classes.add(c));

  // ---- exposure index ----
  let score = 5;
  const hb = sources.hibp?.breaches || [];
  score += Math.min(35, hb.length * 10);
  score += Math.min(9, hb.filter((b) => b.date && b.date > '2024-01-01').length * 3);
  score += Math.min(10, hb.filter((b) => b.sensitive).length * 5);
  score += Math.min(20, (sources.leakcheck?.sources || []).length * 2);
  score += Math.min(15, (sources.xposedornot?.breaches || []).length * 4);
  const stealers = sources.hudsonrock?.computers || 0;
  score += Math.min(50, stealers * 25);
  if ((sources.leakcheck?.fields || []).map(String).includes('password')) score += 10;
  if (sources.emailrep?.credentials_leaked) score += 12;
  const combCount = sources.proxynova?.count || 0;
  if (combCount > 0) score += 15;
  if (sources.emailrep?.suspicious) score += 6;
  score += Math.min(16, (sources.hibp_pastes?.pastes || []).length * 8);
  score = Math.max(2, Math.min(99, Math.round(score)));

  const band = score >= 75 ? 'Critical risk' : score >= 50 ? 'High exposure' : score >= 25 ? 'Moderate exposure' : 'Low exposure';
  const factors = [];
  if (hb.length) factors.push(`${hb.length} HIBP breach${hb.length > 1 ? 'es' : ''}`);
  if ((sources.leakcheck?.sources || []).length) factors.push(`${sources.leakcheck.sources.length} LeakCheck sources`);
  if (stealers) factors.push(`${stealers} infostealer-infected computer${stealers > 1 ? 's' : ''} (HudsonRock)`);
  if ((sources.hibp_pastes?.pastes || []).length) factors.push(`${sources.hibp_pastes.pastes.length} paste exposure${sources.hibp_pastes.pastes.length > 1 ? 's' : ''}`);
  if (sources.emailrep?.credentials_leaked) factors.push('credentials seen in the wild (EmailRep)');
  if (combCount > 0) factors.push(combCount.toLocaleString() + ' combo records (ProxyNova)');
  if (!factors.length) factors.push('no breach traces across queried sources');

  return {
    email, score, band,
    unique_breaches: unified.length,
    breaches: unified.slice(0, 80),
    data_classes: [...classes].slice(0, 40),
    stealers: { computers: stealers, services: sources.hudsonrock?.total_user_services ?? 0, incidents: sources.hudsonrock?.incidents || [] },
    pastes: sources.hibp_pastes?.pastes || [],
    factors,
    coverage: Object.fromEntries(Object.entries(sources).map(([k, v]) => [k, v.status])),
    sources: {
      hibp: sources.hibp?.status === 'ok' ? { breaches: sources.hibp.breaches } : { status: sources.hibp?.status, error: sources.hibp?.error },
      leakcheck: sources.leakcheck?.status === 'ok' ? { found: sources.leakcheck.found, fields: sources.leakcheck.fields } : { status: sources.leakcheck?.status, error: sources.leakcheck?.error },
      xposedornot: sources.xposedornot?.status === 'ok' ? { count: (sources.xposedornot.breaches || []).length } : { status: sources.xposedornot?.status },
      hudsonrock: sources.hudsonrock?.status === 'ok' ? { computers: stealers } : { status: sources.hudsonrock?.status },
      comb: sources.proxynova?.status === 'ok' ? { count: combCount, sample: sources.proxynova.masked_sample } : { status: sources.proxynova?.status },
      emailrep: sources.emailrep?.status === 'ok' ? { reputation: sources.emailrep.reputation, suspicious: sources.emailrep.suspicious } : { status: sources.emailrep?.status },
    },
    checked_at: new Date().toISOString(),
  };
}

module.exports = router;
