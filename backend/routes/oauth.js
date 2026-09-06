const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidDomain, normalizeDomain, ok, fail } = require('../utils/validate');

// OathNet: OAuth / OIDC / SAML analysis + secret-scan. All keyless, SSRF-guarded.

function hostBlocked(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h || h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (['169.254.169.254', 'metadata.google.internal', 'metadata.google'].includes(h)) return true;
  if (/^(127\.|10\.|0\.)/.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^169\.254\./.test(h)) return true;
  return h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:');
}
function safeHttpUrl(input) {
  const u = new URL(String(input || ''));
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s) URLs allowed');
  if (hostBlocked(u.hostname)) throw new Error('Private/internal targets blocked');
  if (u.username || u.password) throw new Error('Credentials in URL are not allowed');
  return u;
}

// GET /api/oauth/discover/:domain — probe well-known OAuth/OIDC endpoints + security flags
router.get('/discover/:domain', async (req, res) => {
  const raw = String(req.params.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Invalid domain');
  const domain = normalizeDomain(raw);
  const paths = [
    '/.well-known/openid-configuration', '/.well-known/oauth-authorization-server',
    '/.well-known/jwks.json', '/jwks.json', '/oauth/jwks', '/oauth/authorize', '/oauth/token',
    '/oauth/userinfo', '/authorize', '/token', '/userinfo', '/oauth2/authorize',
    '/login/oauth/authorize', '/oauth2/token', '/connect/authorize', '/connect/token',
  ];
  try {
    const { data, cached } = await getOrSet(`oauth:${domain}`, 86400, async () => {
      const base = `https://${domain}`;
      const results = await Promise.all(paths.map(async (p) => {
        try {
          const r = await http.get(base + p, { timeout: 8000, maxRedirects: 2 });
          const ct = String(r.headers?.['content-type'] || '');
          const body = typeof r.data === 'string' ? r.data : JSON.stringify(r.data || '');
          return { path: p, url: base + p, status: r.status, content_type: ct.split(';')[0] || null,
            looks_json: ct.includes('json') || body.trim().startsWith('{'), size: body.length,
            ...(r.status === 200 && ct.includes('json') ? { keys: Object.keys(r.data || {}).slice(0, 20) } : {}) };
        } catch (e) { return { path: p, url: base + p, status: null, error: String(e.message).slice(0, 120) }; }
      }));
      const live = results.filter((r) => r.status && r.status < 500);
      const oidc = results.find((r) => r.path === '/.well-known/openid-configuration' && r.status === 200);
      return { domain, openid_discovery: !!oidc, live_count: live.length, endpoints: results,
        note: oidc ? 'OIDC discovery live — run OIDC Config for full analysis' : 'No OIDC discovery document; listed live paths may still be OAuth endpoints' };
    });
    return ok(res, data, { cached, source: 'oathnet-probe' });
  } catch (e) { return fail(res, 502, e.message || 'Discovery failed'); }
});

// GET /api/oauth/oidc?url=https://accounts.google.com — full discovery-document security analysis
router.get('/oidc', async (req, res) => {
  let docUrl;
  try {
    const input = String(req.query.url || '').trim();
    docUrl = /\.well-known\//.test(input) ? safeHttpUrl(input) : safeHttpUrl(input.replace(/\/$/, '') + '/.well-known/openid-configuration');
  } catch (e) { return fail(res, 400, `Invalid URL: ${e.message}`); }
  try {
    const { data, cached } = await getOrSet(`oidc:${docUrl}`, 86400, async () => {
      const r = await http.get(docUrl.toString(), { timeout: 12000 });
      if (r.status !== 200 || typeof r.data !== 'object') throw Object.assign(new Error('No OIDC discovery document at that URL'), { status: 404 });
      const d = r.data;
      const findings = [];
      const algs = d.id_token_signing_alg_values_supported || [];
      if (algs.map(String).includes('none')) findings.push({ level: 'critical', msg: 'id_token alg "none" advertised — unsigned tokens accepted by misconfigured clients' });
      if (algs.map(String).includes('HS256')) findings.push({ level: 'info', msg: 'HS256 supported — watch for key-confusion where RS256 is expected' });
      if (!d.jwks_uri) findings.push({ level: 'warn', msg: 'No jwks_uri — clients cannot rotate/verify keys properly' });
      if (d.registration_endpoint) findings.push({ level: 'warn', msg: `Open dynamic client registration: ${d.registration_endpoint}` });
      if (!d.scopes_supported) findings.push({ level: 'info', msg: 'No scopes_supported advertised' });
      if (Array.isArray(d.response_types_supported) && d.response_types_supported.some((t) => String(t).includes('token'))) findings.push({ level: 'warn', msg: 'Implicit flow (token in fragment) still enabled — legacy, leak-prone' });
      if (!d.claims_supported) findings.push({ level: 'info', msg: 'No claims_supported advertised' });
      let jwks = null;
      if (d.jwks_uri) {
        try {
          const j = await http.get(d.jwks_uri, { timeout: 10000 });
          if (j.status === 200 && Array.isArray(j.data?.keys)) jwks = { count: j.data.keys.length, kids: j.data.keys.map((k) => k.kid || null).slice(0, 10) };
        } catch { /* optional */ }
      }
      return {
        issuer: d.issuer || null, issuer_matches_host: d.issuer ? String(d.issuer).includes(docUrl.hostname) : null,
        authorization_endpoint: d.authorization_endpoint || null, token_endpoint: d.token_endpoint || null,
        userinfo_endpoint: d.userinfo_endpoint || null, jwks_uri: d.jwks_uri || null,
        registration_endpoint: d.registration_endpoint || null, scopes: d.scopes_supported || null,
        response_types: d.response_types_supported || null, signing_algs: algs, claims: (d.claims_supported || []).slice(0, 30),
        jwks, findings,
      };
    });
    return ok(res, data, { cached, source: 'oidc-discovery' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'OIDC analysis failed'); }
});

// GET /api/oauth/jwks?url=https://…/jwks.json — key analysis (sizes, algs, exposed symmetric keys)
router.get('/jwks', async (req, res) => {
  let u;
  try { u = safeHttpUrl(String(req.query.url || '').trim()); }
  catch (e) { return fail(res, 400, `Invalid URL: ${e.message}`); }
  try {
    const { data, cached } = await getOrSet(`jwks:${u}`, 86400, async () => {
      const r = await http.get(u.toString(), { timeout: 12000 });
      const keys = r.data?.keys;
      if (r.status !== 200 || !Array.isArray(keys)) throw Object.assign(new Error('No JWKS document (expected {keys:[…]})'), { status: 404 });
      const findings = [];
      const analyzed = keys.slice(0, 25).map((k) => {
        const out = { kid: k.kid || null, kty: k.kty || null, use: k.use || null, alg: k.alg || null };
        if (k.kty === 'RSA' && k.n) {
          try {
            const bits = Buffer.from(k.n.replace(/-/g, '+').replace(/_/g, '/'), 'base64').length * 8;
            out.bits = bits;
            if (bits < 2048) findings.push({ level: 'critical', msg: `RSA key ${k.kid || ''} only ${bits} bits — factorable, must be ≥2048` });
          } catch { out.bits = null; }
        }
        if (k.kty === 'oct') findings.push({ level: 'critical', msg: `Symmetric key ${k.kid || ''} published in a PUBLIC JWKS — anyone can forge tokens` });
        if (k.kty === 'EC' && k.crv) out.crv = k.crv;
        if (Array.isArray(k.x5c) && k.x5c[0]) {
          try {
            const der = Buffer.from(k.x5c[0], 'base64');
            out.cert_sha256 = crypto.createHash('sha256').update(der).digest('hex').slice(0, 32) + '…';
            const txt = der.toString('latin1');
            const times = [...txt.matchAll(/(\d{12}Z)/g)].map((m) => m[1]).slice(0, 4);
            if (times.length >= 2) out.cert_validity_utc = { not_before: times[0], not_after: times[1] };
          } catch { /* fingerprint optional */ }
        }
        return out;
      });
      const algs = [...new Set(keys.map((k) => k.alg).filter(Boolean))];
      if (algs.map(String).includes('none')) findings.push({ level: 'critical', msg: 'A key advertises alg "none"' });
      return { url: u.toString(), key_count: keys.length, truncated: keys.length > 25, algs, keys: analyzed, findings: findings.length ? findings : [{ level: 'ok', msg: 'No key hygiene issues spotted' }] };
    });
    return ok(res, data, { cached, source: 'jwks' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'JWKS analysis failed'); }
});

// GET /api/oauth/saml?url=https://…/metadata — SAML metadata parse (endpoints, certs, flags)
router.get('/saml', async (req, res) => {
  let u;
  try { u = safeHttpUrl(String(req.query.url || '').trim()); }
  catch (e) { return fail(res, 400, `Invalid URL: ${e.message}`); }
  try {
    const { data, cached } = await getOrSet(`saml:${u}`, 86400, async () => {
      const r = await http.get(u.toString(), { timeout: 12000 });
      const xml = typeof r.data === 'string' ? r.data : '';
      if (r.status !== 200 || !/<EntityDescriptor/i.test(xml)) throw Object.assign(new Error('No SAML metadata (expected EntityDescriptor XML)'), { status: 404 });
      const one = (re) => (xml.match(re) || [])[1]?.trim() || null;
      const all = (re) => [...xml.matchAll(new RegExp(re, 'gi'))].map((m) => m[1]?.trim()).filter(Boolean);
      const entityID = one(/entityID=["']([^"']+)["']/i);
      const sso = [...xml.matchAll(/<[^>]*SingleSignOnService[^>]*Binding=["']([^"']+)["'][^>]*Location=["']([^"']+)["']/gi)].map((m) => ({ binding: m[1].split('/').pop(), location: m[2] }));
      if (!sso.length) [...xml.matchAll(/<[^>]*SingleSignOnService[^>]*Location=["']([^"']+)["'][^>]*Binding=["']([^"']+)["']/gi)].forEach((m) => sso.push({ binding: m[2].split('/').pop(), location: m[1] }));
      const slo = all('<[^>]*SingleLogoutService[^>]*Location=["\']([^"\']+)["\']');
      const certs = all('<[^>]*X509Certificate[^>]*>([^<]+)<');
      const findings = [];
      if (/AuthnRequestsSigned=["']false["']/i.test(xml)) findings.push({ level: 'warn', msg: 'AuthnRequestsSigned="false" — unsigned requests accepted' });
      if (/WantAssertionsSigned=["']false["']/i.test(xml)) findings.push({ level: 'warn', msg: 'WantAssertionsSigned="false" — assertion forgery risk' });
      const nameIDs = all('<[^>]*NameIDFormat[^>]*>([^<]+)<').map((s) => s.split('/').pop());
      const certInfo = certs.slice(0, 5).map((b64) => {
        try {
          const der = Buffer.from(b64.replace(/\s/g, ''), 'base64');
          const fp = crypto.createHash('sha256').update(der).digest('hex').slice(0, 32) + '…';
          const times = [...der.toString('latin1').matchAll(/(\d{12}Z)/g)].map((m) => m[1]);
          const info = { sha256: fp };
          if (times.length >= 2) {
            const toDate = (t) => `20${t.slice(0, 2)}-${t.slice(2, 4)}-${t.slice(4, 6)}`;
            info.not_before = toDate(times[0]); info.not_after = toDate(times[times.length - 1]);
            if (new Date(info.not_after) < new Date()) findings.push({ level: 'critical', msg: `Embedded cert expired ${info.not_after}` });
            else if (new Date(info.not_after) - Date.now() < 30 * 864e5) findings.push({ level: 'warn', msg: `Embedded cert expires soon (${info.not_after})` });
          }
          return info;
        } catch { return { sha256: null }; }
      });
      if (!certs.length) findings.push({ level: 'warn', msg: 'No signing certificates embedded' });
      return { url: u.toString(), entityID, role: /IDPSSODescriptor/i.test(xml) ? 'IdP' : /SPSSODescriptor/i.test(xml) ? 'SP' : 'unknown',
        sso_endpoints: sso, slo_endpoints: slo.slice(0, 5), nameid_formats: nameIDs.slice(0, 8),
        certs: certInfo, findings: findings.length ? findings : [{ level: 'ok', msg: 'No SAML misconfigurations spotted' }] };
    });
    return ok(res, data, { cached, source: 'saml-metadata' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'SAML analysis failed'); }
});

// POST /api/oauth/secretscan { url } — exposed-secret sweep: HTML + same-origin JS, redacted findings
const SECRET_PATTERNS = [
  ['AWS access key', /AKIA[0-9A-Z]{16}/g],
  ['GitHub token', /gh[pousr]_[A-Za-z0-9_]{36,}/g],
  ['GitHub PAT (classic)', /github_pat_[A-Za-z0-9_]{22,}/g],
  ['Slack token', /xox[baprs]-[A-Za-z0-9-]{10,}/g],
  ['Google API key', /AIza[0-9A-Za-z\-_]{35}/g],
  ['Stripe live key', /sk_live_[0-9A-Za-z]{16,}/g],
  ['Private key block', /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g],
  ['AWS secret (assign)', /aws_secret[^=:=]{0,20}[:=]\s*['"][A-Za-z0-9/+=]{20,}['"]/gi],
  ['Generic secret assign', /(api[_-]?key|secret|passwd|pwd|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-]{8,}['"]/gi],
];
router.post('/secretscan', async (req, res) => {
  let u;
  try { u = safeHttpUrl(String(req.body?.url || '').trim()); }
  catch (e) { return fail(res, 400, `Invalid URL: ${e.message}`); }
  try {
    const { data, cached } = await getOrSet(`secrets:${u.origin + u.pathname}`, 3600, async () => {
      const pages = [];
      const main = await http.get(u.toString(), { timeout: 12000, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0' } });
      const html = typeof main.data === 'string' ? main.data.slice(0, 800000) : '';
      pages.push({ file: u.pathname || '/', text: html });
      const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]).filter((s) => !s.startsWith('data:')).slice(0, 12);
      for (const src of scripts) {
        try {
          const abs = new URL(src, u.toString());
          if (abs.origin !== u.origin) continue; // same-origin only (no third-party liability)
          if (pages.length > 6) break;
          const r = await http.get(abs.toString(), { timeout: 10000 });
          if (typeof r.data === 'string') pages.push({ file: abs.pathname, text: r.data.slice(0, 500000) });
        } catch { /* skip failed scripts */ }
      }
      const findings = [];
      for (const page of pages) {
        for (const [label, re] of SECRET_PATTERNS) {
          const rx = new RegExp(re.source, re.flags);
          let m;
          while ((m = rx.exec(page.text)) && findings.length < 30) {
            const raw = m[0];
            const redacted = raw.length > 16 ? raw.slice(0, 8) + '***REDACTED***' + ` (${raw.length} chars)` : '***REDACTED***';
            findings.push({ type: label, file: page.file, match: redacted });
          }
        }
      }
      // Exposed VCS / env checks (status only, tiny bodies)
      const exposures = [];
      for (const [label, path, test] of [
        ['exposed .git', '/.git/HEAD', (t) => t.trim().startsWith('ref:')],
        ['exposed .env', '/.env', (t) => /^[A-Z_]+\s*=/m.test(t) && t.length < 20000 && !t.includes('<html')],
      ]) {
        try {
          const r = await http.get(u.origin + path, { timeout: 8000 });
          const t = typeof r.data === 'string' ? r.data : '';
          if (r.status === 200 && test(t)) exposures.push({ type: label, file: path, match: 'CONFIRMED (content withheld)' });
        } catch { /* not exposed */ }
      }
      return { url: u.toString(), files_scanned: pages.length, findings, exposures,
        verdict: findings.length || exposures.length ? 'secrets or exposures detected — verify manually, rotate affected keys' : 'no known secret patterns in scanned files' };
    });
    return ok(res, data, { cached, source: 'oathnet-secretscan' });
  } catch (e) { return fail(res, 502, e.message || 'Secret scan failed'); }
});

module.exports = router;
