const express = require('express');
const net = require('net');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidDomain, normalizeDomain, isValidIP, ok, fail } = require('../utils/validate');

// SSRF guard: block cloud metadata + private ranges for server-fetched URLs.
function isBlockedTarget(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (['169.254.169.254', 'metadata.google.internal', 'metadata.google'].includes(h)) return true;
  if (isValidIP(h)) {
    const p = h.split('.').map(Number);
    if (p.length === 4) {
      if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
      if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
      if (p[0] === 192 && p[1] === 168) return true;
      if (p[0] === 169 && p[1] === 254) return true;
    }
    if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  }
  return false;
}

function safeUrl(input) {
  const u = new URL(String(input));
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s) URLs allowed');
  if (isBlockedTarget(u.hostname)) throw new Error('Target is blocked (private/internal address)');
  if (u.username || u.password) throw new Error('Credentials in URL are not allowed');
  return u;
}

/** GET /api/network/subdomains/:domain — crt.sh certificate transparency (free, no key). */
router.get('/subdomains/:domain', async (req, res) => {
  const raw = String(req.params.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Invalid domain');
  const domain = normalizeDomain(raw);
  try {
    const { data, cached } = await getOrSet(`sub:${domain}`, 86400, async () => {
      // 1) crt.sh certificate transparency (big, sometimes slow)
      try {
        const r = await http.get(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeout: 25000 });
        if (r.status === 200 && Array.isArray(r.data)) {
          const set = new Set();
          for (const row of r.data) {
            String(row.name_value || '').split('\n').forEach((n) => {
              const v = n.trim().toLowerCase();
              if (v && v.endsWith(domain) && !v.includes('*') && !v.includes('@') && !v.includes(' ')) set.add(v);
            });
          }
          if (set.size) return { domain, count: set.size, subdomains: [...set].sort().slice(0, 500), source: 'crt.sh' };
        }
      } catch { /* fall through to HackerTarget */ }
      // 2) HackerTarget hostsearch fallback (fast, free tier)
      const r = await http.get(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { timeout: 15000 });
      if (r.status === 200 && typeof r.data === 'string' && !r.data.startsWith('error')) {
        const set = new Set();
        r.data.split('\n').forEach((line) => {
          const v = line.split(',')[0].trim().toLowerCase();
          if (v && v.endsWith(domain) && !v.includes(' ') && !v.includes('@')) set.add(v);
        });
        return { domain, count: set.size, subdomains: [...set].sort().slice(0, 500), source: 'hackertarget (fallback)' };
      }
      throw Object.assign(new Error('Subdomain lookup failed on all providers (crt.sh timed out, HackerTarget refused)'), { status: 502 });
    });
    return ok(res, data, { cached });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Subdomain enumeration failed'); }
});

/** POST /api/network/headers { url } — security-header audit with SSRF guard. */
router.post('/headers', async (req, res) => {
  let u;
  try { u = safeUrl(req.body?.url || ''); } catch (e) { return fail(res, 400, e.message); }
  try {
    const r = await http.get(u.toString(), { timeout: 12000, maxRedirects: 3 });
    const h = {};
    for (const [k, v] of Object.entries(r.headers || {})) h[k.toLowerCase()] = v;
    const checks = [
      { header: 'strict-transport-security', label: 'HSTS', ok: !!h['strict-transport-security'], fix: 'add Strict-Transport-Security: max-age=31536000; includeSubDomains' },
      { header: 'content-security-policy', label: 'CSP', ok: !!h['content-security-policy'], fix: 'add a Content-Security-Policy' },
      { header: 'x-frame-options', label: 'Clickjacking protection', ok: !!(h['x-frame-options'] || h['content-security-policy']?.includes('frame-ancestors')), fix: 'add X-Frame-Options: SAMEORIGIN' },
      { header: 'x-content-type-options', label: 'MIME sniffing protection', ok: h['x-content-type-options'] === 'nosniff', fix: 'add X-Content-Type-Options: nosniff' },
      { header: 'referrer-policy', label: 'Referrer policy', ok: !!h['referrer-policy'], fix: 'add Referrer-Policy: strict-origin-when-cross-origin' },
      { header: 'permissions-policy', label: 'Permissions policy', ok: !!(h['permissions-policy'] || h['feature-policy']), fix: 'add Permissions-Policy' },
    ];
    const score = Math.round((checks.filter((c) => c.ok).length / checks.length) * 100);
    const leaks = ['server', 'x-powered-by', 'x-aspnet-version'].filter((k) => h[k]).map((k) => `${k}: ${h[k]}`);
    return ok(res, {
      url: u.toString(), final_url: r.request?.res?.responseUrl || u.toString(), status: r.status,
      score, checks, server_leaks: leaks,
      cookies: (r.headers?.['set-cookie'] || []).map((c) => ({
        raw: String(c).slice(0, 200), secure: /;\s*secure/i.test(c), http_only: /;\s*httponly/i.test(c), samesite: /samesite=(lax|strict|none)/i.test(c),
      })),
    });
  } catch (e) { return fail(res, 502, `Header fetch failed: ${e.message}`); }
});

/** POST /api/network/tech { url } — lightweight stack fingerprinting (headers + HTML signals). */
router.post('/tech', async (req, res) => {
  let u;
  try { u = safeUrl(req.body?.url || ''); } catch (e) { return fail(res, 400, e.message); }
  try {
    const r = await http.get(u.toString(), { timeout: 12000, maxRedirects: 3 });
    const headers = r.headers || {};
    const html = typeof r.data === 'string' ? r.data.slice(0, 200000).toLowerCase() : '';
    const found = [];
    const sig = (name, confidence, evidence) => found.push({ name, confidence, evidence });
    const H = (k) => String(headers[k.toLowerCase()] || headers[k] || '');
    if (/next\.js|__next/i.test(html) || H('x-powered-by').includes('Next.js')) sig('Next.js', 'high', 'markers in HTML/headers');
    if (/wp-content|wp-includes|wordpress/i.test(html)) sig('WordPress', 'high', 'wp- paths');
    if (/drupal/i.test(html) || H('x-drupal-cache')) sig('Drupal', 'medium', 'drupal markers');
    if (/shopify/i.test(html)) sig('Shopify', 'high', 'shopify markers');
    if (/cloudflare/i.test(H('server')) || headers['cf-ray']) sig('Cloudflare', 'high', 'cf-ray/server header');
    if (/nginx/i.test(H('server'))) sig('Nginx', 'high', 'server header');
    if (/apache/i.test(H('server'))) sig('Apache', 'high', 'server header');
    if (/react/i.test(html)) sig('React', 'medium', 'react markers');
    if (/vue/i.test(html)) sig('Vue.js', 'medium', 'vue markers');
    if (/tailwind/i.test(html)) sig('Tailwind CSS', 'medium', 'tailwind markers');
    if (/bootstrap/i.test(html)) sig('Bootstrap', 'medium', 'bootstrap markers');
    if (/google-analytics|gtag\.js|googletagmanager/i.test(html)) sig('Google Analytics/Tag Manager', 'high', 'ga/gtm scripts');
    if (/hubspot/i.test(html)) sig('HubSpot', 'medium', 'hubspot scripts');
    if (/stripe/i.test(html)) sig('Stripe', 'medium', 'stripe.js');
    return ok(res, { url: u.toString(), status: r.status, server: H('server') || null, powered_by: H('x-powered-by') || null, technologies: found });
  } catch (e) { return fail(res, 502, `Tech detection failed: ${e.message}`); }
});

/** POST /api/network/expand { url } — follow redirects to unwrap short links. */
router.post('/expand', async (req, res) => {
  let u;
  try { u = safeUrl(req.body?.url || ''); } catch (e) { return fail(res, 400, e.message); }
  try {
    const chain = [u.toString()];
    let current = u.toString();
    for (let i = 0; i < 10; i++) {
      const r = await http.get(current, { timeout: 10000, maxRedirects: 0 });
      if ([301, 302, 303, 307, 308].includes(r.status) && r.headers.location) {
        current = new URL(r.headers.location, current).toString();
        if (isBlockedTarget(new URL(current).hostname)) return fail(res, 400, 'Redirect chain leads to blocked internal address');
        chain.push(current);
      } else {
        return ok(res, { original: chain[0], final: current, hops: chain.length - 1, chain, status: r.status });
      }
    }
    return ok(res, { original: chain[0], final: current, hops: chain.length - 1, chain, warning: 'max hops reached — possible redirect loop' });
  } catch (e) { return fail(res, 502, `Expand failed: ${e.message}`); }
});

/** GET /api/network/blacklist/:ip — DNSBL reputation via dns.google (Spamhaus ZEN + SpamCop). */
router.get('/blacklist/:ip', async (req, res) => {
  const ip = String(req.params.ip || '').trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || ip.split('.').some((o) => Number(o) > 255)) return fail(res, 400, 'IPv4 address required');
  try {
    const rev = ip.split('.').reverse().join('.');
    const zones = ['zen.spamhaus.org', 'bl.spamcop.net'];
    const results = await Promise.all(zones.map(async (zone) => {
      try {
        const r = await http.get(`https://dns.google/resolve?name=${rev}.${zone}&type=A`, { timeout: 7000 });
        const listed = (r.data?.Answer || []).length > 0;
        return { zone, listed, records: (r.data?.Answer || []).map((a) => a.data) };
      } catch { return { zone, listed: null, error: 'query failed' }; }
    }));
    const listedCount = results.filter((x) => x.listed).length;
    return ok(res, {
      ip, listed_count: listedCount, clean: listedCount === 0,
      results, note: 'Spamhaus ZEN covers SBL/XBL/PBL. For production use a registered data-feed.',
    });
  } catch (e) { return fail(res, 502, e.message || 'Blacklist check failed'); }
});

/** POST /api/network/portscan { host, ports? } — tightly-capped TCP connect scan. */
const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443];
function tcpProbe(host, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let done = false;
    const finish = (state) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve({ port, state, latency_ms: Date.now() - start }); } };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => finish('open'));
    sock.on('timeout', () => finish('filtered'));
    sock.on('error', (e) => finish(e.code === 'ECONNREFUSED' ? 'closed' : 'filtered'));
    try { sock.connect(port, host); } catch { finish('filtered'); }
  });
}
router.post('/portscan', async (req, res) => {
  const host = String(req.body?.host || '').trim();
  if (!host) return fail(res, 400, 'Body { host, ports? } required');
  let hostname = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  if (isBlockedTarget(hostname)) return fail(res, 400, 'Scanning private/internal hosts is blocked');
  let ports = req.body?.ports;
  if (ports === undefined) ports = COMMON_PORTS;
  if (!Array.isArray(ports) || ports.length === 0 || ports.length > 20) return fail(res, 400, 'ports must be an array of ≤20 ports');
  ports = [...new Set(ports.map(Number))].filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535);
  if (!ports.length) return fail(res, 400, 'No valid ports supplied');
  // Only allow common ports unless explicitly a public IP/domain the user owns — capped allowlist keeps abuse down
  const outside = ports.filter((p) => !COMMON_PORTS.includes(p));
  if (outside.length > 5) return fail(res, 400, 'Max 5 non-standard ports per scan');
  try {
    const results = await Promise.all(ports.map((p) => tcpProbe(hostname, p)));
    return ok(res, { host: hostname, scanned: ports.length, open: results.filter((r) => r.state === 'open').map((r) => r.port), results, authorized_use_only: true });
  } catch (e) { return fail(res, 500, e.message || 'Port scan failed'); }
});

module.exports = router;
