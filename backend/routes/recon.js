const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { http } = require('../utils/http');
const { getOrSet } = require('../utils/cache');
const { isValidDomain, normalizeDomain, isValidIP, isValidEmail, ok, fail } = require('../utils/validate');

// RECON — active web reconnaissance: crawler (Photon-style), DNS brute (subbrute-style),
// multi-source subdomains (Amass/Subfinder-style), WMN-700 sweep (Sherlock-style),
// email chase (h8mail-style), WP audit, takeover detect, goldmine, emailsec grade,
// typosquat, favicon hash, Tor check, PGP lookup, GitHub code (token).

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

function blockedHost(h) {
  h = String(h || '').toLowerCase();
  return !h || h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')
    || ['169.254.169.254', 'metadata.google.internal'].includes(h)
    || /^(127\.|10\.|0\.)/.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h)
    || /^169\.254\./.test(h) || h === '::1';
}
function safeUrl(input) {
  const u = new URL(String(input || ''));
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s)');
  if (blockedHost(u.hostname)) throw new Error('Private/internal targets blocked');
  if (u.username || u.password) throw new Error('Credentials in URL not allowed');
  return u;
}
async function pmap(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; try { out[k] = await fn(items[k], k); } catch (e) { out[k] = { _error: String(e.message).slice(0, 120) }; } }
  }));
  return out;
}
async function doh(name, type) {
  try {
    const r = await http.get(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, { timeout: 7000 });
    return (r.data?.Answer || []).map((a) => a.data);
  } catch { return []; }
}
// MurmurHash3 x86_32 (for Shodan-style favicon hash over base64 bytes)
function mmh3(key, seed) {
  seed = seed >>> 0 || 0;
  let h1 = seed, len = key.length, i = 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  while (len >= 4) {
    let k1 = (key.charCodeAt(i) & 255) | ((key.charCodeAt(i + 1) & 255) << 8) | ((key.charCodeAt(i + 2) & 255) << 16) | ((key.charCodeAt(i + 3) & 255) << 24);
    k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2);
    h1 ^= k1; h1 = (h1 << 13) | (h1 >>> 19); h1 = Math.imul(h1, 5) + 0xe6546b64;
    i += 4; len -= 4;
  }
  let k1 = 0;
  if (len === 3) k1 ^= (key.charCodeAt(i + 2) & 255) << 16;
  if (len >= 2) k1 ^= (key.charCodeAt(i + 1) & 255) << 8;
  if (len >= 1) { k1 ^= (key.charCodeAt(i) & 255); k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2); h1 ^= k1; }
  h1 ^= key.length;
  h1 ^= h1 >>> 16; h1 = Math.imul(h1, 0x85ebca6b); h1 ^= h1 >>> 13; h1 = Math.imul(h1, 0xc2b2ae35); h1 ^= h1 >>> 16;
  return h1 | 0;
}

// ---------- 1. Web crawler (Photon-style) ----------
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const PHONE_RE = /\+?\d[\d\s().-]{7,20}\d/g;
const SOCIAL_DOMAINS = ['github.com', 'twitter.com', 'x.com', 'instagram.com', 'facebook.com', 'linkedin.com', 'youtube.com', 'tiktok.com', 't.me', 'discord.gg', 'reddit.com', 'medium.com'];
router.post('/crawl', async (req, res) => {
  let start;
  try { start = safeUrl(req.body?.url || ''); } catch (e) { return fail(res, 400, `Invalid URL: ${e.message}`); }
  const depth = Math.min(Math.max(parseInt(req.body?.depth, 10) || 1, 0), 2);
  const max = Math.min(Math.max(parseInt(req.body?.max, 10) || 30, 1), 40);
  try {
    const origin = start.origin;
    const seen = new Set(), queue = [{ url: start.toString(), d: 0 }];
    const pages = [], emails = new Set(), phones = new Set(), socials = new Set(), docs = new Set(), forms = [];
    const comments = []; const interesting = new Set(); const jsFiles = new Set(); let skipped = 0;
    while (queue.length && pages.length < max) {
      const { url, d } = queue.shift();
      if (seen.has(url)) continue;
      seen.add(url);
      let html = '';
      try {
        const r = await http.get(url, { timeout: 10000, headers: { 'User-Agent': BROWSER_UA }, maxRedirects: 3 });
        if (typeof r.data !== 'string' || !String(r.headers?.['content-type'] || '').includes('html')) { skipped++; continue; }
        html = r.data.slice(0, 500000);
        pages.push({ url, status: r.status, size: html.length });
      } catch { skipped++; continue; }
      for (const m of html.matchAll(EMAIL_RE)) { const e = m[0].toLowerCase(); if (!e.endsWith('.png') && !e.endsWith('.jpg') && emails.size < 100) emails.add(e); }
      for (const m of html.matchAll(PHONE_RE)) { const p = m[0].replace(/[^\d+]/g, ''); if (p.replace(/\D/g, '').length >= 9 && p.replace(/\D/g, '').length <= 15 && phones.size < 100) phones.add(m[0].trim()); }
      for (const m of html.matchAll(/<a[^>]+href=["']([^"']+)["']/gi)) {
        try {
          const abs = new URL(m[1], url);
          if (SOCIAL_DOMAINS.some((s) => abs.hostname === s || abs.hostname.endsWith('.' + s))) { if (socials.size < 100) socials.add(abs.toString().slice(0, 200)); continue; }
          if (abs.origin === origin) {
            if (/\.(pdf|docx?|xlsx?|pptx?|csv|txt|zip|sql|bak|env|log|pem|key)$/i.test(abs.pathname)) { if (docs.size < 100) docs.add(abs.pathname); continue; }
            if (/(admin|login|wp-admin|wp-login|dashboard|phpmyadmin|\.git|\.env|server-status|actuator|console|jenkins|phpinfo)/i.test(abs.pathname)) interesting.add(abs.pathname.slice(0, 160));
            if (d < depth && !seen.has(abs.toString()) && queue.length < max * 2) queue.push({ url: abs.toString().split('#')[0], d: d + 1 });
          }
        } catch { /* bad href */ }
      }
      for (const m of html.matchAll(/<form[^>]*>/gi)) forms.push(m[0].slice(0, 200));
      for (const m of html.matchAll(/<!--([\s\S]{0,300}?)-->/g)) { const c = m[1].trim(); if (c && comments.length < 30) comments.push(c.slice(0, 200)); }
      for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) { try { const abs = new URL(m[1], url); if (abs.origin === origin && jsFiles.size < 50) jsFiles.add(abs.pathname); } catch {} }
    }
    return ok(res, {
      start: start.toString(), pages_crawled: pages.length, skipped,
      emails: [...emails].slice(0, 100), phones: [...phones].slice(0, 100),
      social_profiles: [...socials].slice(0, 100), documents: [...docs].slice(0, 100),
      interesting_paths: [...interesting].slice(0, 50), js_files: [...jsFiles].slice(0, 50),
      forms: forms.slice(0, 20), html_comments: comments.slice(0, 30), pages: pages.slice(0, 40),
    }, { source: 'evosint-crawler' });
  } catch (e) { return fail(res, 502, e.message || 'Crawl failed'); }
});

// ---------- 2. DNS brute force (subbrute-style, built-in wordlist) ----------
const BRUTE_WORDS = ('www mail ftp admin api dev test staging blog shop support portal app apps beta alpha demo mail2 mx smtp pop imap vpn remote secure login auth sso git svn jira confluence wiki docs help desk status cdn static assets img images video media cdn1 cdn2 ns1 ns2 dns srv db sql mysql backup bk ftp2 files share drive cloud storage s3 cdn-eu cdn-us edge origin lb proxy gw firewall ids ips noc ops mon monitor grafana kibana elk splunk zabbix nagios jenkins ci cd build deploy repo packages npm pypi docker k8s kube rancher consul vault etcd kafka rabbitmq redis mongo elastic search solr cms wordpress drupal joomla magento prestashop shopify store cart pay billing invoice crm erp hr itsm asset cmdb mdm sip voip pbx xmpp irc chat forum community news press events jobs career careers legal about contact us team staff people devops secops soc cert ir forensics lab research ai ml data analytics bi etl warehouse lake iot scadaics 5g lab qa uat pre prod production eu us asia web web1 web2 webmail exchange owa autodiscover lync teams sharepoint yammer ldap ad kerberos radius tacacs ntp syslog snmp printer scan fax iot camera cam cctv dvr nvr door badge hvac bms plc rtsp mqtt coap modbus bacnet dnp3 iec61850 opcua ethercat profinet can j1939 nmea ais adsb acars').split(' ');
router.post('/dns-brute', async (req, res) => {
  const raw = String(req.body?.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Body { domain } required');
  const domain = normalizeDomain(raw);
  const extra = Array.isArray(req.body?.extra) ? req.body.extra.map(String).filter((w) => /^[a-z0-9-]{1,40}$/i.test(w)).slice(0, 100) : [];
  const words = [...new Set([...BRUTE_WORDS, ...extra])];
  if (words.length > 400) return fail(res, 400, 'Max 400 labels per run');
  try {
    const { data, cached } = await getOrSet(`brute:${domain}:${words.length}`, 86400, async () => {
      const found = [];
      await pmap(words, 12, async (w) => {
        const fqdn = `${w}.${domain}`;
        const a = await doh(fqdn, 'A');
        if (a.length) found.push({ host: fqdn, records: a.slice(0, 8) });
      });
      return { domain, tried: words.length, found: found.sort((x, y) => x.host.localeCompare(y.host)) };
    });
    return ok(res, data, { cached, source: 'dns-brute' });
  } catch (e) { return fail(res, 502, e.message || 'Brute force failed'); }
});

// ---------- 3. Multi-source subdomains (Amass/Subfinder-style aggregator) ----------
router.post('/subdomains', async (req, res) => {
  const raw = String(req.body?.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Body { domain } required');
  const domain = normalizeDomain(raw);
  try {
    const { data, cached } = await getOrSet(`subagg:${domain}`, 86400, async () => {
      const per_source = {};
      const jobs = [
        (async () => {
          try {
            const r = await http.get(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeout: 25000 });
            const set = new Set();
            if (r.status === 200 && Array.isArray(r.data)) for (const row of r.data) String(row.name_value || '').split('\n').forEach((n) => { const v = n.trim().toLowerCase(); if (v && v.endsWith(domain) && !v.includes('*') && !v.includes('@') && !v.includes(' ')) set.add(v); });
            per_source.crtsh = [...set];
          } catch { per_source.crtsh = []; }
        })(),
        (async () => {
          try {
            const r = await http.get(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { timeout: 15000 });
            const set = new Set();
            if (r.status === 200 && typeof r.data === 'string' && !r.data.startsWith('error')) r.data.split('\n').forEach((l) => { const v = l.split(',')[0].trim().toLowerCase(); if (v && v.endsWith(domain) && !v.includes(' ') && !v.includes('@')) set.add(v); });
            per_source.hackertarget = [...set];
          } catch { per_source.hackertarget = []; }
        })(),
        (async () => {
          try {
            const r = await http.get(`https://api.subdomain.center/?domain=${encodeURIComponent(domain)}`, { timeout: 15000 });
            per_source.subcenter = Array.isArray(r.data) ? r.data.map(String).map((s) => s.toLowerCase()).filter((v) => v.endsWith(domain)).slice(0, 1000) : [];
          } catch { per_source.subcenter = []; }
        })(),
        (async () => {
          try {
            const r = await http.get(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent('domain:' + domain)}&size=100`, { timeout: 15000 });
            const set = new Set();
            (r.data?.results || []).forEach((x) => { const v = String(x.page?.domain || '').toLowerCase(); if (v && (v === domain || v.endsWith('.' + domain))) set.add(v); });
            per_source.urlscan = [...set];
          } catch { per_source.urlscan = []; }
        })(),
      ];
      if (process.env.OTX_API_KEY) jobs.push((async () => {
        try {
          const r = await http.get(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`, { headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY }, timeout: 15000 });
          const set = new Set();
          (r.data?.passive_dns || []).forEach((x) => { const v = String(x.hostname || '').toLowerCase(); if (v.endsWith(domain)) set.add(v); });
          per_source.otx = [...set];
        } catch { per_source.otx = []; }
      })());
      await Promise.all(jobs);
      const merged = new Map();
      for (const [src, list] of Object.entries(per_source)) for (const h of list) {
        if (!merged.has(h)) merged.set(h, { host: h, sources: [] });
        merged.get(h).sources.push(src);
      }
      return { domain, count: merged.size, per_source_count: Object.fromEntries(Object.entries(per_source).map(([k, v]) => [k, v.length])), subdomains: [...merged.values()].sort((a, b) => b.sources.length - a.sources.length || a.host.localeCompare(b.host)).slice(0, 1000) };
    });
    return ok(res, data, { cached, source: 'sub-aggregator' });
  } catch (e) { return fail(res, 502, e.message || 'Aggregation failed'); }
});

// ---------- 4. WhatsMyName 700+ sweep (Sherlock-style, live dataset) ----------
router.get('/wmn/:username', async (req, res) => {
  const u = String(req.params.username || '').trim();
  if (!/^[a-zA-Z0-9._-]{1,39}$/.test(u)) return fail(res, 400, 'Invalid username');
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 150, 10), 716);
  const cat = String(req.query.cat || '').toLowerCase();
  try {
    const ds = await getOrSet('wmn:dataset', 86400, async () => {
      const r = await http.get('https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json', { timeout: 25000 });
      if (!Array.isArray(r.data?.sites)) throw Object.assign(new Error('WMN dataset unreachable'), { status: 502 });
      return r.data.sites.filter((s) => s.uri_check && s.uri_check.includes('{account}'));
    });
    const sites = ds.data.filter((s) => !cat || String(s.cat || '').toLowerCase() === cat).slice(0, limit);
    const key = `wmn:${u.toLowerCase()}:${cat || 'all'}:${sites.length}`;
    const { data, cached } = await getOrSet(key, 86400, async () => {
      const results = await pmap(sites, 25, async (s) => {
        const url = s.uri_check.replace('{account}', encodeURIComponent(u));
        try {
          const r = await http.get(url, { timeout: 7000, headers: { 'User-Agent': BROWSER_UA, Accept: 'text/html,application/json,*/*' } });
          const body = (typeof r.data === 'string' ? r.data : JSON.stringify(r.data || '')).slice(0, 120000);
          if (s.m_code && r.status === s.m_code && s.m_string && body.includes(s.m_string)) return { name: s.name, cat: s.cat, found: false, url };
          if (s.e_code && r.status === s.e_code && (!s.e_string || body.includes(s.e_string))) return { name: s.name, cat: s.cat, found: true, url, method: s.e_string ? 'content' : 'status-only' };
          if (!s.e_string && !s.m_string && r.status === s.e_code) return { name: s.name, cat: s.cat, found: true, url, method: 'status-only' };
          return { name: s.name, cat: s.cat, found: false, url, note: 'inconclusive' };
        } catch (e) { return { name: s.name, cat: s.cat, found: false, url, error: String(e.message).slice(0, 100) }; }
      });
      const hits = results.filter((r) => r.found);
      return { results, summary: { checked: results.length, hits: hits.length } };
    });
    return ok(res, data.results, { summary: data.summary, cached, source: 'whatsmyname (CC BY-SA, Micah Hoffman)' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'WMN sweep failed'); }
});

// ---------- 5. Email chase (h8mail-style: patterns × MX + Gravatar) ----------
function emailPatterns(first, last, domain) {
  const f = first.toLowerCase(), l = last.toLowerCase(), fi = f[0], li = l[0];
  return [...new Set([`${f}`, `${l}`, `${f}${l}`, `${l}${f}`, `${f}.${l}`, `${l}.${f}`, `${f}_${l}`, `${f}-${l}`, `${fi}${l}`, `${li}${f}`, `${f}${li}`, `${l}${fi}`, `${fi}.${l}`, `${f}.${li}`, `${fi}${li}`, `${f}${l[0]}`, `${l}${f[0]}`])].map((p) => `${p}@${domain}`);
}
router.post('/chase', async (req, res) => {
  const first = String(req.body?.first || '').trim().toLowerCase(), last = String(req.body?.last || '').trim().toLowerCase();
  let domain = String(req.body?.domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!/^[a-z]{2,}$/.test(first) || !/^[a-z' -]{2,}$/.test(last) || !isValidDomain(domain)) return fail(res, 400, 'Body { first, last, domain } required');
  domain = normalizeDomain(domain);
  try {
    const { data, cached } = await getOrSet(`chase:${first}:${last}:${domain}`, 86400, async () => {
      const mx = await doh(domain, 'MX');
      if (!mx.length) return { domain, mx_found: false, candidates: [], note: 'Domain has no MX — chase unlikely' };
      const cands = emailPatterns(first.replace(/[^a-z]/g, ''), last.replace(/[^a-z]/g, ''), domain);
      const rows = await pmap(cands, 8, async (em) => {
        let gravatar = false;
        try {
          const h = crypto.createHash('md5').update(em).digest('hex');
          const g = await http.get(`https://en.gravatar.com/${h}.json`, { timeout: 8000 });
          gravatar = g.status === 200 && !!g.data?.entry;
        } catch { /* none */ }
        return { email: em, mx: true, gravatar, score: (gravatar ? 2 : 0) + 1 };
      });
      rows.sort((a, b) => b.score - a.score);
      return { domain, mx_found: true, mx: mx.slice(0, 5), candidates: rows };
    });
    return ok(res, data, { cached, source: 'chase' });
  } catch (e) { return fail(res, 502, e.message || 'Chase failed'); }
});

// ---------- 6. WordPress audit ----------
router.post('/wpcheck', async (req, res) => {
  let u;
  try { u = safeUrl(req.body?.url || ''); } catch (e) { return fail(res, 400, `Invalid URL: ${e.message}`); }
  const base = u.origin;
  const findings = [];
  const get = async (p, opts = {}) => {
    try {
      const r = await http.get(base + p, { timeout: 9000, headers: { 'User-Agent': BROWSER_UA }, validateStatus: () => true, ...(opts.raw ? { responseType: 'text' } : {}) });
      const body = typeof r.data === 'string' ? r.data : JSON.stringify(r.data || '');
      return { status: r.status, body: body.slice(0, 100000) };
    } catch (e) { return { status: null, error: e.message }; }
  };
  try {
    const home = await get('/');
    const isWP = /wp-content|wp-includes|wp-json|wordpress/i.test(home.body || '');
    findings.push({ check: 'WordPress detected', level: isWP ? 'info' : 'info', detail: isWP ? 'wp markers present' : 'no wp markers — remaining checks best-effort' });
    const readme = await get('/readme.html');
    const stable = /Stable tag:\s*([0-9.]+)/i.exec(readme.body || '');
    if (readme.status === 200 && stable) findings.push({ check: 'Version disclosure (readme.html)', level: 'warn', detail: `WordPress ${stable[1]} exposed — delete readme.html` });
    const users = await get('/wp-json/wp/v2/users');
    if (users.status === 200) {
      try {
        const arr = JSON.parse(users.body);
        if (Array.isArray(arr)) findings.push({ check: 'REST user enumeration', level: 'high', detail: `${arr.length} users exposed: ${arr.slice(0, 5).map((x) => x.slug).join(', ')} — restrict via authentication` });
      } catch { /* not json */ }
    }
    const rpc = await get('/xmlrpc.php');
    if (/XML-RPC server accepts POST requests only/i.test(rpc.body || '')) findings.push({ check: 'XML-RPC enabled', level: 'warn', detail: 'brute-force amplification vector — disable if unused' });
    const dbg = await get('/wp-content/debug.log');
    if (dbg.status === 200 && /PHP (Notice|Warning|Fatal|Stack trace)/i.test(dbg.body || '')) findings.push({ check: 'debug.log exposed', level: 'high', detail: 'path disclosure + internals — remove or deny' });
    const login = await get('/wp-login.php');
    if (login.status === 200) findings.push({ check: 'wp-login reachable', level: 'info', detail: 'harden with 2FA + rate limiting' });
    return ok(res, { url: base, wordpress: isWP, findings: findings.length ? findings : [{ check: 'scan', level: 'ok', detail: 'no issues spotted' }] }, { source: 'wpcheck' });
  } catch (e) { return fail(res, 502, e.message || 'WP check failed'); }
});

// ---------- 7. Subdomain takeover detector ----------
const TAKEOVER_FPS = [
  { svc: 'GitHub Pages', cname: 'github.io', markers: ["There isn't a GitHub Pages site here"] },
  { svc: 'Heroku', cname: 'herokuapp.com', markers: ['No such app'] },
  { svc: 'AWS S3', cname: 'amazonaws.com', markers: ['NoSuchBucket', 'The specified bucket does not exist'] },
  { svc: 'Shopify', cname: 'myshopify.com', markers: ['Sorry, this shop is currently unavailable'] },
  { svc: 'Bitbucket', cname: 'bitbucket.io', markers: ['Repository not found'] },
  { svc: 'Ghost', cname: 'ghost.io', markers: ['The thing you were looking for is no longer here'] },
  { svc: 'WordPress.com', cname: 'wordpress.com', markers: ['Do you want to register'] },
  { svc: 'Squarespace', cname: 'squarespace.com', markers: ['No Such Account'] },
  { svc: 'Fastly', cname: 'fastly.net', markers: ['Fastly error: unknown domain'] },
  { svc: 'Pantheon', cname: 'pantheonsite.io', markers: ['404 error unknown site'] },
  { svc: 'Zendesk', cname: 'zendesk.com', markers: ['Help Center Closed'] },
  { svc: 'Surge.sh', cname: 'surge.sh', markers: ['project not found'] },
  { svc: 'Cargo', cname: 'cargocollective.com', markers: ['404', 'If you are the owner'] },
  { svc: 'Readme.io', cname: 'readme.io', markers: ['Project doesnt exist'] },
  { svc: 'Azure', cname: 'azurewebsites.net', nxdomain: true, markers: [] },
  { svc: 'Azure TrafficManager', cname: 'trafficmanager.net', nxdomain: true, markers: [] },
  { svc: 'CloudFront', cname: 'cloudfront.net', markers: ['ERROR: The request could not be satisfied', 'Bad Request'] },
];
router.post('/takeover', async (req, res) => {
  const raw = String(req.body?.domain || '');
  const provided = Array.isArray(req.body?.subdomains) ? req.body.subdomains.map(String).slice(0, 200) : null;
  if (!isValidDomain(raw)) return fail(res, 400, 'Body { domain, subdomains? } required');
  const domain = normalizeDomain(raw);
  try {
    let subs = provided;
    if (!subs) {
      const r = await http.get(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { timeout: 15000 });
      subs = typeof r.data === 'string' ? [...new Set(r.data.split('\n').map((l) => l.split(',')[0].trim().toLowerCase()).filter((v) => v.endsWith(domain)))] : [];
      try {
        const c = await http.get(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeout: 20000 });
        if (Array.isArray(c.data)) for (const row of c.data) String(row.name_value || '').split('\n').forEach((n) => { const v = n.trim().toLowerCase(); if (v.endsWith(domain) && !v.includes('*') && !v.includes(' ')) subs.push(v); });
        subs = [...new Set(subs)];
      } catch { /* crt.sh optional */ }
    }
    subs = subs.filter((s) => s === domain || s.endsWith('.' + domain)).slice(0, 150);
    const results = await pmap(subs, 10, async (sub) => {
      const cnames = await doh(sub, 'CNAME');
      const target = (cnames[0] || '').replace(/\.$/, '').toLowerCase();
      if (!target) return { host: sub, cname: null, verdict: 'no-cname' };
      const fp = TAKEOVER_FPS.find((f) => target.includes(f.cname));
      if (!fp) return { host: sub, cname: target, verdict: 'no-fingerprint' };
      if (fp.nxdomain) {
        const a = await doh(sub, 'A');
        return a.length === 0
          ? { host: sub, cname: target, verdict: 'VULNERABLE', service: fp.svc, evidence: 'NXDOMAIN on claimed-service CNAME' }
          : { host: sub, cname: target, verdict: 'not-vulnerable', service: fp.svc };
      }
      try {
        const r = await http.get(`http://${sub}/`, { timeout: 8000, headers: { 'User-Agent': BROWSER_UA } });
        const body = (typeof r.data === 'string' ? r.data : '').slice(0, 60000);
        const hit = fp.markers.find((m) => body.includes(m));
        return hit
          ? { host: sub, cname: target, verdict: 'VULNERABLE', service: fp.svc, evidence: `marker: "${hit}"` }
          : { host: sub, cname: target, verdict: 'not-vulnerable', service: fp.svc };
      } catch (e) { return { host: sub, cname: target, verdict: 'inconclusive', service: fp.svc, error: String(e.message).slice(0, 100) }; }
    });
    const vuln = results.filter((r) => r.verdict === 'VULNERABLE');
    return ok(res, { domain, scanned: results.length, vulnerable: vuln.length, results }, { source: 'takeover' });
  } catch (e) { return fail(res, 502, e.message || 'Takeover scan failed'); }
});

// ---------- 8. Wayback goldmine (sensitive-file discovery) ----------
const GOLD_PATTERNS = [/\.env(\.|$)/i, /\.git\//i, /wp-config/i, /\.sql(\.|$)/i, /\.bak(\.|$)/i, /backup/i, /phpmyadmin/i, /admin/i, /server-status/i, /\.DS_Store/i, /id_rsa/i, /\.pem$/i, /\.log$/i, /debug/i, /composer\.json/i, /package\.json/i, /\.ya?ml$/i, /swagger/i, /api-docs/i, /actuator/i, /jenkins/i, /phpinfo/i, /\.old$/i, /\.zip$/i, /\.rar$/i];
router.post('/goldmine', async (req, res) => {
  const raw = String(req.body?.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Body { domain } required');
  const domain = normalizeDomain(raw);
  try {
    const { data, cached } = await getOrSet(`gold:${domain}`, 86400, async () => {
      const r = await http.get(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&limit=8000&collapse=urlkey&fl=timestamp,original,statuscode&matchType=domain`, { timeout: 40000 });
      if (!Array.isArray(r.data)) throw Object.assign(new Error('CDX unreachable'), { status: 502 });
      const [, ...rows] = r.data;
      const hits = [];
      for (const row of rows) {
        if (String(row[2]) !== '200') continue; // live snapshots only — cuts ancient junk URLs
        const url = row[1] || '';
        const pat = GOLD_PATTERNS.find((re) => re.test(url));
        if (pat && hits.length < 100) hits.push({ url: url.slice(0, 300), timestamp: row[0], status: row[2], pattern: String(pat), replay: `https://web.archive.org/web/${row[0]}id_/${url}` });
      }
      return { domain, scanned_urls: rows.length, hits };
    });
    return ok(res, data.hits, { cached, source: 'wayback-goldmine', domain: data.domain, scanned: data.scanned_urls, count: data.hits.length });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Goldmine failed'); }
});

// ---------- 9. Email security grader (SPF/DMARC/DKIM/MTA-STS) ----------
const DKIM_SELECTORS = ['google', 'k1', 'k2', 'everlytickey1', 'everlytickey2', 'mxvault', 'dkim', 'default', 'selector1', 'selector2', 's1', 's2', 'mail', 'email', 'key1', 'cm', 'sig1'];
router.get('/emailsec/:domain', async (req, res) => {
  const raw = String(req.params.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Invalid domain');
  const domain = normalizeDomain(raw);
  try {
    const { data, cached } = await getOrSet(`emailsec:${domain}`, 86400, async () => {
      const findings = [];
      let score = 100;
      const txt = await doh(domain, 'TXT');
      const spf = txt.map((t) => t.replace(/^"|"$/g, '')).find((t) => t.startsWith('v=spf1'));
      if (!spf) { score -= 30; findings.push({ check: 'SPF', level: 'fail', detail: 'no SPF record — anyone can spoof this domain' }); }
      else {
        const hard = /-all/.test(spf), soft = /~all/.test(spf);
        findings.push({ check: 'SPF', level: hard ? 'pass' : 'warn', detail: spf.slice(0, 200) + (hard ? '' : ' (not enforcing -all)') });
        if (!hard) score -= soft ? 8 : 15;
        const includes = (spf.match(/include:/g) || []).length;
        if (includes > 8) { score -= 5; findings.push({ check: 'SPF lookups', level: 'warn', detail: `${includes} includes — risks permerror over 10-lookup limit` }); }
      }
      const dmarcRaw = await doh(`_dmarc.${domain}`, 'TXT');
      const dmarc = dmarcRaw.map((t) => t.replace(/^"|"$/g, '').replace(/\\;/g, ';')).find((t) => t.startsWith('v=DMARC1'));
      if (!dmarc) { score -= 25; findings.push({ check: 'DMARC', level: 'fail', detail: 'no DMARC record' }); }
      else {
        const p = /p=(\w+)/i.exec(dmarc)?.[1] || '?';
        findings.push({ check: 'DMARC', level: p === 'reject' ? 'pass' : p === 'quarantine' ? 'warn' : 'fail', detail: dmarc.slice(0, 220) });
        if (p === 'none') score -= 10; else if (p === 'quarantine') score -= 4;
      }
      const dkimHits = [];
      await pmap(DKIM_SELECTORS, 8, async (sel) => {
        const recs = await doh(`${sel}._domainkey.${domain}`, 'TXT');
        if (recs.some((t) => t.includes('v=DKIM1') || t.includes('k=rsa'))) dkimHits.push(sel);
      });
      if (!dkimHits.length) { score -= 15; findings.push({ check: 'DKIM', level: 'warn', detail: 'no DKIM selector found among 17 common selectors' }); }
      else findings.push({ check: 'DKIM', level: 'pass', detail: `selectors live: ${dkimHits.join(', ')}` });
      const sts = await doh(`_mta-sts.${domain}`, 'TXT');
      if (!sts.some((t) => t.includes('v=STSv1'))) { score -= 5; findings.push({ check: 'MTA-STS', level: 'info', detail: 'no MTA-STS policy' }); }
      else findings.push({ check: 'MTA-STS', level: 'pass', detail: sts[0].slice(0, 160) });
      score = Math.max(0, score);
      return { domain, score, grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F', spf: spf || null, dmarc: dmarc || null, dkim_selectors: dkimHits, findings };
    });
    return ok(res, data, { cached, source: 'emailsec' });
  } catch (e) { return fail(res, 502, e.message || 'Emailsec failed'); }
});

// ---------- 10. Typosquat generator + DNS check ----------
const TLD_SWAP = ['com', 'net', 'org', 'io', 'co', 'dev', 'app', 'info', 'biz', 'xyz', 'top', 'site', 'online', 'us'];
router.post('/typosquat', async (req, res) => {
  const raw = String(req.body?.domain || '');
  if (!isValidDomain(raw)) return fail(res, 400, 'Body { domain } required');
  const domain = normalizeDomain(raw);
  const parts = domain.split('.');
  if (parts.length < 2) return fail(res, 400, 'Need a registrable domain');
  const tld = parts.pop(), name = parts.join('.');
  const cands = new Set();
  const addName = (n) => { if (/^[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?$/.test(n) && n !== name) cands.add(n + '.' + tld); };
  const alpha = 'abcdefghijklmnopqrstuvwxyz';
  for (let i = 0; i < name.length; i++) {
    addName(name.slice(0, i) + name.slice(i + 1)); // omission
    addName(name.slice(0, i) + name[i] + name[i] + name.slice(i)); // duplication
    if (i < name.length - 1) addName(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2)); // transpose
    for (const c of alpha) addName(name.slice(0, i) + c + name.slice(i + 1)); // substitution
    addName(name.slice(0, i) + '-' + name.slice(i)); // hyphenate
  }
  addName(name + '-'); addName('-' + name);
  for (const t of TLD_SWAP) if (t !== tld) cands.add(name + '.' + t);
  const list = [...cands].filter((c) => c !== domain).slice(0, 220);
  try {
    const rows = await pmap(list, 15, async (cand) => {
      const a = await doh(cand, 'A');
      return { domain: cand, registered_dns: a.length > 0, records: a.slice(0, 3) };
    });
    const live = rows.filter((r) => r.registered_dns);
    return ok(res, { domain, generated: list.length, live_count: live.length, live, sample_dead: rows.filter((r) => !r.registered_dns).slice(0, 10).map((r) => r.domain) }, { source: 'typosquat' });
  } catch (e) { return fail(res, 502, e.message || 'Typosquat failed'); }
});

// ---------- 11. Favicon hash (Shodan pivot) ----------
router.get('/favicon-hash', async (req, res) => {
  let u;
  try { u = safeUrl(req.query.url || ''); } catch (e) { return fail(res, 400, `Query ?url= required: ${e.message}`); }
  try {
    const { data, cached } = await getOrSet(`fav:${u.origin}`, 86400 * 7, async () => {
      let iconUrl = u.origin + '/favicon.ico';
      try {
        const home = await http.get(u.origin + '/', { timeout: 10000, headers: { 'User-Agent': BROWSER_UA } });
        const m = typeof home.data === 'string' && home.data.match(/<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']/i);
        if (m) iconUrl = new URL(m[1], u.origin).toString();
      } catch { /* default */ }
      const r = await http.get(iconUrl, { timeout: 10000, responseType: 'arraybuffer' });
      const buf = Buffer.from(r.data);
      if (!buf.length || buf.length > 500000) throw Object.assign(new Error('Favicon fetch failed'), { status: 502 });
      const hash = mmh3(buf.toString('base64'), 0);
      return { url: u.origin, icon: iconUrl, mmh3: hash, shodan: `https://www.shodan.io/search?query=http.favicon.hash:${hash}`, bytes: buf.length };
    });
    return ok(res, data, { cached, source: 'favicon-mmh3' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Favicon hash failed'); }
});

// ---------- 12. Tor relay/exit check (onionoo) ----------
router.get('/tor/:ip', async (req, res) => {
  const ip = String(req.params.ip || '').trim();
  if (!isValidIP(ip)) return fail(res, 400, 'IP required');
  try {
    const { data, cached } = await getOrSet(`tor:${ip}`, 86400, async () => {
      const r = await http.get(`https://onionoo.torproject.org/details?search=${encodeURIComponent(ip)}`, { timeout: 15000 });
      const relays = (r.data?.relays || []).filter((x) => (x.or_addresses || []).some((a) => a.split(':')[0] === ip));
      return { ip, is_tor: relays.length > 0, relays: relays.slice(0, 5).map((x) => ({ nickname: x.nickname, flags: x.flags || [], running: !!x.running, consensus_weight: x.consensus_weight ?? null })) };
    });
    return ok(res, data, { cached, source: 'onionoo' });
  } catch (e) { return fail(res, 502, 'Tor check failed'); }
});

// ---------- 13. PGP key lookup (openpgp.org + Ubuntu keyserver) ----------
router.get('/pgp/:email', async (req, res) => {
  const email = String(req.params.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return fail(res, 400, 'Invalid email');
  try {
    const { data, cached } = await getOrSet(`pgp:${email}`, 86400 * 7, async () => {
      const out = { email, keys: [] };
      try {
        const r = await http.get(`https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(email)}`, { timeout: 12000 });
        if (r.status === 200 && r.data) out.keys.push({ server: 'keys.openpgp.org', found: true, bytes: String(r.data).length });
      } catch { /* none */ }
      try {
        const r = await http.get(`https://keyserver.ubuntu.com/pks/lookup?search=${encodeURIComponent(email)}&op=index&options=mr`, { timeout: 12000 });
        if (r.status === 200 && typeof r.data === 'string') {
          const lines = r.data.split('\n');
          let cur = null;
          for (const ln of lines) {
            if (ln.startsWith('pub:')) { const p = ln.split(':'); cur = { server: 'keyserver.ubuntu.com', found: true, keyid: (p[1] || '').slice(-16), bits: p[3], created: p[4] ? new Date(Number(p[4]) * 1000).toISOString().slice(0, 10) : null, uids: [] }; out.keys.push(cur); }
            else if (ln.startsWith('uid:') && cur) { const m = /<([^>]+)>/.exec(decodeURIComponent(ln)); if (m) cur.uids.push(m[1]); }
          }
        }
      } catch { /* none */ }
      out.found = out.keys.length > 0;
      return out;
    });
    return ok(res, data, { cached, source: 'pgp-keyservers' });
  } catch (e) { return fail(res, 502, 'PGP lookup failed'); }
});

// ---------- 14. GitHub code search (token-gated) ----------
router.get('/github-code', async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (!q || q.length > 200) return fail(res, 400, 'Query ?q= required');
  if (!process.env.GITHUB_TOKEN) return fail(res, 428, 'GitHub code search needs a token — set GITHUB_TOKEN server-side (free PAT, no scopes needed)');
  try {
    const { data, cached } = await getOrSet(`ghcode:${q.toLowerCase()}`, 3600, async () => {
      const r = await http.get(`https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=20`, {
        headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}`, Accept: 'application/vnd.github+json' }, timeout: 15000,
      });
      if (r.status !== 200) throw Object.assign(new Error('GitHub code search failed'), { status: 502 });
      return { total: r.data?.total_count ?? 0, items: (r.data?.items || []).map((i) => ({ repo: i.repository?.full_name, path: i.path, url: i.html_url })) };
    });
    return ok(res, data, { cached, source: 'github-code' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Code search failed'); }
});

// GET /api/recon/ghorg/:org — public org profile + top repos + public members
router.get('/ghorg/:org', async (req, res) => {
  const org = String(req.params.org || '').trim();
  if (!/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(org)) return fail(res, 400, 'Invalid org name');
  try {
    const { data, cached } = await getOrSet(`ghorg:${org.toLowerCase()}`, 3600, async () => {
      const H = process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {};
      const [o, repos, members] = await Promise.all([
        http.get(`https://api.github.com/orgs/${encodeURIComponent(org)}`, { headers: H, timeout: 12000 }),
        http.get(`https://api.github.com/orgs/${encodeURIComponent(org)}/repos?per_page=10&sort=updated`, { headers: H, timeout: 12000 }),
        http.get(`https://api.github.com/orgs/${encodeURIComponent(org)}/public_members?per_page=30`, { headers: H, timeout: 12000 }),
      ]);
      if (o.status === 404) { const e = new Error('Org not found'); e.status = 404; throw e; }
      if (o.status !== 200) { const e = new Error('GitHub error'); e.status = 502; throw e; }
      const d = o.data || {};
      return {
        login: d.login, name: d.name || null, description: (d.description || '').slice(0, 300),
        blog: d.blog || null, email: d.email || null, location: d.location || null,
        public_repos: d.public_repos ?? null, followers: d.followers ?? null,
        created: (d.created_at || '').slice(0, 10),
        top_repos: (Array.isArray(repos.data) ? repos.data : []).map((r) => ({ name: r.name, stars: r.stargazers_count, language: r.language, url: r.html_url })),
        public_members: (Array.isArray(members.data) ? members.data : []).map((m) => ({ login: m.login, url: m.html_url })),
      };
    });
    return ok(res, data, { cached, source: 'github' });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Org lookup failed'); }
});

// GET /api/recon/pkg/:registry/:name — npm / PyPI / crates.io metadata (all keyless)
const PKG = {
  npm: async (name) => {
    const r = await http.get(`https://registry.npmjs.org/${encodeURIComponent(name)}`, { timeout: 12000 });
    if (r.status === 404) return null;
    if (r.status !== 200) throw new Error('npm error');
    const d = r.data || {};
    const latest = d['dist-tags'] && d['dist-tags'].latest;
    const lv = (latest && d.versions && d.versions[latest]) || null;
    return { registry: 'npm', name: d.name, description: (d.description || '').slice(0, 300), latest: latest || null,
      versions: Object.keys(d.versions || {}).length,
      maintainers: (d.maintainers || []).map((m) => m.name).slice(0, 10),
      license: (lv && lv.license) || null,
      homepage: (lv && (lv.homepage || (lv.repository && lv.repository.url))) || null,
      deps: lv && lv.dependencies ? Object.keys(lv.dependencies).slice(0, 20) : [],
      published: latest && d.time ? d.time[latest] : null };
  },
  pypi: async (name) => {
    const r = await http.get(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { timeout: 12000 });
    if (r.status === 404) return null;
    if (r.status !== 200) throw new Error('PyPI error');
    const i = (r.data && r.data.info) || {};
    return { registry: 'pypi', name: i.name, description: (i.summary || '').slice(0, 300), latest: i.version || null,
      license: i.license || null, homepage: i.home_page || null, author: i.author || null,
      author_email: i.author_email || null, requires_python: i.requires_python || null, yanked: !!i.yanked };
  },
  crates: async (name) => {
    const r = await http.get(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, { headers: { 'User-Agent': 'Evosint/2.12 (pkg-recon)' }, timeout: 12000 });
    if (r.status === 404) return null;
    if (r.status !== 200) throw new Error('crates.io error');
    const c = (r.data && r.data.crate) || {};
    const v = (r.data && r.data.versions && r.data.versions[0]) || {};
    return { registry: 'crates', name: c.name || c.id, description: (c.description || '').slice(0, 300),
      latest: v.num || c.max_version || null, downloads: c.downloads ?? null,
      documentation: c.documentation || null, homepage: c.homepage || null,
      repository: c.repository || null, license: v.license || null };
  },
};
router.get('/pkg/:registry/:name', async (req, res) => {
  const reg = String(req.params.registry || '').toLowerCase();
  const name = String(req.params.name || '').trim();
  if (!PKG[reg]) return fail(res, 400, 'Registry must be npm, pypi or crates');
  if (!/^[@a-zA-Z0-9][a-zA-Z0-9._/-]{0,99}$/.test(name)) return fail(res, 400, 'Invalid package name');
  try {
    const { data, cached } = await getOrSet(`pkg:${reg}:${name.toLowerCase()}`, 3600, async () => {
      const out = await PKG[reg](name);
      if (!out) { const e = new Error('Package not found'); e.status = 404; throw e; }
      return out;
    });
    return ok(res, data, { cached, source: reg });
  } catch (e) { return fail(res, e.status || 502, e.message || 'Package lookup failed'); }
});

// GET /api/recon/certs?q= — certificate identity search via crt.sh (orgs, names)
// Broad terms match tens of thousands of certs, so expired certs are excluded
// server-side and short/empty queries are rejected up front.
router.get('/certs', async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (!q || q.length < 3 || q.length > 120 || /[<>"']/.test(q)) return fail(res, 400, 'Query ?q= needs 3–120 chars (org or name — narrower is faster)');
  try {
    const { data, cached } = await getOrSet(`crtid:${q.toLowerCase()}`, 86400, async () => {
      const r = await http.get(`https://crt.sh/?q=${encodeURIComponent(q)}&output=json&exclude=expired`, { timeout: 25000 });
      if (r.status !== 200 || !Array.isArray(r.data)) { const e = new Error('crt.sh unreachable'); e.status = 502; throw e; }
      const seen = new Map();
      for (const row of r.data.slice(0, 500)) {
        const cn = String(row.common_name || '');
        if (!cn || seen.has(cn)) continue;
        seen.set(cn, { common_name: cn,
          issuer: String(row.issuer_name || '').split(',').slice(0, 2).join(',').slice(0, 120),
          not_before: row.not_before || null, not_after: row.not_after || null });
        if (seen.size >= 30) break;
      }
      return [...seen.values()];
    });
    return ok(res, data, { cached, source: 'crt.sh', count: data.length });
  } catch (e) {
    if (e.code === 'ECONNABORTED' || /timeout/i.test(e.message || '')) return fail(res, 504, 'crt.sh timed out — try a narrower, more specific query');
    return fail(res, e.status || 502, e.message || 'Certificate search failed');
  }
});

module.exports = router;
