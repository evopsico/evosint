// Post-deploy live smoke: runs against production. Authed (guest quota is shared).
const https = require('https');
const crypto = require('crypto');
const HOST = 'evosint.vercel.app';
function req(m, p, b, headers) {
  return new Promise((resolve) => {
    const pl = b ? JSON.stringify(b) : null;
    const r = https.request({ hostname: HOST, path: p, method: m, timeout: 90000,
      headers: { ...(pl ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(pl) } : {}), ...(headers || {}), 'User-Agent': 'Mozilla/5.0' } },
      (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch {} resolve({ s: res.statusCode, h: res.headers, j }); }); });
    r.on('timeout', () => resolve({ s: -1 }));
    r.on('error', (e) => resolve({ s: -1, b: e.message }));
    if (pl) r.write(pl);
    r.end();
  });
}
function b32dec(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, val = 0; const out = [];
  for (const ch of String(s).toUpperCase().replace(/[^A-Z2-7]/g, '')) { val = (val << 5) | A.indexOf(ch); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function code(secret) {
  const t = Math.floor(Date.now() / 30000);
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(t));
  const h = crypto.createHmac('sha1', b32dec(secret)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000).padStart(6, '0');
}
let pass = 0, total = 0;
function check(n, c, x) { total++; if (c) pass++; console.log((c ? 'PASS' : 'FAIL') + ' live ' + n + (x ? ' | ' + x : '')); }
(async () => {
  let r = await req('GET', '/api/health');
  check('health 2.13.0', r.s === 200 && r.j && r.j.version === '2.13.0');
  const un = 'livefull' + Date.now().toString(36);
  r = await req('POST', '/api/auth/signup', { username: un, password: 'LiveFull12!', repeat: 'LiveFull12!', dob: '1990-06-06' });
  const tok0 = r.j && r.j.data && r.j.data.token;
  check('signup', r.s === 200 && !!tok0);
  const H = { Authorization: 'Bearer ' + tok0 };
  r = await req('POST', '/api/auth/totp/setup', {}, H);
  const secret = r.j && r.j.data && r.j.data.secret;
  check('totp setup', r.s === 200 && !!secret);
  r = await req('POST', '/api/auth/totp/enable', { code: code(secret) }, H);
  check('totp enable', r.s === 200 && ((r.j && r.j.data && r.j.data.backup_codes) || []).length === 8);
  r = await req('POST', '/api/auth/login', { username: un, password: 'LiveFull12!' });
  check('login gated', r.s === 200 && r.j.data.totp_required === true && !r.j.data.token);
  const tmp = r.j.data.tmp;
  r = await req('POST', '/api/auth/totp/verify', { tmp, code: code(secret) });
  check('totp verify', r.s === 200 && !!((r.j || {}).data || {}).token);
  for (const [p, want] of [['/api/recon/ghorg/github', 'github'], ['/api/recon/pkg/npm/express', 'express'], ['/api/recon/certs?q=signal', null], ['/api/threat/greynoise/8.8.8.8', null]]) {
    r = await req('GET', p, null, H);
    check('GET ' + p.split('?')[0], r.s === 200 && (want ? ((r.j || {}).data || {}).login === want || ((r.j || {}).data || {}).name === want : Array.isArray((r.j || {}).data) || typeof (((r.j || {}).data || {}).observed) === 'boolean'));
  }
  console.log(`\nLIVE ${pass}/${total}`);
  process.exit(pass === total ? 0 : 1);
})();
