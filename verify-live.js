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
  check('health 2.17.0', r.s === 200 && r.j && r.j.version === '2.17.0');
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
  r = await req('GET', '/api/recon/ghorg/github', null, H);
  check('GET /api/recon/ghorg', r.s === 200 && ((r.j || {}).data || {}).login === 'github');
  r = await req('GET', '/api/recon/pkg/npm/express', null, H);
  check('GET /api/recon/pkg/npm', r.s === 200 && ((r.j || {}).data || {}).name === 'express');
  r = await req('GET', '/api/threat/greynoise/8.8.8.8', null, H);
  check('GET /api/threat/greynoise', r.s === 200 && typeof ((((r.j || {}).data) || {}).observed) === 'boolean');
  // certs: crt.sh flakes — try a second narrow query before calling it broken
  r = await req('GET', '/api/recon/certs?q=signal', null, H);
  if (r.s !== 200) r = await req('GET', '/api/recon/certs?q=mozilla', null, H);
  check('GET /api/recon/certs', r.s === 200 && Array.isArray((r.j || {}).data));
  r = await req('GET', '/api/kitty/state', null, H);
  check('GET /api/kitty/state', r.s === 200 && ((r.j || {}).data || {}).per === 1000);
  r = await req('POST', '/api/kitty/click', { n: 7 }, H);
  check('POST /api/kitty/click', r.s === 200 && ((r.j || {}).data || {}).clicks === 7);
  r = await req('GET', '/api/world/geo?q=Berlin', null, H);
  check('GET /api/world/geo', r.s === 200 && (((r.j || {}).data || [])[0] || {}).name === 'Berlin');
  r = await req('GET', '/api/world/reverse?lat=52.52&lon=13.41', null, H);
  check('GET /api/world/reverse', r.s === 200 && ((r.j || {}).data || {}).name === 'Berlin');
  console.log(`\nLIVE ${pass}/${total}`);
  process.exit(pass === total ? 0 : 1);
})();
