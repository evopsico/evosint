const https = require('https');
const crypto = require('crypto');
const HOST = 'evosint.vercel.app';
function req(m, p, b, headers) {
  return new Promise((resolve) => {
    const pl = b ? JSON.stringify(b) : null;
    const r = https.request({ hostname: HOST, path: p, method: m, timeout: 60000,
      headers: { ...(pl ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(pl) } : {}), ...(headers || {}), 'User-Agent': 'Mozilla/5.0' } },
      (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch {} resolve({ s: res.statusCode, h: res.headers, j, raw: d.slice(0, 120) }); }); });
    r.on('timeout', () => resolve({ s: -1 }));
    r.on('error', (e) => resolve({ s: -1, b: e.message }));
    if (pl) r.write(pl);
    r.end();
  });
}
// independent TOTP (not the server's copy): RFC vectors already prove both correct
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
  check('health 2.12.0', r.s === 200 && r.j && r.j.version === '2.12.0', r.s + ' v' + (r.j && r.j.version));
  r = await req('GET', '/');
  const csp = r.h['content-security-policy'] || '';
  check('CSP allows turnstile frames', /frame-src[^;]*challenges\.cloudflare\.com/.test(csp));
  check('CSP scripts stay self-only', /script-src 'self'/.test(csp) && !/unsafe-inline/.test((csp.match(/script-src[^;]*/) || [''])[0]));
  r = await req('GET', '/sw.js');
  check('sw.js live', r.s === 200);
  r = await req('GET', '/manifest.webmanifest');
  check('manifest live', r.s === 200);
  r = await req('GET', '/api/auth/config');
  check('auth config (no keys -> null)', r.s === 200 && r.j.data.turnstileSiteKey === null);
  const un = 'live2fa' + Date.now().toString(36);
  r = await req('POST', '/api/auth/signup', { username: un, password: 'Live2fa12!', repeat: 'Live2fa12!', dob: '1990-05-05' });
  const tok0 = r.j && r.j.data && r.j.data.token;
  check('live signup (no captcha configured)', r.s === 200 && !!tok0, 'tier=' + (r.j.data || {}).tier);
  const H = { Authorization: 'Bearer ' + tok0 };
  r = await req('POST', '/api/auth/totp/setup', {}, H);
  const secret = r.j && r.j.data && r.j.data.secret;
  check('live totp setup', r.s === 200 && !!secret && (r.j.data.uri || '').startsWith('otpauth://'));
  r = await req('POST', '/api/auth/totp/enable', { code: code(secret) }, H);
  const codes = (r.j && r.j.data && r.j.data.backup_codes) || [];
  check('live totp enable + 8 codes', r.s === 200 && codes.length === 8);
  r = await req('POST', '/api/auth/login', { username: un, password: 'Live2fa12!' });
  const tmp = r.j && r.j.data && r.j.data.tmp;
  check('live login gated (tmp, no token)', r.s === 200 && r.j.data.totp_required === true && !!tmp && !r.j.data.token);
  r = await req('POST', '/api/auth/totp/verify', { tmp, code: code(secret) });
  check('live totp verify -> token', r.s === 200 && !!((r.j || {}).data || {}).token);
  r = await req('POST', '/api/auth/totp/verify', { tmp, backup_code: codes[0] });
  check('live backup code -> token', r.s === 200 && ((r.j || {}).data || {}).backup_remaining === 7);
  r = await req('GET', '/api/recon/ghorg/github', null, H);
  check('live ghorg', r.s === 200 && ((r.j || {}).data || {}).login === 'github');
  r = await req('GET', '/api/recon/pkg/npm/express', null, H);
  check('live npm pkg', r.s === 200 && ((r.j || {}).data || {}).name === 'express');
  r = await req('GET', '/api/recon/certs?q=github', null, H);
  check('live cert search', r.s === 200 && Array.isArray((r.j || {}).data));
  r = await req('GET', '/api/threat/greynoise/8.8.8.8', null, H);
  check('live greynoise', r.s === 200 && typeof (((r.j || {}).data || {}).observed) === 'boolean');
  console.log(`\nLIVE ${pass}/${total}`);
  process.exit(pass === total ? 0 : 1);
})();
