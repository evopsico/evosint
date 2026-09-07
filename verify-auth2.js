const { spawn, execSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const PORT = 4780;
const { totpCode } = require('./backend/utils/crypto');
try { execSync(`powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort ${PORT} -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }"`, { timeout: 15000 }); } catch {}
function call(method, p, body, headers) {
  return new Promise((resolve) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request({ hostname: '127.0.0.1', port: PORT, path: p, method, timeout: 30000,
      headers: { ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}), ...(headers || {}) } }, (res) => {
      let d = ''; res.on('data', (c) => { d += c; });
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch {} resolve({ s: res.statusCode, j, raw: d.slice(0, 160) }); });
    }).on('timeout', () => resolve({ s: -1 })).on('error', (e) => resolve({ s: -1, b: e.message }));
    if (payload) req.write(payload);
    req.end();
  });
}
let pass = 0, total = 0;
function check(n, c, x) { total++; if (c) pass++; console.log((c ? 'PASS' : 'FAIL') + ' ' + n + (x ? ' | ' + x : '')); }
const U = 't2fa' + Date.now().toString(36);
(async () => {
  const srv = spawn('node', ['backend/server.js'], { cwd: process.cwd(), env: { ...process.env, PORT: String(PORT) } });
  await new Promise((r) => setTimeout(r, 6000));
  try {
    let r = await call('GET', '/api/auth/config');
    check('config (no keys -> null)', r.s === 200 && r.j && r.j.data && r.j.data.turnstileSiteKey === null, JSON.stringify((r.j || {}).data));
    r = await call('POST', '/api/auth/signup', { username: U, password: 'TotpTest1!', repeat: 'TotpTest1!', dob: '1992-02-02' });
    const tok0 = r.j && r.j.data && r.j.data.token;
    check('signup (no TOTP yet -> direct token)', r.s === 200 && !!tok0);
    const H = { Authorization: 'Bearer ' + tok0 };
    r = await call('POST', '/api/auth/totp/setup', {}, H);
    const secret = r.j && r.j.data && r.j.data.secret;
    check('totp setup returns secret+uri', r.s === 200 && !!secret && !!(r.j.data.uri || '').startsWith('otpauth://'), 'uri=' + ((r.j.data || {}).uri || '').slice(0, 40));
    r = await call('POST', '/api/auth/totp/enable', { code: '000000' }, H);
    check('enable rejects wrong code', r.s === 400);
    r = await call('POST', '/api/auth/totp/enable', { code: totpCode(secret, Date.now()) }, H);
    const codes = (r.j && r.j.data && r.j.data.backup_codes) || [];
    check('enable accepts live code + 8 backup codes', r.s === 200 && codes.length === 8, 'codes=' + codes.length);
    r = await call('GET', '/api/auth/me', null, H);
    check('me flags totp_enabled', r.s === 200 && r.j.data.totp_enabled === true);
    r = await call('POST', '/api/auth/login', { username: U, password: 'TotpTest1!' });
    const tmp = r.j && r.j.data && r.j.data.tmp;
    check('login with 2FA on -> totp_required + tmp (no token)', r.s === 200 && r.j.data.totp_required === true && !!tmp && !r.j.data.token);
    r = await call('POST', '/api/auth/totp/verify', { tmp, code: '000000' });
    check('verify rejects wrong code', r.s === 401);
    r = await call('POST', '/api/auth/totp/verify', { tmp, code: totpCode(secret, Date.now()) });
    const tok1 = r.j && r.j.data && r.j.data.token;
    check('verify live code -> full token', r.s === 200 && !!tok1);
    r = await call('POST', '/api/auth/totp/verify', { tmp: tmp.slice(0, -2) + 'xx', code: totpCode(secret, Date.now()) });
    check('mutated tmp rejected', r.s === 401);
    const H1 = { Authorization: 'Bearer ' + tok1 };
    const bc = codes[0];
    r = await call('POST', '/api/auth/totp/verify', { tmp, backup_code: bc });
    check('backup code works once', r.s === 200 && (r.j.data.backup_remaining === 7), 'remaining=' + ((r.j.data || {}).backup_remaining ?? '?'));
    r = await call('POST', '/api/auth/totp/verify', { tmp, backup_code: bc });
    check('backup code burned (reuse fails)', r.s === 401);
    r = await call('POST', '/api/auth/totp/disable', { password: 'TotpTest1!' }, H1);
    check('disable with password', r.s === 200);
    r = await call('POST', '/api/auth/login', { username: U, password: 'TotpTest1!' });
    check('login direct again after disable', r.s === 200 && !!((r.j || {}).data || {}).token);
    r = await call('GET', '/api/auth/backup', null, H1);
    check('backup is super-only (403 for user)', r.s === 403);
  } finally { srv.kill(); }
  console.log(`AUTH2 ${pass}/${total}`);
  process.exit(pass === total ? 0 : 1);
})();
